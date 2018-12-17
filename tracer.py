import lief
from triton import *
from pwn import *
from collections import deque, Counter, OrderedDict
import pdb
import json
from termcolor import colored
from multiprocessing import get_logger, current_process
import logging


LOGGER = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(process)s - %(filename)s -  %(lineno)s - %(levelname)s]  %(message)s"))
LOGGER.addHandler(console_handler)
LOGGER.setLevel(logging.INFO)

# memory mapping
BASE_PLT = 0X10000000
BASE_ARGV = 0X20000000
BASE_ALLOC = 0X30000000
BASE_FAIL = 0X40000000
BASE_STACK = 0X9FFFFFFF


class Tracer(object):
    """
    Tracer Object, Emulate the program
    """
    def __init__(self, program_name, symbolized_input):
        """
        :param program_name (str): The program name
        :param default_input (str): Default function inputs value (i.e, stdin for scanf)
        :param call_tracking (dict): Stored the number of time a function is called in a lap (<lap>:Counter({0x401337:1,0x401348:2})}
        :param taken_branch (set): Stored taken branches address (set(0x401337,0x401348))
        :param untaken_branch (set): Stored untaken branches address (set(0x401337, 0x401348))
        :param lap (int): The number of lap
        :param symbolized_input (boolean): Select if the function inputs/output need to be symbolized
        :param malloc_current_allocation (int): The pointer address return by malloc
        :param malloc_max_allocation (int): The max limit
        :param malloc_base (int): The malloc base address
        :param malloc_chunk_size (int): The malloc chunk size
        :param custom_relocation (dict): Contains function relocation {<relocation address in triton memory>:[<function to relocate>, <function to call instead>]}
        """
        self.program_name = program_name
        self.default_input = '99'
        self.call_tracking = dict()
        self.untaken_branch = set()
        self.taken_branch = set()
        self.lap = 0
        self.symbolized_input = symbolized_input

        # Allocation information used by malloc()
        self.malloc_current_allocation = 0
        self.malloc_max_allocation = 2048
        self.malloc_base = BASE_ALLOC
        self.malloc_chunk_size = 0x00010000

        # implemented handler
        self.custom_relocation = {
                BASE_FAIL: ('honey_pot',          self._honey_pot),
                BASE_PLT + 0: ('__libc_start_main',  self._libc_main_handler),
                BASE_PLT + 1: ('printf',             self._printf_handler),
                BASE_PLT + 2: ('puts',               self._puts_handler),
                BASE_PLT + 3: ('malloc',             self._malloc_handler),
                BASE_PLT + 4: ('scanf',              self._scanf_handler),
                BASE_PLT + 5: ('atoi',               self._atoi_handler),
                BASE_PLT + 6: ('fgetc',              self._fgetc_handler),
                BASE_PLT + 7: ('strlen',             self._strlen_handler),
        }

    # Callbacklist
    def add_start_callback(self, start_func):
        """ Add a callback at the program start """
        self._start_callback = start_func

    def add_end_callback(self, end_func):
        """ Add a callback at the program end """
        self._end_callback = end_func

    def add_memory_callback(self, memory_func):
        """ Add a callback inside a function when the memory is modified (i.e, scanf)"""
        self._memory_callback = memory_func

    def add_register_callback(self, register_func):
        """ Add a callback inside a function when the register is modified (i.e, fgetc)"""
        self._register_callback = register_func

    def add_instruction_callback(self, emulate_func):
        """ Add a callback for each instruction """
        self._emulate_callback = emulate_func

    def _load_binary(self, ctx):
        """ Map the binary into memory """
        phdrs = self.binary.segments
        for phdr in phdrs:
            size = phdr.physical_size
            vaddr = phdr.virtual_address
            LOGGER.info('Loading 0x%06x - 0x%06x' % (vaddr, vaddr+size))
            ctx.setConcreteMemoryAreaValue(vaddr, phdr.content)
        return

    def _make_relocation(self, ctx):
        """ Perform our own relocations """
        missing_symbol = set()
        try:
            # for rel in binary.pltgot_relocations:
            for rel in self.binary.relocations:
                symbol_name = rel.symbol.name
                symbol_relo = rel.address
                # By default set the relocations to BASE_FAIL, and Add the symbol to a list
                ctx.setConcreteMemoryValue(MemoryAccess(symbol_relo, CPUSIZE.QWORD), BASE_FAIL)
                missing_symbol.add(symbol_name)
                for key, val in self.custom_relocation.items():
                    if symbol_name == val[0]:
                        LOGGER.info('[+] Hooking %s' % (symbol_name))
                        ctx.setConcreteMemoryValue(MemoryAccess(symbol_relo, CPUSIZE.QWORD), key)
                        missing_symbol.discard(symbol_name)
                        break
            for symb in missing_symbol:
                LOGGER.info('[-] Miss Hooking %s' % (symb))
        except:
            pass

    def tracer_init(self, ctx):
        """ Initialize the tracer """
        # Parse the binary
        self.binary = lief.parse(self.program_name)

        # Load the binary
        self._load_binary(ctx)

        # Perform our own relocations
        self._make_relocation(ctx)

    def start(self, ctx, maximum_lap, entrypoint=None):
        """ Start emulating the program

        :param ctx (TritonContext): The triton context
        :param maximum_lap (int): Maximum lap number
        :param entrypoint (int): The entrypoint address
        """
        # call start callback
        # self._start_callback(configure_logger())

        ret_value = 0
        lap = 0
        while lap < maximum_lap:
            # concretize previous context
            ctx.concretizeAllMemory()
            ctx.concretizeAllRegister()

            # define a fake stack
            ctx.setConcreteRegisterValue(ctx.registers.rbp, BASE_STACK)
            ctx.setConcreteRegisterValue(ctx.registers.rsp, BASE_STACK)

            # let's emulate the binary from the entry point
            LOGGER.info('[+] starting emulation.')
            if entrypoint:
                pc = entrypoint
            else:
                pc = self.binary.entrypoint
            ret_value = self.emulate(ctx, pc)
            if ret_value < 0:
                break

            # End callback
            is_loop = self.call_tracking.get(self.lap, Counter())
            self._end_callback(ctx, self.lap, is_loop)

            LOGGER.info('[+] emulation done.')
            self.lap = self.lap + 1
            lap = lap + 1  # local lap counter
            self.malloc_current_allocation = 0

        print colored("------------------- END -------------------", 'cyan', attrs=['reverse', 'blink'])
        return ret_value

    def emulate(self, ctx, pc):
        """ Emulate/Process each instruction. Stored information about function called, branch called

        :param ctx (TritonContext): The Triton Context
        :param pc (int): The entrypoint
        """
        self.last_branch = deque([], 10)
        self.backtrace = list()
        last_call_instruction = 0
        ret_value = 0
        taken_addr = 0
        untaken_addr = 0

        count = 0
        while pc:
            # Fetch opcodes
            opcodes = ctx.getConcreteMemoryAreaValue(pc, 16)

            # Create the Triton instruction
            inst = Instruction()
            inst.setOpcode(opcodes)
            inst.setAddress(pc)

            if ctx.processing(inst) is False:
                LOGGER.info('[-] Instruction not supported: %s' % (str(inst)))
                break

            LOGGER.debug(inst)

            # ================== Trace call
            # CALL OPCODE
            if inst.getType() == 56:
                oper = inst.getOperands()
                if oper[0].getType() == 1:
                    next_adddr = oper[0].getValue()
                    self.backtrace.append(next_adddr)
                    next_section = self.binary.section_from_virtual_address(next_adddr)
                    if next_section.name == ".text":
                        self.last_branch.append(next_adddr)
                    else:
                        last_call_instruction = inst
                else:
                    next_adddr = oper[0].getAddress()
                    self.backtrace.append(next_adddr)
                    # trace basic block
                    next_section = self.binary.section_from_virtual_address(next_adddr)
                    if next_section.name == ".text":
                        self.last_branch.append(next_adddr)
                    else:
                        last_call_instruction = inst
                    # Use named insted of address
                    pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
                self.show_backtrace()
            # RET OPCODE
            if inst.getType() == 149:
                self.backtrace.pop()
                self.show_backtrace()

            # ================== Trace Execution
            if inst.isBranch() is True:
                untaken_addr = self.is_text_section(inst.getNextAddress())
                oper = inst.getOperands()
                if oper[0].getType() == 1:
                    taken_addr = oper[0].getValue()
                    taken_addr = self.is_text_section(taken_addr)
                    if taken_addr != 0:
                        self.last_branch.append(taken_addr)
                else:
                    taken_addr = oper[0].getAddress()
                    taken_addr = self.is_text_section(taken_addr)
                    if taken_addr != 0:
                        self.last_branch.append(taken_addr)
                if inst.isConditionTaken() is True:
                    LOGGER.debug("Condition Taken : 0x%08x", taken_addr)
                    self.untaken_branch.add(untaken_addr)
                    self.taken_branch.add(taken_addr)
                else:
                    LOGGER.debug("Condition no taken : 0x%08x", untaken_addr)
                    self.untaken_branch.add(taken_addr)
                    self.taken_branch.add(untaken_addr)

            # emulate Callback
            ret_value = self._emulate_callback(inst, taken_addr, untaken_addr)
            if ret_value < 0:
                break

            if inst.getType() == OPCODE.HLT:
                break

            # Simulate routines
            ret_value = self._hooking_handler(ctx, last_call_instruction)
            if ret_value < 0:
                LOGGER.debug("Emulate return Value : %d", ret_value)
                break

            # Next
            pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
            count = count + 1

        LOGGER.info('[+] Instruction executed: %d' % (count))
        return ret_value

    def _hooking_handler(self, ctx, last_call_instruction):
        """ Check if the instruction has been relocated/replaced. If yes, call his handler

        :param ctx (TritonContext): The Triton Context
        :param last_call_instruction (Instruction): The Instruction to check
        """

        ret_value = 0
        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
        for key, val in self.custom_relocation.items():
            if key == pc:
                # Emulate the routine and the return value
                ret_value = val[1](ctx, pc, last_call_instruction)
                if ret_value is not None and ret_value >= 0 and (type(ret_value) == int or type(ret_value) == long):
                    # need to concretize ?
                    ctx.concretizeRegister(ctx.registers.rax)
                    ctx.setConcreteRegisterValue(ctx.registers.rax, ret_value)
                elif type(ret_value) is int and ret_value < 0:
                    break
                    # Something went wrong with a function
                else:
                    LOGGER.info("The return value is not concrete")
                    pass

                # Get the return address
                ret_addr = ctx.getConcreteMemoryValue(MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.rsp), CPUSIZE.QWORD))

                # Hijack rip to skip the call
                ctx.concretizeRegister(ctx.registers.rip)
                ctx.setConcreteRegisterValue(ctx.registers.rip, ret_addr)

                # Restore rsp (simulate the ret)
                ctx.concretizeRegister(ctx.registers.rsp)
                ctx.setConcreteRegisterValue(ctx.registers.rsp, ctx.getConcreteRegisterValue(ctx.registers.rsp)+CPUSIZE.QWORD)
        return ret_value

    def _count_loop(self, last_call_instruction=None):
        """ Add +1 to the instruction counter and return the counter for the current Instruction """
        LOGGER.info("[+] Function loopCounter")
        if last_call_instruction:
            self.call_tracking.setdefault(self.lap, Counter()).update({last_call_instruction.getAddress()})
            return self.call_tracking[self.lap][last_call_instruction.getAddress()]
        else:
            return 0

    def is_text_section(self, addr):
        next_section = self.binary.section_from_virtual_address(addr)
        if next_section.name == ".text":
            return addr
        else:
            return 0

    def printSymVar(self):
        """ Print all symbolic variable """
        for k, v in ctx.getSymbolicVariables().items():
            print "SymvarId : ", k, " kind : ", v.getKind(), "kind value : ", hex(v.getKindValue()), " Memory Value : ", chr(ctx.getConcreteMemoryValue(v.getKindValue())), ", comments : ", v.getComment(), ", bitSize : ", v.getBitSize()

    def show_backtrace(self):
        """ Show the backtrace """
        if self.backtrace:
            for i in range(len(self.backtrace)):
                LOGGER.debug("[%d] 0x%08x", i, self.backtrace[i])

    def printRegisters(self, ctx):
        """ Print the registers """
        print "rax Register : ", hex(ctx.getConcreteRegisterValue(ctx.registers.rax))
        print "rbx Register : ", hex(ctx.getConcreteRegisterValue(ctx.registers.rbx))
        print "rcx Register : ", hex(ctx.getConcreteRegisterValue(ctx.registers.rcx))
        print "rdx Register : ", hex(ctx.getConcreteRegisterValue(ctx.registers.rdx))
        print "rdi Register : ", hex(ctx.getConcreteRegisterValue(ctx.registers.rdi))
        print "rsi Register : ", hex(ctx.getConcreteRegisterValue(ctx.registers.rsi))
        print "rsp Register : ", hex(ctx.getConcreteRegisterValue(ctx.registers.rsp))
        print "rbp Register : ", hex(ctx.getConcreteRegisterValue(ctx.registers.rbp))
        print "rip Register : ", hex(ctx.getConcreteRegisterValue(ctx.registers.rip))

    def _start_callback(self):
        pass

    def _register_callback(self, inputs, register, last_call_instruction=None, min_loop=None):
        pass

    def _memory_callback(self, name, ctx, base_addr, inputs, last_call_instruction, loop_round, min_value, max_value, disable_loop=None):
        pass

# =============================== Handler =========================================
    def _honey_pot(self, ctx, pc, last_call_instruction):
        LOGGER.info('[-] _honey_pot hooked')
        LOGGER.info('[-] This function is not map')
        LOGGER.info('[-] %s', last_call_instruction)

        self.backtrace.pop()
        return -1

    def _libc_main_handler(self, ctx, pc, last_call_instruction):
        LOGGER.info('[+] __libc_start_main hooked')
        ret = 0

        # Get arguments
        main = ctx.getConcreteRegisterValue(ctx.registers.rdi)
        self.backtrace.append(main)

        # Push the return value to jump into the main() function
        ctx.concretizeRegister(ctx.registers.rsp)
        ctx.setConcreteRegisterValue(ctx.registers.rsp, ctx.getConcreteRegisterValue(ctx.registers.rsp)-CPUSIZE.QWORD)

        ret_to_main = MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.rsp), CPUSIZE.QWORD)
        ctx.concretizeMemory(ret_to_main)
        ctx.setConcreteMemoryValue(ret_to_main, main)

        # Setup argc / argv
        ctx.concretizeRegister(ctx.registers.rdi)
        ctx.concretizeRegister(ctx.registers.rsi)

        argvs = [
            self.program_name,  # argv[0]
            self.default_input,  # argv[1]
        ]

        # Define argc / argv
        base = BASE_ARGV
        addrs = list()

        index = 0
        for argv in argvs:
            addrs.append(base)
            ret = self._memory_callback(self.custom_relocation[pc][0], ctx, base, argv, last_call_instruction, self.call_tracking.get(self.lap, Counter()), 0, None, True)
            base += 0x10000  # don't need ?
            LOGGER.debug('[+] argv[%d] = %s' % (index, argv))
            index += 1

        argc = len(argvs)
        argv = base
        for addr in addrs:
            ctx.setConcreteMemoryValue(MemoryAccess(base, CPUSIZE.QWORD), addr)
            base += CPUSIZE.QWORD

        ctx.setConcreteRegisterValue(ctx.registers.rdi, argc)
        ctx.setConcreteRegisterValue(ctx.registers.rsi, argv)
        return ret

    def _get_format_string(self, ctx, addr):
        l = 0
        while ctx.getConcreteMemoryValue(addr+l) != 0:
            l += 1
        s = ctx.getConcreteMemoryAreaValue(addr, l)
        return s.replace("%s", "{}").replace("%d", "{:d}").replace("%#02x", "{:#02x}")  \
               .replace("%#x", "{:#x}").replace("%x", "{:x}").replace("%02X", "{:02x}") \
               .replace("%c", "{:c}").replace("%02x", "{:02x}").replace("%ld", "{:d}")  \
               .replace("%*s", "").replace("%lX", "{:x}").replace("%08x", "{:08x}")     \
               .replace("%u", "{:d}").replace("%lu", "{:d}")

    def _get_memory_string(self, ctx, addr):
        s = str()
        index = 0

        while ctx.getConcreteMemoryValue(addr+index):
            c = chr(ctx.getConcreteMemoryValue(addr+index))
            # if c not in string.printable:
            #     c = ""
            s += c
            index += 1
        return s

    def _printf_handler(self, ctx, pc, last_call_instruction):
        LOGGER.info('[+] printf hooked')

        # Get arguments
        return_addr = ctx.getConcreteRegisterValue(ctx.registers.rsp)
        arg1 = self._get_format_string(ctx, ctx.getConcreteMemoryValue(MemoryAccess(return_addr + 0x4, CPUSIZE.QWORD)))
        arg2 = ctx.getConcreteMemoryValue(MemoryAccess(return_addr + 0x8, CPUSIZE.QWORD))
        arg3 = ctx.getConcreteMemoryValue(MemoryAccess(return_addr + 0x10, CPUSIZE.QWORD))
        arg4 = ctx.getConcreteMemoryValue(MemoryAccess(return_addr + 0x18, CPUSIZE.QWORD))
        arg5 = ctx.getConcreteMemoryValue(MemoryAccess(return_addr + 0x20, CPUSIZE.QWORD))
        arg6 = ctx.getConcreteMemoryValue(MemoryAccess(return_addr + 0x28, CPUSIZE.QWORD))
        nbArgs = arg1.count("{")
        args = [arg2, arg3, arg4, arg5, arg6][:nbArgs]
        s = arg1.format(*args)

        if LOGGER.info:
            sys.stdout.write(s)
        self.backtrace.pop()
        return nbArgs

    def _puts_handler(self, ctx, pc, last_call_instruction):
        self.backtrace.pop()
        return 0

# Simulate the malloc() function
    def _malloc_handler(self, ctx, pc, last_call_instruction):
        LOGGER.info('[+] malloc hooked')

        # Get arguments
        size = ctx.getConcreteRegisterValue(ctx.registers.rdi)

        if size > self.malloc_chunk_size:
            LOGGER.info('malloc failed: size too big')
            sys.exit(-1)

        if self.malloc_current_allocation >= self.malloc_max_allocation:
            LOGGER.info('malloc failed: too many allocations done')
            sys.exit(-1)

        area = self.malloc_base + (self.malloc_current_allocation * self.malloc_chunk_size)
        self.malloc_current_allocation += 1

        # Return value
        LOGGER.debug("return area : 0x%08x", area)
        self.backtrace.pop()
        return area

    def _scanf_handler(self, ctx, pc, last_call_instruction):
        LOGGER.info("[+] scanf hooked")
        # Get arguments
        return_addr = ctx.getConcreteRegisterValue(ctx.registers.rsp)
        arg1 = self._get_format_string(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))
        arg2 = ctx.getConcreteRegisterValue(ctx.registers.rsi)
        arg3 = ctx.getConcreteRegisterValue(ctx.registers.rdx)
        nbArgs = arg1.count("{")
        args = [arg2, arg3][:nbArgs]
        s = arg1.format(*args)

        LOGGER.debug("scanf arguments, arg1 : 0x%08x, arg2 : 0x%08x, arg3 : 0x%08x", s, arg2, arg3)

        ret = self._memory_callback(self.custom_relocation[pc][0], ctx, arg2, self.default_input, last_call_instruction, self._count_loop(last_call_instruction), 0, None, False)

        if ret < 0:
            nbArgs = ret

        self.backtrace.pop()
        return nbArgs

# Simulate the strtoul() function
    def _stroul_handler(self, ctx, pc, last_call_instruction):
        debug('[+] strtoul hooked')

        # Get arguments
        nptr = _get_memory_string(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))
        endptr = ctx.getConcreteRegisterValue(ctx.registers.rsi)
        base = ctx.getConcreteRegisterValue(ctx.registers.rdx)

        self.backtrace.pop()
        # Return value
        return long(nptr, base)

    # Simulate the atoi() function
    def _atoi_handler(self, ctx, pc, last_call_instruction):
        debug('[+] strtoul hooked')
        addr = ctx.getConcreteRegisterValue(ctx.registers.rdi)
        ret_value = 0
        l = 0
        while ctx.getConcreteMemoryValue(addr+l) != 0:
            isSymb = ctx.isMemorySymbolized(addr+l)
            if ctx.isMemorySymbolized(addr+l) is False:
                isSymb = False
            l += 1

        s = ctx.getConcreteMemoryAreaValue(addr, l)
        from_memory_data = {'base_addr':addr}
        if s.isdigit() is True:
            ret_value = self._register_callback(self.custom_relocation[pc][0], ctx, int(s), ctx.registers.rax, last_call_instruction, True, addr, self._count_loop(last_call_instruction), 0, None)

        self.backtrace.pop()
        return ret_value

    def _fgetc_handler(self, ctx, pc, last_call_instruction):
        LOGGER.info("[+] fgetc Hooked")

        ret_value = self._register_callback(self.custom_relocation[pc][0], ctx, 0x41, ctx.registers.al, last_call_instruction, False, None, self._count_loop(last_call_instruction), None, None)

        self.backtrace.pop()
        return ret_value

    # Simulate the strlen() function
    def _strlen_handler(self, ctx, pc, last_call_instruction):
        LOGGER.debug('[+] strlen hooked')
        self.backtrace.pop()

        arg1 = self._get_memory_string(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))
        if self.symbolized_input is True:
            ret = self._register_callback(self.custom_relocation[pc][0], ctx, len(arg1), ctx.registers.rax, last_call_instruction, True, None, self._count_loop(last_call_instruction), 0, len(arg1))
            return ret

        # Return value
        return len(arg1)
