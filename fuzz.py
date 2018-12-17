from collections import OrderedDict, deque
from termcolor import colored
from triton import MemoryAccess, CPUSIZE
from pwn import unordlist
from subprocess import Popen, PIPE
from itertools import combinations
import sys
import logging


LOGGER = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(process)s - %(filename)s -  %(lineno)s - %(levelname)s]  %(message)s"))
LOGGER.addHandler(console_handler)
LOGGER.setLevel(logging.INFO)

# Notes
# [ ] Is saved_mutate_input needed ? because we have str_mutate_input


class Fuzz():
    """
    Fuzzing Object, Use Radamsa to mutate or generate inputs
    First part :
    """
    def __init__(self, exploration_memory, exploration_registers, from_memory_addr, dst_addr, queue):
        """
        :param dst_path (list): The destination address we want to reach
        :param radamsa_bin (str): Radamsa binary path
        :param call_address_list (list): Contain functions addresses where fuzzing is possible

        :param exploration_memory (nested dict)    : Store informations about the differents path reach and symbolized memory
        :param exploration_registers (nested dict) : Store informations about the differents paths reach and symbolized registers
        :param from_memory_addr (int)              : Contain a path address that we will used as original inputs
        :param lock ()                             : Multiprocess lock (is needed ?)
        :param queue (Queue)                       : Multiprocess queue to transmit data between process

        :param registers_input (dict)      : Contain original data to used for each function ({0x401337         : [65,10]})
        :param iter_registers_input (iter) : iterator over registers_input ({0x401337                           : iter([65,10])}))
        :param mutate_input (dict)         : Contain mutated_data for each selected function address ({4198922L : deque(['A', 'A', '\n'])})
        :param saved_mutate_input (dict)   : Original mutated inputs copy
        :param str_mutate_input (str)      : Real inputs used
        :param dry_lap (bool)              : Flag to know if the dry lap has been reach or not
        """

        self.dst_path = list()
        self.dst_path.append({'taken_addr': dst_addr, 'vars': {}})
        self.radamsa_bin = '/usr/bin/radamsa'
        self.call_address_list = list()

        LOGGER.debug("from_memory_addr : 0x%08x, dst_addr : 0x%08x", from_memory_addr, dst_addr)
        self.exploration_memory = exploration_memory
        self.exploration_registers = exploration_registers
        self.from_memory_addr = from_memory_addr

        # multiprocess
        # self.lock = lock
        self.queue = queue

        # registers fuzzing
        self.registers_input = dict()
        self.iter_registers_input = dict()
        # memory fuzzing
        self.memory_input = dict()

        self.mutate_input = dict()
        self.saved_mutate_input = dict()
        self.str_mutate_input = ''

        self.dry_lap = True

    # def fuzz(self, exploration_memory, exploration_registers, from_memory_addr, dst_addr, lock, queue):
    #     LOGGER.debug("[+] fuzz function")


    def mutate(self, payload, count, generate):
        """ Mutate data

        :param payload (str): data to mutate
        :param count (int): how many output to generate
        :param generate (bool): Mutate or generate data
        """

        try:
            if generate is True:
                radamsa = [self.radamsa_bin, '-g', 'random', '-n', str(count), '-o', '/tmp/radamsa-%01n.txt']
            else:
                radamsa = [self.radamsa_bin, '-g', 'stdin', '-n', str(count), '-o', '/tmp/radamsa-%01n.txt']
            p = Popen(radamsa, stdin=PIPE, universal_newlines=True)
            p.communicate(payload)
            p.wait()
        except:
            LOGGER.error("Could not execute 'radamsa'.")
            sys.exit(1)
        with open('/tmp/radamsa-1.txt', 'rb') as f:
            mutated_data = f.read()
        return mutated_data

    def _all_combinations(self, iterable):
        for L in range(0, len(iterable)+1):
            for subset in combinations(iterable, L):
                yield subset

    # return inputs to go to dst_address
    def get_memory_input_to_address(self, last_call_address, select_addr):
        """ get memory input to reach an address

        :param last_call_address (int) : Current function address
        :param select_addr (int)       : The pointer address to stored data
        """
        next_input = list()
        try:
            for k, v in self.exploration_memory.get(self.from_memory_addr, dict()).get('call_addr', OrderedDict()).items():
                for ke, va in v['base_addr'].items():
                    if ke == select_addr:
                        for keys, vals in sorted(va['sym_vars_addr'].items()):
                            while len(next_input) < (keys - select_addr):
                                next_input.append(0x41)
                            try:
                                next_input.append(vals['values'][0])
                            except:
                                break
        except:
            next_input = -1
        self.memory_input.update({select_addr: next_input})
        return next_input

    def get_register_input_to_address(self, last_call_address, loop_round, default):
        """ get register input to reach an address

        :param last_call_address (int) : Current function address
        :param loop_round (int)        : The number of times the loop is carried out
        :param default (int)           : The default value to return
        """

        LOGGER.info("[+] Function getRegisterInput")
        next_input = list()
        if self.registers_input.has_key(last_call_address) is False:
            # pdb.set_trace()
            if self.exploration_registers.has_key(self.from_memory_addr):
                LOGGER.debug("dst_addr : 0x%08x", self.from_memory_addr)
                for ke, va in self.exploration_registers[self.from_memory_addr]['call_addr'].items():
                    if ke == last_call_address:
                        LOGGER.debug("call_addr : 0x%08x", ke)
                        for k, v in sorted(va['loop_round'].items()):
                            LOGGER.debug("loop_round : %d", k)
                            next_input.append(v['values'])

                        self.registers_input.update({last_call_address: next_input})
                        self.iter_registers_input.update({last_call_address: iter(next_input)})
                        return next_input
            self.registers_input.update({last_call_address: [default]})
            self.iter_registers_input.update({last_call_address: iter([default])})
        return default

    def start(self, logger):
        """
        """
        global LOGGER
        LOGGER = logger

    def end(self, ctx, lap, isLoop):
        """ Callback function.
        Function called by the Tracer at the program ending

        :param ctx (TritonContext) : The triton context
        :param lap (int)           : The lap number (integer)
        :param is_loop (dict)      : The number of time each function has been called during this lap. dict({<function addr>: counter})
        """

        self.str_mutate_input = ''
        # + select in which callAddress we mutate data
        # pdb.set_trace()
        if self.dry_lap is True:
            self.selected_fuzz_address = self._all_combinations(self.call_address_list[::-1])
            # get rid of the first input ( always empty )
            self.select_fuzz_address = next(self.selected_fuzz_address)

        # end of dry lap
        self.dry_lap = False

        # make register input iterable again
        for k, v in self.registers_input.items():
            self.iter_registers_input.update({k: iter(v)})

        # next Address every 100 lap ?
        LOGGER.debug("lap round : %d", lap)
        if lap % 30 == 0:
            self.select_fuzz_address = next(self.selected_fuzz_address)

    def fuzz_register(self, name, ctx, inputs, register, last_call_instruction, is_input_needed, base_addr, loop_round, min_value, max_value):
        """ Callback function. Function called by the Tracer if it's possible to fuzz register

        :param name (str)                          : The function name (type(str))
        :param ctx (TritonContext)                 : The triton context
        :param inputs (str)                        : The concrete value
        :param register (register)                 : The register to worked on. Needed to know the register size
        :param last_call_instruction (Instruction) : The current function address
        :param is_input_needed (boolean)                   : If True we don't need want to replace inputs (used only for the libc_main function)
        :param loop_round (int)                    : How many time this function has been called during this lap
        :param min_value (int)                     : The minimum value
        :param max_value (int)                     : The maximum value
        """

        LOGGER.info("[+] Function fuzz_register")

        # Make sure last_call_address is not empty
        if last_call_instruction:
            last_call_address = last_call_instruction.getAddress()
        else:
            last_call_address = 0x0

        # should be useless ! just in chase
        if is_input_needed is False:
            LOGGER.info("last callInstruction : %s", last_call_instruction)
            # check if we are not in libc_main
            if last_call_instruction:
                LOGGER.debug("number of loop", loop_round)

                if loop_round <= 1:
                    LOGGER.debug("Not in a loop")
                elif loop_round > 400:
                    return -1
                else:
                    pass
            else:
                loop_round = 0

            # there is no need to fuzz function like atoi, strlen, etc...
            # separate symbolizedRegister function in two parts ? only elligible fuinction can call this one
            # check if function is elligible for fuzzing
            # atoi for example doesnt need to change input, but maybe need to symbolized input

            if name == 'fgetc' or name == 'getc' or name == 'getchar':
                if self.registers_input.has_key(last_call_address) is False:
                    self.get_register_input_to_address(last_call_address, loop_round, inputs)
                    # save callAddress in a list
                    self.call_address_list.append(last_call_address)
                # do one round to check if input is valid
                if self.dry_lap is True:
                    LOGGER.debug("dry_lap : True")
                    try:
                        inputs = next(self.iter_registers_input[last_call_address])
                    except:
                        pass
                else:
                    if last_call_address in self.select_fuzz_address:
                        LOGGER.debug("Select Fuzz : 0x%08x", last_call_address)
                        if self.registers_input[last_call_address]:
                            # mutate input
                            try:
                                inputs = ord(self.mutate_input[last_call_address].popleft())
                            except:
                                mutate = ''
                                while not mutate:
                                    mutate = self.mutate(unordlist(self.registers_input[last_call_address]), 1, False)
                                self.mutate_input.update({last_call_address: deque(mutate)})
                                self.saved_mutate_input.update({last_call_address: deque(mutate)})
                                inputs = ord(self.mutate_input[last_call_address].popleft())
                        else:
                            # generate input
                            try:
                                inputs = ord(self.mutate_input[last_call_address].popleft())
                            except:
                                mutate = ''
                                while not mutate:
                                    mutate = self.mutate(unordlist(self.registers_input[last_call_address]), 1, True)
                                self.mutate_input.update({last_call_address: deque(mutate)})
                                self.saved_mutate_input.update({last_call_address: deque(mutate)})
                                inputs = ord(self.mutate_input[last_call_address].popleft())
                    else:
                        if self.registers_input.has_key(last_call_address):
                            try:
                                inputs = next(self.iter_registers_input[last_call_address])
                            except:
                                pass

            self.str_mutate_input += chr(inputs)
            print colored("Inputs!!", 'green', attrs=['reverse', 'blink'])
            LOGGER.info("inputs to send : 0x%08x at call Instruction : %08x, dst_path : 0x%08x", inputs, last_call_address, self.dst_path[-1].get('taken_addr', 0x0))

        return inputs

    def fuzz_memory(self, name, ctx, base_addr, inputs, last_call_instruction, loop_round, min_value, max_value, disable_loop=None):
        """ Callback function. Function called by the Tracer if it's possible to fuzz memory

        :param name (str)                          : The function name
        :param ctx (TritonContext)                 : The triton context
        :param base_addr (int)   : The pointer address where inputs is stored in memory
        :param inputs (str)                        : The concrete value
        :param last_call_instruction (Instruction) : The current function address
        :param loop_round (int)                    : How many time this function has been called during this lap
        :param min_value (int)                     : The minimum value
        :param max_value (int)                     : The maximum value
        :param disable_loop (bool)                 : Flag
        """
        LOGGER.info("[+] Function fuzz_memory")

        LOGGER.info("last callInstruction : %s", last_call_instruction)
        # check if we are not in libc_main
        if not disable_loop:
            LOGGER.debug("Loop Number : %d", loop_round)
            if loop_round <= 1:
                LOGGER.debug("Not in a loop")
            else:
                pass
        else:
            loop_round = 0

        # pdb.set_trace()
        if self.memory_input.has_key(base_addr) is False:
            self.get_memory_input_to_address(last_call_instruction.getAddress(), base_addr)
            # save callAddress in a list
            self.call_address_list.append(base_addr)
        # do one round to check if input is valid
        if self.dry_lap is True:
            try:
                tmp = unordlist(self.memory_input[base_addr])
                if tmp:
                    inputs = tmp
            except:
                pass
        else:
            if base_addr in self.select_fuzz_address:
                LOGGER.debug("Select Fuzz : 0x%08x", base_addr)
                if self.memory_input[base_addr]:
                    # mutate input
                    try:
                        inputs = self.mutate_input[base_addr]
                    except:
                        mutate = self.mutate(unordlist(self.memory_input[base_addr]), 2, False)
                        self.mutate_input.update({base_addr: mutate})
                        self.saved_mutate_input.update({base_addr: mutate})
                        inputs = self.mutate_input[base_addr]
                else:
                    # generate input
                    try:
                        inputs = self.mutate_input[base_addr]
                    except:
                        mutate = self.mutate(unordlist(self.registers_input[base_addr]), 2, True)
                        self.mutate_input.update({base_addr: mutate})
                        self.saved_mutate_input.update({base_addr: mutate})
                        inputs = self.mutate_input[base_addr]
                # for i in range(len(mutate)):
                #     self.mutate_input.setdefault(self.dst_path[-1]['taken_addr']).setdefault('call_addr').setdefault(last_call_address).setdefault('base_addr').setdefault(addr).setdefault('sym_vars_addr').update({(base_addr + i):mutate[i]})
            else:
                if self.memory_input[base_addr]:
                    try:
                        tmp = unordlist(self.memory_input[base_addr])
                        if tmp:
                            inputs = tmp
                    except:
                        pass

        print colored("Inputs!!", 'green', attrs=['reverse', 'blink'])
        LOGGER.info("inputs to send : %s at address : %08x, dst_path : 0x%08x", repr(inputs), base_addr, self.dst_path[-1].get('taken_addr', 0x0))
        self.str_mutate_input += inputs + '\n'
        inputs += "\x00"
        # pause()

        for i in range(len(inputs)):
            ctx.setConcreteMemoryValue(MemoryAccess(base_addr + i, CPUSIZE.BYTE), ord(inputs[i]))
            LOGGER.debug("At addr : 0x%08x, input : %c", base_addr+i, inputs[i])
        return len(inputs)

    def get_instruction(self, inst, taken_addr, untaken_addr):
        """ Callback function. Function called by the Tracer for each instruction

        :param inst (Instruction) : Instruction executed
        :param taken_addr (int)   : Taken branch address if the instruction is a branch
        :param untaken_addr (int) : Untaken branch address if the instruction is a branch
        """
        # LOGGER.debug("get_instruction Callback")
        # If the destination path is reach, update

        if inst.getAddress() == self.from_memory_addr:
            print colored('from_memory_addr Reach : ' + hex(self.from_memory_addr), 'red', attrs=['reverse', 'blink'])
            LOGGER.info("from_memory_addr Reach!")

        if inst.getAddress() == self.dst_path[-1].get('taken_addr', 0x0):
            LOGGER.info("[+] Destination path 0x%08x reach", self.dst_path[-1].get('taken_addr'))
            self.queue.put((self.dst_path[-1].get('taken_addr'), self.str_mutate_input))
            return -1
        return 0
