import pdb
from collections import OrderedDict, Counter
from termcolor import colored
import json
import time
from triton import SYMEXPR, MemoryAccess, CPUSIZE, TritonContext, ARCH, MODE, AST_REPRESENTATION
from tracer import Tracer
from fuzz import Fuzz
from pwn import unordlist, ordlist, pause
from multiprocessing import get_logger
import logging


LOGGER = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(process)s - %(filename)s -  %(lineno)s - %(levelname)s]  %(message)s"))
LOGGER.addHandler(console_handler)
LOGGER.setLevel(logging.INFO)


class Exploration(object):
    """
    Exploration Object, Symbolized inputs, looking for new paths
    """

    def __init__(self):
        """
        :param exploration_memory (nested dict)     : Store informations about the differents path reach and symbolized memory
        :param exploration_registers (nested dict)  : Store informations about the differents paths reach and symbolized registers
        :param exploration_fuzz (nested dict)       : Stored a destination address and the string used to reach the destination {dst_addr: {'inputs': 'AAAA', 'index': 0}}
        :param sym_vars_constraint (dict)           : Stored differente constraint about a function (i.e,: Maximum number of characters to be copied)
        :param added_constraint_node (dict)         : Node constraint to add to a symbolic variable ({'Symvar_0:Node'})
        :param dst_path (dict)                      : The current destination we are trying to reach (0x0 not defined yet) ({'taken_addr':0x0,'vars':data})
        :param untaken_addr (dict)                  : Stored all untaken branch address associate with data used to go to the source branch ({0x401337:data})
        :param taken_addr (dict)                    : Stored all taken branch address associate with data used to go to the source branch ({0x401348:data})
        :param dst_path_counter (Counter)           : Count the number of time we are trying to reach a specific address (+1 on each lap). Used to know if a destination is unreachable.
        :param fuzz_is_needed (bool)                : If true, all the path are reach
        """
        self.exploration_memory = dict()
        self.exploration_registers = dict()
        self.exploration_fuzz = dict()
        self.sym_vars_constraint = dict()
        self.added_constraint_node = dict()
        self.dst_path = list()
        self.dst_path.append({'taken_addr': 0x0, 'vars': {}})
        self.untaken_branch = dict()
        self.taken_branch = dict()
        self.dst_path_counter = Counter()
        self.fuzz_is_needed = False

    # -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- Fuzzing -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
    def add_fuzz_inputs(self, dst_addr, inputs):
        """Add fuzz inputs to exploration_memory and exploration_registers

        :param dst_addr (int) : The destination Address reached
        :param inputs (str)   : The whole string used to reach the destination ('AAAAA\nCCC\n')
        """

        LOGGER.info("[+] function _convert_memory_fuzzing_inputs")
        self.exploration_fuzz.update({dst_addr: {'inputs': inputs, 'index': 0}})
        self.exploration_memory.update({dst_addr: {
            'fuzz_inputs': self.exploration_fuzz[dst_addr],
            'is_taken': False,
            'unreachable': False,
            'fuzz': True,
            'copy_from': False}})
        self.exploration_registers.update({dst_addr: {
            'fuzz_inputs': self.exploration_fuzz[dst_addr],
            'is_taken': False,
            'unreachable': False,
            'fuzz': True,
            'copy_from': False}})

    def _convert_memory_fuzzing_inputs(self, dst_address, call_addr, base_addr, values, loop_round):
        """Convert fuzzing inputs format ('str') to exploration_memory format

        :param dst_address (int) : The destination reached
        :param call_addr (int)   : The current function address (i.e, scanf address)
        :param base_addr (int)   : The pointer address where inputs is stored in memory
        :param values (str)      : String value stored at base_addr
        :param loop_round (int)  : Number of loop round.
        """

        LOGGER.info("[+] function _convert_memory_fuzzing_inputs")
        for i in range(len(values)):
            self.exploration_memory.setdefault(dst_address, dict()).setdefault('call_addr', dict()).setdefault(call_addr, dict()).setdefault('base_addr', dict()).setdefault(base_addr, dict()).setdefault('sym_vars_addr', OrderedDict()).setdefault(base_addr + i, {}).setdefault('values', dict()).update({0: values[i]})
            self.exploration_memory.setdefault(dst_address, dict()).setdefault('call_addr', dict()).setdefault(call_addr, dict()).setdefault('base_addr', dict()).setdefault(base_addr, dict()).setdefault('sym_vars_addr', OrderedDict()).setdefault(base_addr + i, {}).update({'base_addr': base_addr, 'kind': 2})
            self.exploration_memory.setdefault(dst_address, dict()).update({'loop_round': loop_round})

    def _convert_registers_fuzzing_inputs(self, dst_address, call_addr, values, loop_round):
        """Convert fuzz inputs format (flat string) to exploration registers format

        :param dst_address : The destination reached
        :param call_addr   : The current function address (i.e, scanf address)
        :param base_addr   : The pointer address where inputs is stored in memory
        :param values      : String value stored at base_addr
        """

        self.exploration_registers.setdefault(dst_address, dict()).setdefault('call_addr', dict()).setdefault(call_addr, dict()).setdefault('loop_round', dict()).setdefault(loop_round, dict()).update({'values': values})
        self.exploration_registers.setdefault(dst_address, dict()).setdefault('call_addr', dict()).setdefault(call_addr, dict()).setdefault('loop_round', dict()).setdefault(loop_round, dict()).update({'register': 1})

    # -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- Get Inputs -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
    def get_register_input(self, last_call_address, loop_round, default):
        """ return an input, for the current function (i.e, fgetc)

        :param last_call_address (int) : The current function address (i.e, fgetc)
        :param loop_round (int)        : The number of times the loop is carried out
        :param default (int)           : The default value to return

        :return (int)                  : The Value
        """

        if self.dst_path[-1]['taken_addr'] == 0:
            LOGGER.debug("dst_path addresse is 0x0")
            for key, val in reversed(sorted(self.exploration_registers.items())):
                if val['is_taken'] is False and val['unreachable'] is False:
                    if val['fuzz'] is False:
                        LOGGER.debug("dst_addr : 0x%08x", key)
                        for ke, va in sorted(val['call_addr'].items()):
                            LOGGER.debug("call_addr : 0x%08x", ke)
                            if ke == last_call_address:
                                if max(va['loop_round'].keys()) >= loop_round:
                                    for k, v in sorted(va['loop_round'].items()):
                                        LOGGER.debug("loop_round : %d", k)
                                        if k == loop_round:
                                            self.dst_path[-1]['taken_addr'] = key
                                            self.dst_path[-1]['vars'] = v['values']
                                            return v['values']
                                else:
                                    self.dst_path[-1]['taken_addr'] = key
                                    self.dst_path[-1]['vars'] = va['loop_round'][1]['values']  # select first possiblity ? list(va['loop_round])[:1:]['values']
                                    return va['loop_round'][1]['values']
                    else:
                        inputs = self.get_fuzz_inputs(self.dst_path[-1]['taken_addr'], self.exploration_registers[self.dst_path[-1]['taken_addr']]['fuzz_inputs'], 1)[0]
                        self._convert_registers_fuzzing_inputs(key, last_call_address, inputs, loop_round)
                        return inputs
        else:
            if self.exploration_registers[self.dst_path[-1]['taken_addr']]['fuzz'] is True:
                inputs = self.get_fuzz_inputs(self.dst_path[-1]['taken_addr'], self.exploration_registers[self.dst_path[-1]['taken_addr']]['fuzz_inputs'], 1)[0]
                self._convert_registers_fuzzing_inputs(self.dst_path[-1]['taken_addr'], last_call_address, inputs, loop_round)
                return inputs
            else:
                for ke, va in self.exploration_registers[self.dst_path[-1]['taken_addr']]['call_addr'].items():
                    LOGGER.debug("call_addr : 0x%08x", ke)
                    if ke == last_call_address:
                        if max(va['loop_round'].keys()) >= loop_round:
                            for k, v in sorted(va['loop_round'].items()):
                                LOGGER.debug("loop_round : %d", k)
                                if k == loop_round:
                                    # if self.dst_path[-1]['taken_addr'] == 0:
                                    #     self.dst_path[-1]['taken_addr'] = key
                                    #     self.dst_path[-1]['vars'] = v['values']
                                    return v['values']
                        else:
                            return va['loop_round'][1]['values']

        return default

    def get_memory_input(self, last_call_address, select_addr, loop_round):
        """ return an input, for the current function (i.e, scanf)

        :param last_call_address (int) : The current function address (i.e, fgetc)
        :param select_addr (int)       : The pointer address to stored data
        :param loop_round (int)        : The number of times the loop is carried out

        :return (list)                 : Return the source char array
        """

        LOGGER.info("[+] Function get_memory_input")
        nextInput = list()
        if self.dst_path[-1]['taken_addr'] == 0:
            for k, v in reversed(sorted(self.exploration_memory.items())):
                if v['is_taken'] is False and v['unreachable'] is False:
                    if v['fuzz'] is False:
                        LOGGER.debug("dst_addr : 0x%08x", k)
                        return self.get_memory_input_to_address(k, last_call_address, select_addr)
                    else:
                        inputs = self.get_fuzz_inputs(k, v['fuzz_inputs'], 1000)
                        self._convert_memory_fuzzing_inputs(k, last_call_address, select_addr, inputs, loop_round)
                        return inputs
        else:
            if self.exploration_memory[self.dst_path[-1]['taken_addr']]['fuzz'] is True:
                inputs = self.get_fuzz_inputs(self.dst_path[-1]['taken_addr'], self.exploration_memory[self.dst_path[-1]['taken_addr']]['fuzz_inputs'], 1000)
                self._convert_memory_fuzzing_inputs(self.dst_path[-1]['taken_addr'], last_call_address, select_addr, inputs, loop_round)
                return inputs
            else:
                return self.get_memory_input_to_address(self.dst_path[-1].get('taken_addr'), last_call_address, select_addr)

    def get_fuzz_inputs(self, dst_addr, fuzz_inputs, step):
        """ return a value(s) from a fuzzing input string, for the current function

        :param dst_addr (int)    : The destination to reach
        :param fuzz_inputs (str) : The whole fuzzing string used by the fuzzer to reach a destination path
        :param step (int)        : How many char the function need (i.e, fgetc need one by one. scanf is unlimited)

        :return (list)           : Return the source char array
        """

        char = '\n'
        start = fuzz_inputs['index']
        end = len(fuzz_inputs['inputs'])
        if start < end:
            index = fuzz_inputs['inputs'].find(char, start, start+step)
            if index >= 0 and index != start:
                tmp = fuzz_inputs['inputs'][start:index]
                fuzz_inputs['index'] = index + 1
            else:
                fuzz_inputs['index'] = start + step
                tmp = fuzz_inputs['inputs'][start:(start + step)]
            if self.dst_path[-1]['taken_addr'] == 0:
                self.dst_path[-1]['taken_addr'] = dst_addr
                self.dst_path[-1]['vars'] = tmp
            if not tmp:
                pdb.set_trace()
            return ordlist(tmp)
        else:
            pdb.set_trace()
            return [0x41]

    def get_memory_input_to_address(self, dst_address, last_call_address, select_addr):
        """ Return value(s) needed to go to the destination address

        :param dst_address (int)       : The destination address we wish to reach
        :param last_call_address (int) : The current function address
        :param select_addr (int)       : The pointer address to stored data

        :return (list)                 : Return the source char array. -1 if error
        """

        LOGGER.info("[+] Function get_memory_input_to_address")
        nextInput = list()
        try:
            for k, v in self.exploration_memory.get(dst_address, dict()).get('call_addr', OrderedDict()).items():
                for ke, va in v['base_addr'].items():
                    if ke == select_addr:
                        for keys, vals in sorted(va['sym_vars_addr'].items()):
                            while len(nextInput) < (keys - select_addr):
                                nextInput.append(0x41)
                            try:
                                nextInput.append(list(vals['values'].values())[0])
                            except:
                                pdb.set_trace()
                                break
                        if self.dst_path[-1]['taken_addr'] == 0:
                            self.dst_path[-1]['taken_addr'] = dst_address
                            self.dst_path[-1]['vars'] = va['sym_vars_addr']
        except:
            pdb.set_trace()
            nextInput = -1
        return nextInput

    def _get_new_input(self, ctx):
        """ Stored a set of new inputs based on the last trace

        :param ctx (TritonContext)  : The triton context

        :return (dict)              : The seed ({<dst_addr>:{<KindValue>: value}})
        """

        LOGGER.info("[+] Function _get_new_input")
        # Set of new inputs
        inputs = list()

        # Get path constraints from the last execution
        pco = ctx.getPathConstraints()

        # We start with any input. T (Top)
        ast = ctx.getAstContext()
        previous_constraints = ast.equal(ast.bvtrue(), ast.bvtrue())

        # Go through the path constraints
        for pc in pco:
            # If there is a condition
            if pc.isMultipleBranches():
                # Get all branches
                branches = pc.getBranchConstraints()
                for branch in branches:
                    # Get the constraint of the branch which has been not taken
                    LOGGER.debug("Is taken : %r, srcAddr : 0x%08x, dstAddr : 0x%08x", branch['isTaken'], branch['srcAddr'], branch['dstAddr'])
                    if branch['isTaken'] is False:
                        seed = dict()
                        if branch['dstAddr'] not in self.exploration_memory.keys():
                            nodeList = [previous_constraints, branch['constraint']]
                            LOGGER.debug("New branch destination Address 0x%08x", branch['dstAddr'])

                            # Add constraint on sym_var
                            for symName, node in self.added_constraint_node.items():
                                if str(ctx.unrollAst(branch['constraint'])).find(symName) != -1 or str(ctx.unrollAst(previous_constraints)).find(symName) != -1:
                                    # add node to constraint
                                    nodeList.append(node)

                            # can't set limit to 2 for the moment because of memory inputs
                            models = ctx.getModels(ast.land(nodeList), 1)

                            for i in range(len(models)):
                                for k, v in sorted(models[i].items()):
                                    # Get the symbolic variable assigned to the model
                                    sym_var = ctx.getSymbolicVariableFromId(k)
                                    json_comment = json.loads(sym_var.getComment())
                                    seed.setdefault(branch['dstAddr'], {}).update({sym_var.getKindValue(): v.getValue()})
                                    if sym_var.getKind() == SYMEXPR.REG:
                                        if json_comment['base_addr']:
                                            # Need to convert Symbolic Register to Symbolic Mem (examples atoi)
                                            try:
                                                values = str(v.getValue())
                                                for s in range(len(values)):
                                                    self.exploration_memory.setdefault(branch['dstAddr'], dict()).setdefault('call_addr', dict()).setdefault(json_comment['last_call_address'], dict()).setdefault('base_addr', dict()).setdefault(json_comment['base_addr'], dict()).setdefault('sym_vars_addr', OrderedDict()).setdefault(json_comment['base_addr'] + s, {}).setdefault('values', dict()).update({i: ord(values[s])})
                                                    self.exploration_memory.setdefault(branch['dstAddr'], dict()).setdefault('call_addr', dict()).setdefault(json_comment['last_call_address'], dict()).setdefault('base_addr', dict()).setdefault(json_comment['base_addr'], dict()).setdefault('sym_vars_addr', OrderedDict()).setdefault(json_comment['base_addr'] + s, {}).update({'base_addr': json_comment['base_addr'], 'kind': 2})
                                                    self.exploration_memory.setdefault(branch['dstAddr'], dict()).update({'is_taken': False, 'loop_round': json_comment['loop_round'], 'unreachable': False, 'copy_from': False, 'fuzz': False})
                                            except:
                                                pdb.set_trace()
                                        else:
                                            # fgetc like function
                                            # {4198988L: {'call_addr': {4198922:{'loop_round': {1: {'register': 1L, 'values': 10L}}}}, 'is_taken': False, 'lastBranch': 4198914L, 'loop': False}}
                                            self.exploration_registers.setdefault(branch['dstAddr'], dict()).setdefault('call_addr', dict()).setdefault(json_comment['last_call_address'], dict()).setdefault('loop_round', dict()).setdefault(json_comment['loop_round'], dict()).update({'values': v.getValue()})
                                            self.exploration_registers.setdefault(branch['dstAddr'], dict()).setdefault('call_addr', dict()).setdefault(json_comment['last_call_address'], dict()).setdefault('loop_round', dict()).setdefault(json_comment['loop_round'], dict()).update({'register': sym_var.getKindValue()})
                                            self.exploration_registers.setdefault(branch['dstAddr'], dict()).update({'is_taken': False, 'unreachable': False, 'copy_from': False, 'fuzz': False})
                                    else:
                                        # sym_var.getKind() == SYMEXPR.MEM
                                        # {4199072L: {'call_addr': {4198584: {'base_addr': {536936448: {'sym_vars_addr': OrderedDict([(536936449L, {'kind': 2, 'values': {0: 117L}, 'base_addr': 536936448})])}}}}, 'is_taken': False, 'loop_round': 0, 'loop': False}}
                                        self.exploration_memory.setdefault(branch['dstAddr'], dict()).setdefault('call_addr', dict()).setdefault(json_comment['last_call_address'], dict()).setdefault('base_addr', dict()).setdefault(json_comment['base_addr'], dict()).setdefault('sym_vars_addr', OrderedDict()).setdefault(sym_var.getKindValue(), {}).setdefault('values', dict()).update({i: v.getValue()})
                                        self.exploration_memory.setdefault(branch['dstAddr'], dict()).setdefault('call_addr', dict()).setdefault(json_comment['last_call_address'], dict()).setdefault('base_addr', dict()).setdefault(json_comment['base_addr'], dict()).setdefault('sym_vars_addr', OrderedDict()).setdefault(sym_var.getKindValue(), {}).update({'base_addr': json_comment['base_addr'], 'kind': 2})
                                        self.exploration_memory.setdefault(branch['dstAddr'], dict()).update({'is_taken': False, 'loop_round': json_comment['loop_round'], 'unreachable': False, 'copy_from': False, 'fuzz': False})
                            try:
                                self.show_exploration(branch['dstAddr'])
                            except KeyError:
                                pass
                        if seed:
                            inputs.append(seed)

            # Update the previous constraints with true branch to keep a good path.
            previous_constraints = ast.land([previous_constraints, pc.getTakenPathConstraintAst()])

        return inputs

    # -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- Callback -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
    def start(self, logger):
        """ Unused yet
        """
        # global LOGGER
        # LOGGER = logger
        pass

    def symbolized_register_input(self, name, ctx, inputs, register, last_call_instruction, is_input_needed, base_addr , loop_round, min_value, max_value):
        """ Callback function. Function called by the Tracer if it's possible to symbolized register

        : param name (str)                          : The function name
        : param ctx (TritonContext)                 : The triton context
        : param inputs (str)                        : The concrete value
        : param register (register)                 : The register to worked on. Needed to know the register size
        : param last_call_instruction (Instruction) : The current function address
        : param is_input_needed (boolean)           : If True we don't need want to modify default inputs (i.e, strcpy)
        : param base_addr                           : If inputs come from memory, we want set the base address (pointer address)
        : param loop_round (int)                    : How many time this function has been called during this lap
        : param min_value (int)                     : The minimum value
        : param max_value (int)                     : The maximum value

        : return (Symbolic Variable)                : The symbolic variable; return -1 if block on a loop
        """
        LOGGER.info("[+] Function symbolized_register_input")

        # Make sure last_call_address is not empty
        if last_call_instruction:
            last_call_address = last_call_instruction.getAddress()
        else:
            last_call_address = 0x0

        LOGGER.info("last callInstruction : %s", last_call_instruction)
        # check if we need to change inputs. Otherwise keep default
        if is_input_needed is False:
            # check if we are not in libc_main
            if last_call_instruction:
                LOGGER.info("Loop number %d", loop_round)

                if loop_round <= 1:
                    LOGGER.debug("Not in a loop")
                else:
                    # if inputs come from fuzzing, might be a lot more than 100. what if reading a file ? check if input come from fuzzing ? if index from fuzzing is not a the end maybe reset index ?
                    if loop_round > 1000:
                        LOGGER.info("[-] BLOCKED ON A LOOP")
                        return -1
                    if self.dst_path[-1]['taken_addr'] == 0x0:
                        newIn = self._get_new_input(ctx)
            else:
                loop_round = 0

            inputs = self.get_register_input(last_call_address, loop_round, inputs)

            print colored("Inputs!!", 'green', attrs=['reverse', 'blink'])
            LOGGER.info("inputs to send : 0x%08x at call Instruction : %08x, dst_path : 0x%08x", inputs, last_call_address, self.dst_path[-1].get('taken_addr', 0x0))
            # pause()

        # Concretize and symbolized register
        ctx.setConcreteRegisterValue(register, inputs)
        ret_value = ctx.convertRegisterToSymbolicVariable(register)
        json_comment = json.dumps(dict({'base_addr': base_addr, 'last_call_address': last_call_address, 'loop_round': loop_round}))
        ret_value.setComment(json_comment)
        # add a constraints on symbolic variable
        if min_value is not None and max_value is not None:
            self._add_sym_vars_constraint(ctx, last_call_address, ret_value, min_value, max_value)
        return ret_value

    def symbolized_memory_input(self, name, ctx, base_addr, inputs, last_call_instruction, loop_round, min_value, max_value, disable_loop):
        """ Callback function. Function called by the Tracer if it's possible to symbolized memory

        : param name (str)                          : The function name
        : param base_addr (int)                     : The pointer address where inputs is stored in memory
        : param ctx (TritonContext)                 : The triton context
        : param inputs (str)                        : The concrete value
        : param last_call_instruction (Instruction) : The current function address
        : param loop_round (int)                    : How many time this function has been called during this lap
        : param min_value (int)                     : The minimum value
        : param max_value (int)                     : The maximum value
        : param disable_loop (bool)                 : Flag

        : return (int)                              : The source string len; return -1 if blocked on a loop
        """

        LOGGER.info("[+] Function symbolized_memory_input")
        LOGGER.info("last callInstruction : %s", last_call_instruction)
        # check if we are not in libc_main
        if disable_loop is False:
            LOGGER.info("Loop number %d", loop_round)
            if loop_round <= 1:
                LOGGER.debug("Not in a loop")
            else:
                if loop_round > 10:
                    return -1
                elif self.dst_path[-1]['taken_addr'] == 0x0:
                    newIn = self._get_new_input(ctx)
        else:
            loop_round = 0

        tmp = self.get_memory_input(last_call_instruction.getAddress(), base_addr, loop_round)
        if tmp:
            inputs = unordlist(tmp)

        print colored("Inputs!!", 'green', attrs=['reverse', 'blink'])
        LOGGER.info("inputs to send : %s at address : %08x, dst_path : 0x%08x", repr(inputs), base_addr, self.dst_path[-1].get('taken_addr', 0x0))
        inputs += "\x00"
        # pause()

        for i in range(len(inputs)):
            ctx.setConcreteMemoryValue(MemoryAccess(base_addr + i, CPUSIZE.BYTE), ord(inputs[i]))
            sym_var = ctx.convertMemoryToSymbolicVariable(MemoryAccess(base_addr + i, CPUSIZE.BYTE))
            json_comment = json.dumps(dict({'base_addr': base_addr, 'last_call_address': last_call_instruction.getAddress(), 'loop_round': loop_round, 'from_memory': False}))
            sym_var.setComment(json_comment)
            LOGGER.debug("At addr : 0x%08x, input : %c", base_addr+i, inputs[i])
        return len(inputs)

    def get_instruction(self, inst, taken_addr, untaken_addr):
        """ Callback function. Function called by the Tracer for each instruction

        : param inst (Instruction) : Instruction executed
        : param taken_addr (int)   : Taken branch address if the instruction is a branch
        : param untaken_addr (int) : Untaken branch address if the instruction is a branch

        : return (int)             : Return 0
        """

        LOGGER.debug("[+] get_instruction Callback")
        # If the destination path is reach, update
        if inst.getAddress() == self.dst_path[-1].get('taken_addr', 0x0):
            self.show_exploration()
            print colored('Reach !', 'red', attrs=['reverse', 'blink'])
            LOGGER.info("[+] Destination path 0x%08x reach", self.dst_path[-1].get('taken_addr'))
            lastPath = self.dst_path[-1].get('taken_addr', 0x0)
            try:
                self.exploration_memory[lastPath].update({'is_taken': True, 'fuzz': False})
            except:
                pdb.set_trace()
                LOGGER.info("[-] exploration_memory['is_taken'] unavailable")
            try:
                self.exploration_registers[lastPath].update({'is_taken': True, 'fuzz': False})
            except KeyError:
                LOGGER.info("[-] exploration_registers['is_taken'] unavailable")
            self.dst_path.append({'taken_addr': 0x0, 'vars': {}})
            # pause()

        # get and save untaken branch for later fuzzing
        # Notes : add to fuzzer queue only if we are at the same level function ?
        if inst.isBranch() is True:
            if self.dst_path[-1]['taken_addr'] == 0:
                try:
                    dst_addr = self.dst_path[-2]['taken_addr']
                except IndexError:
                    dst_addr = 0
            else:
                dst_addr = self.dst_path[-1]['taken_addr']

            if inst.isConditionTaken() is True:
                LOGGER.debug("Condition Taken : 0x%08x", taken_addr)
                self.untaken_branch.setdefault(untaken_addr, dst_addr)
                self.taken_branch.setdefault(taken_addr, dst_addr)
                # should add taken branch to exploration_memory and exploration_registers ?
                if not self.exploration_memory.has_key(taken_addr):
                    self.exploration_memory.setdefault(taken_addr, dict()).update({'is_taken': True, 'unreachable': False, 'fuzz': False, 'copy_from': dst_addr, 'loop_round': None})
                # useless ? because a program start always by libc_main_handler ? this is used because we dont want a models to an address we already have reach
                # if not self.exploration_registers.has_key(taken_addr):
                #     self.exploration_registers.setdefault(taken_addr, dict()).update({'is_taken':True, 'unreachable':False, 'fuzz':False, 'copy_from':dst_addr, 'loop':None, 'loop_round':None})
            else:
                LOGGER.debug("Condition no taken : 0x%08x", untaken_addr)
                self.untaken_branch.setdefault(taken_addr, dst_addr)
                self.taken_branch.setdefault(untaken_addr, dst_addr)
                # should add taken branch to exploration_memory and exploration_registers ? Avoid copying wrong data from previousinput in _get_new_input when destinaion has already been reach (strlen ex 10.c)
                if not self.exploration_memory.has_key(untaken_addr):
                    self.exploration_memory.setdefault(untaken_addr, dict()).update({'is_taken': True, 'unreachable': False, 'fuzz': False, 'copy_from': dst_addr, 'loop_round': None})
                # Useless ?
                # if not self.exploration_registers.has_key(untaken_addr):
                #     self.exploration_registers.setdefault(untaken_addr, dict()).update({'is_taken':True, 'unreachable':False, 'fuzz':False, 'copy_from':dst_addr, 'loop_round':None})

        return 0

    def end(self, ctx, lap, is_loop):
        """ Callback function.
        Function called by the Tracer at the program ending

        :param ctx (TritonContext) : The triton context
        :param lap (int)           : The lap number (integer)
        :param is_loop (dict)      : The number of time each function has been called during this lap. dict({<function addr>: counter})
        """

        LOGGER.info("[+] Program end")
        # Count how many successive time we are trying to reach an address
        dst_address = self.dst_path[-1]['taken_addr']
        if dst_address != 0:
            self.dst_path_counter.update({dst_address})
            if self.dst_path_counter[dst_address] >= 3:
                LOGGER.info("Destination Path Try Number : %d", self.dst_path_counter)
                pdb.set_trace()
                try:
                    self.exploration_memory[dst_address].update({'unreachable': True})
                except:
                    pdb.set_trace()
                try:
                    self.exploration_registers[dst_address].update({'unreachable': True})
                except:
                    pdb.set_trace()
                self.dst_path.append({'taken_addr': 0x0, 'vars': {}})

        self._get_new_input(ctx)

        if self.is_all_path_reach() is True:
            self.fuzz_is_needed = True  # need to fuzz ?
        else:
            self.fuzz_is_needed = False

        print colored("Number of destination : " + str(len(self.exploration_memory.keys())), 'yellow', attrs=['reverse', 'blink'])
        LOGGER.info("Number of destination : %d", len(self.exploration_memory.keys()))
        print colored("Untaken Branch : " + str(map(hex, self.get_untaken_branch())), 'yellow', attrs=['reverse', 'blink'])
        LOGGER.info("Untaken Branch : %s", map(hex, self.get_untaken_branch()))

        # Clear the path constraints to be clean at the next execution.
        ctx.clearPathConstraints()

    # -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- Constraints -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
    def _add_sym_vars_constraint(self, ctx, last_call_address, sym_var, min_value, max_value):
        """ Add a constraint on a symbolic variable. (i.e, strlen return value between 0 and 10)

        :param ctx (TritonContext)        : The triton context
        :param last_call_address (int)    : The current function address
        :param sym_var (SymbolicVariable) : The symbolic variable to worked on
        :param min_value (int)            : The minimum constraint value
        :param max_value (int)            : The maximum constraint value
        """

        LOGGER.info("[+] function _add_sym_vars_constraint")
        symVarName = sym_var.getName()
        # pdb.set_trace()

        # need to check if min_value and max_value are greater than original
        if self.sym_vars_constraint.has_key(last_call_address):
            if min_value < self.sym_vars_constraint[last_call_address]['min']:
                self.sym_vars_constraint[last_call_address]['min'] = min_value
            else:
                min_value = self.sym_vars_constraint[last_call_address]['min']
            # need try ?
            if max_value > self.sym_vars_constraint[last_call_address]['max']:
                self.sym_vars_constraint[last_call_address]['max'] = max_value
            else:
                max_value = self.sym_vars_constraint[last_call_address]['max']
        else:
            self.sym_vars_constraint.update({last_call_address: {'min': min_value, 'max': max_value}})

        # create astNode with constraint
        astCtx = ctx.getAstContext()
        node0 = astCtx.variable(sym_var)
        node1 = astCtx.bvuge(node0, astCtx.bv(min_value, 64))
        node2 = astCtx.bvule(node0, astCtx.bv(max_value, 64))
        node3 = astCtx.land([node1, node2])

        self.added_constraint_node.update({symVarName: node3})

    # -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- Display informations -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
    def show_exploration(self, specific_branch=None):
        """Display the whole database or a specific destination address

        :param specific_branch (int): Destination addr to display
        """

        LOGGER.info("[+] Function show Exploration")
        if specific_branch:
            if self.exploration_memory[specific_branch]['fuzz'] is False:
                print colored("dst_addr : " + hex(specific_branch) + ", is_taken : " + str(self.exploration_memory[specific_branch]['is_taken']) + ", loop_round : " + str(self.exploration_memory[specific_branch]['loop_round']) + ", unreach : " + str(self.exploration_memory[specific_branch]['unreachable']) + ", fuzz : False", 'blue', attrs=['reverse', 'blink'])
                for k, v in self.exploration_memory[specific_branch]['call_addr'].items():
                    print "\tcallAddr : ", hex(k)
                    for ke, va in v['base_addr'].items():
                        print "\t\tbase_addr", hex(ke)
                        for key, val in va['sym_vars_addr'].items():
                            try:
                                print "\t\t\tsym_var_address : ", hex(key), "values : ", chr(val.get('values')[0])
                            except Exception as e:
                                pdb.set_trace()
                                print val.get('values')
            else:
                print colored("dst_addr : " + hex(specific_branch) + ", is_taken : " + str(self.exploration_memory[specific_branch]['is_taken']) + ", unreach : " + str(self.exploration_memory[specific_branch]['unreachable']) + ", fuzz : True", 'blue', attrs=['reverse', 'blink'])
        else:
            for k, v in sorted(self.exploration_memory.items()):
                if v['fuzz'] is True:
                    print colored("dst_addr : " + hex(k) + ", is_taken : " + str(v['is_taken']) + ", unreach : " + str(v['unreachable']) + ", fuzz : True", 'blue', attrs=['reverse', 'blink'])
                    print "\tvalues : ", repr(v['fuzz_inputs']['inputs'])
                elif v['copy_from'] is False:
                    print colored("dst_addr : " + hex(k) + ", is_taken : " + str(v['is_taken']) + ", unreach : " + str(v['unreachable']) + ", fuzz : False", 'blue', attrs=['reverse', 'blink'])
                    for ke, va in v['call_addr'].items():
                        print "\tcallAddr : ", hex(ke)
                        for key, val in va['base_addr'].items():
                            print "\t\tbase_addr", hex(key)
                            for keys, vals in val['sym_vars_addr'].items():
                                try:
                                    print "\t\t\tsymvarAddress : ", hex(keys), "values : ", chr(list(vals.get('values').values())[0])
                                    # print "\t\t\tsymvarAddress : ",hex(keys), "values : ", vals.get('values')
                                except Exception as e:
                                    pdb.set_trace()
                                    print val.get('values')
                else:
                    print colored("dst_addr : " + hex(k) + ", is_taken : " + str(v['is_taken']) + ", unreach : " + str(v['unreachable']) + ", fuzz : False" + ", copy_from : " + hex(v['copy_from']), 'blue', attrs=['reverse', 'blink'])

        # Registers output
        for key, val in reversed(sorted(self.exploration_registers.items())):
            if val['fuzz'] is True:
                print colored(", fuzz : True", 'magenta', attrs=['reverse', 'blink'])
            elif val['copy_from'] is False:
                print colored("dst_addr : " + hex(key) + ", is_taken : " + str(val['is_taken']) + ", unreach : " + str(val['unreachable']) + ", fuzz : False", 'magenta', attrs=['reverse', 'blink'])
                for ke, va in sorted(val['call_addr'].items()):
                    print "\tcallAddr : ", hex(ke)
                    for k, v in sorted(va['loop_round'].items()):
                        print "\t\tloopRound : ", hex(k), ", value : ", hex(v['values'])
            else:
                print colored("dst_addr : " + hex(key) + ", is_taken : " + str(val['is_taken']) + ", unreach : " + str(val['unreachable']) + ", fuzz : False" + ", copy_from : " + hex(val['copy_from']), 'magenta', attrs=['reverse', 'blink'])

    def show_dest_path(self):
        for i in self.dst_path:
            print hex(i.get('taken_addr'))

    def _resolve_last_path_constraint(self, ctx):
        ast = ctx.getAstContext()
        previous_constraints = ast.equal(ast.bvtrue(), ast.bvtrue())
        branches = ctx.getPathConstraints()[-1].getBranchConstraints()
        model1 = ctx.getModel(ast.land([previous_constraints, branches[0]['constraint']]))
        model2 = ctx.getModel(ast.land([previous_constraints, branches[1]['constraint']]))
        print model1.values()[0]
        print model2.values()[0]

    def get_untaken_branch(self):
        """ Return the difference between untaken address and taken address
            Return real and unique untaken branch address
        """
        return set(self.untaken_branch.keys()) - set(self.taken_branch.keys())

    def is_all_path_reach(self):
        for k, v in self.exploration_memory.items():
            if v['is_taken'] is False:
                return False  # Some path are not reach
        else:
            return True

    def save_exploration_to_file(self, dst_addr):
        """Save exploration_memory dictionary to a file in json format"""
        with open("fuzzQueue.txt", "w") as f:
            f.write(json.dumps(self.exploration_memory.get(dst_addr, 0x0)))

