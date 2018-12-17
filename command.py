#!/usr/bin/env python2

from tracer import Tracer
from exploration import Exploration
from triton import TritonContext, ARCH, MODE, AST_REPRESENTATION
from fuzz import Fuzz
import multiprocessing
import Queue
import copy
import logging

LOGGER = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(process)s - %(filename)s -  %(lineno)s - %(levelname)s]  %(message)s"))
LOGGER.addHandler(console_handler)
LOGGER.setLevel(logging.INFO)

program_name = './binary_test/testFuzz10'

def send_to_fuzz(entrypoint, exploration_memory, exploration_registers, from_memory_addr, dst_addr, q):
    """send a request to the fuzzer

    :param dst_addr (int): The destination address you wishe to reach
    """

    fuzz = Fuzz(exploration_memory, exploration_registers, from_memory_addr, dst_addr, q)

    fuzzer = Tracer(program_name, False)

    # set triton parameter
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx.enableMode(MODE.ALIGNED_MEMORY, True)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)

    fuzzer.tracer_init(ctx)

    # add fuzz callback
    fuzzer.add_start_callback(fuzz.start)
    fuzzer.add_instruction_callback(fuzz.get_instruction)
    fuzzer.add_end_callback(fuzz.end)
    fuzzer.add_memory_callback(fuzz.fuzz_memory)
    fuzzer.add_register_callback(fuzz.fuzz_register)

    p = multiprocessing.Process(target=fuzzer.start, args=(ctx, 30, entrypoint))
    # return [p,ctx,fuzzer, exploration_memory]
    return p


def main():
    entrypoint = 0x401094
    fuzzed_address = set()
    queue = multiprocessing.Queue()
    process = list()

    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx.enableMode(MODE.ALIGNED_MEMORY, True)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)

    exploration = Exploration()
    tracer = Tracer(program_name, True)
    tracer.tracer_init(ctx)

    # Sets callbacks
    tracer.add_start_callback(exploration.start)
    tracer.add_instruction_callback(exploration.get_instruction)
    tracer.add_end_callback(exploration.end)
    tracer.add_memory_callback(exploration.symbolized_memory_input)
    tracer.add_register_callback(exploration.symbolized_register_input)

    for i in range(30):
        tracer.start(ctx, 1, entrypoint)

        if exploration.fuzz_is_needed is True:
            untaken_branch = set(exploration.get_untaken_branch())
            for i in untaken_branch:
                if i not in fuzzed_address:
                    if exploration.untaken_branch[i] != 0:
                        process.append(send_to_fuzz(entrypoint, copy.deepcopy(exploration.exploration_memory),
                                                    copy.deepcopy(exploration.exploration_registers),
                                                    copy.copy(exploration.untaken_branch[i]), i, queue))
                        process[-1].start()
                        process[-1].join()

                    fuzzed_address.add(i)

            try:
                new_inputs = queue.get(block=True, timeout=5)
                exploration.add_fuzz_inputs(new_inputs[0], new_inputs[1])
            except Queue.Empty:
                print(map(hex, exploration.get_untaken_branch()))
                print("Can't find more branch")
                break

    exploration.show_exploration()


if __name__ == '__main__':
    main()
