import angr
import claripy
import monkeyhex
import logging
from dataclasses import dataclass


class SolverError(Exception):
    pass


@dataclass
class SymByteTainted:
    taint_offset: int
    sym_byte: claripy.BVS

    def __hash__(self):
        return self.taint_offset


root = logging.getLogger()
root.setLevel(logging.INFO)

angr_logger = logging.getLogger('pyvex.expr')
angr_logger.setLevel(logging.WARNING)
angr_logger = logging.getLogger('angr.project')
angr_logger.setLevel(logging.WARNING)
angr_logger = logging.getLogger('cle.loader')
angr_logger.setLevel(logging.WARNING)
angr_logger = logging.getLogger('angr.sim_manager')
angr_logger.setLevel(logging.WARNING)
angr_logger = logging.getLogger('angr.engines.engine')
angr_logger.setLevel(logging.WARNING)

PROGRAM = 'drtaint_marker_app'

sim_opts = {
    angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
}

project = None
state = None
max_length = 0


def is_initialized():
    return project is not None and state is not None


def load_binary(load_opts, target_addr, ctx, length):

    global project, state, max_length

    # Load program to be analyzed and setup its context
    project = angr.Project('bin/' + PROGRAM,
                           main_opts=load_opts[PROGRAM],
                           lib_opts=load_opts,
                           use_sim_procedures=False)

    max_length = length
    state = project.factory.blank_state(
        addr=target_addr, add_options=sim_opts)

    regs = state.regs
    regs.r0 = ctx['r0']
    regs.r1 = ctx['r1']
    regs.r2 = ctx['r2']
    regs.r3 = ctx['r3']
    regs.r4 = ctx['r4']
    regs.r5 = ctx['r5']
    regs.r6 = ctx['r6']
    regs.r7 = ctx['r7']
    regs.r8 = ctx['r8']
    regs.r9 = ctx['r9']
    regs.r10 = ctx['r10']
    regs.r11 = ctx['r11']
    regs.r12 = ctx['r12']
    regs.sp = ctx['sp']
    regs.lr = ctx['lr']
    regs.flags = ctx['flags']


def find_branches(cmp_addr, max_steps=5):

    global project

    # Find 2 possible branches cmp leads to
    state_cmp = project.factory.blank_state(
        addr=cmp_addr, add_options=sim_opts)

    steps = 0
    simulation = project.factory.simgr(state_cmp)

    while steps < max_steps and len(simulation.active) != 2:
        simulation.step(num_inst=1)
        steps += 1

    if len(simulation.active) != 2:
        raise SolverError(f'Unable to find branches from 0x%08x' % cmp_addr)

    branch1 = simulation.active[0].addr
    branch2 = simulation.active[1].addr
    return branch1, branch2

I = 0

def solve_path_constraints(buf, buf_addr, taint, taint_offs, cmp_addr):

    global project, state, max_length, I

    I+=1

    # Set buffer concrete value
    buf_len = len(buf)
    content = claripy.BVV(buf, buf_len * 8)
    state.memory.store(buf_addr, content)

    # Process tainted bytes
    tainted = [
        int(taint[0:2], 16),
        int(taint[2:4], 16),
        int(taint[4:6], 16),
        int(taint[6:8], 16),
    ]

    # Get unique bytes and remove those
    # have '0' value (not tainted)
    tainted = set(tainted)
    tainted.discard(0)

    # Set buffer symbolic values
    sym_bytes_tainted = set()
    for offs in tainted:
        sym_byte = claripy.BVS('t', 8)
        global_offs = offs + taint_offs - 1
        state.memory.store(buf_addr + global_offs, sym_byte)
        sym_bytes_tainted.add(SymByteTainted(global_offs, sym_byte))

    # Launch simulation and explore paths
    # from the beginning of target function
    simulation = project.factory.simgr(state)
    branch1, branch2 = find_branches(cmp_addr)

    i = 0
    while True:

        simulation.explore(find=[branch1, branch2])
        cnt_found = len(simulation.found)

        if cnt_found == 0 or i > max_length:
            info = '(cmp_addr=0x%08x, taint=0x%s)' % (cmp_addr, taint)
            raise SolverError('Failed to solve path constraints ' + info)
        if cnt_found == 2:
            break

        assert cnt_found == 1
        simulation.move(from_stash='found', to_stash='active')
        simulation.step()

        i += 1

    # Retrieve solutions
    res_branch1 = bytearray(buf[:])
    res_branch2 = bytearray(buf[:])

    for sbt in sym_bytes_tainted:

        solution_state = simulation.found[0]
        res_byte = solution_state.solver.eval(sbt.sym_byte, cast_to=bytes)
        res_branch1[sbt.taint_offset] = int(res_byte[0])

        solution_state = simulation.found[1]
        res_byte = solution_state.solver.eval(sbt.sym_byte, cast_to=bytes)
        res_branch2[sbt.taint_offset] = int(res_byte[0])

    return res_branch1, res_branch2
