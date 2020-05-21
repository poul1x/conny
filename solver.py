import angr
import claripy
import monkeyhex
import logging

root = logging.getLogger()
root.setLevel(logging.INFO)

PROGRAM = 'target'
LIBC = 'libc'

project = None
state = None

def is_initialized():
    return project is not None and state is not None

def load_binary(load_addr, libc_addr, target_addr, ctx):

    global project, state

    # Load program to be analyzed and setup its context
    project = angr.Project(PROGRAM, main_opts={'base_addr': load_addr},
                        lib_opts={LIBC : {'base_addr' : libc_addr}})

    state = project.factory.blank_state(addr=target_addr)
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

def find_branches(cmp_addr):

    global project

    sim_opts = {
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
    }

    # Find 2 possible branches cmp leads to
    state_cmp = project.factory.blank_state(addr=cmp_addr, add_options=sim_opts)
    simulation = project.factory.simgr(state_cmp)
    simulation.step()

    assert len(simulation.active) == 2
    branch1 = simulation.active[0].addr
    branch2 = simulation.active[1].addr
    return branch1, branch2

def solve_path_constraints(buf, buf_addr, taint, cmp_addr):

    global project, state

    # Set buffer concrete value
    buf_len = len(buf)
    content = claripy.BVV(buf.encode(), buf_len * 8)
    state.memory.store(buf_addr, content)

    # Process tainted bytes
    tainted = [
        int(taint[0:2],16),
        int(taint[2:4],16),
        int(taint[4:6],16),
        int(taint[6:8],16),
    ]

    # Get unique bytes and remove those
    # have '0' value (not tainted)
    tainted = set(tainted)
    tainted.discard(0)

    # Set buffer symbolic values
    # and remember to shift left by 1
    sym_bytes = []
    for offs in tainted:
        sym_byte = claripy.BVS('t', 8)
        state.memory.store(buf_addr + offs - 1, sym_byte)
        sym_bytes.append(sym_byte)

    # Launch simulation and explore paths
    # from the beginning of target function
    simulation = project.factory.simgr(state)
    simulation.explore(find=list(find_branches(cmp_addr)))

    if not simulation.found:
        return False, bytes(), bytes()

    # Retrieve solutions
    assert len(simulation.found) == 2

    res_branch1 = bytes()
    for sym_byte in sym_bytes:
        solution_state = simulation.found[0]
        res_byte = solution_state.solver.eval(sym_byte, cast_to=bytes)
        res_branch1 += res_byte

    res_branch2 = bytes()
    for sym_byte in sym_bytes:
        solution_state = simulation.found[1]
        res_byte = solution_state.solver.eval(sym_byte, cast_to=bytes)
        res_branch2 += res_byte

    return True, res_branch1, res_branch2