import angr
import claripy
import monkeyhex

FILEPATH = 'drtaint_marker_app'

sim_opts = {
    angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
}

state_info = {
    'load_addr': 'B2E17000',
    'target_addr': 'B2E17760',
    'buffer_addr': 'BEBD3530',
    'ctx.r0': 'BEBD3530',
    'ctx.r1': '00007974',
    'ctx.r2': '00000000',
    'ctx.r3': 'BEBD3530',
    'ctx.r4': 'BEBD3558',
    'ctx.r5': '00000000',
    'ctx.r6': '00000000',
    'ctx.r7': '00000000',
    'ctx.r8': '00000000',
    'ctx.r9': '00000000',
    'ctx.r10': 'B2E28000',
    'ctx.r11': 'BEBD353C',
    'ctx.r12': 'BEBD35C0',
    'ctx.sp': 'BEBD3528',
    'ctx.lr': 'B2E17828',
    'ctx.flags': '60070010',
}

solve_info = {
    'cmp_addr': 'B2E17778',
    'taint': '00000001',
    'buf': 'qwerty',
}

load_addr = int(state_info['load_addr'], 16)
proj = angr.Project('drtaint_marker_app',
                    main_opts={'base_addr': load_addr},
                    auto_load_libs=False)

# Find 2 possible branches cmp leads to
cmp_addr = int(solve_info['cmp_addr'],16)
state_cmp = proj.factory.blank_state(addr=cmp_addr, add_options=sim_opts)
simulation = proj.factory.simgr(state_cmp)
simulation.step()

assert len(simulation.active) == 2
branch1 = simulation.active[0].addr
branch2 = simulation.active[1].addr

# Setup context and solve path constrains
# corresponding found branches
target_addr = int(state_info['target_addr'], 16)
state = proj.factory.blank_state(addr=target_addr)

regs = state.regs
regs.r0 = int(state_info['ctx.r0'], 16)
regs.r1 = int(state_info['ctx.r1'], 16)
regs.r2 = int(state_info['ctx.r2'], 16)
regs.r3 = int(state_info['ctx.r3'], 16)
regs.r4 = int(state_info['ctx.r4'], 16)
regs.r5 = int(state_info['ctx.r5'], 16)
regs.r6 = int(state_info['ctx.r6'], 16)
regs.r7 = int(state_info['ctx.r7'], 16)
regs.r8 = int(state_info['ctx.r8'], 16)
regs.r9 = int(state_info['ctx.r9'], 16)
regs.r10 = int(state_info['ctx.r10'], 16)
regs.r11 = int(state_info['ctx.r11'], 16)
regs.r12 = int(state_info['ctx.r12'], 16)
regs.sp = int(state_info['ctx.sp'], 16)
regs.lr = int(state_info['ctx.lr'], 16)
regs.flags = int(state_info['ctx.flags'], 16)

# Set buffer concrete value
buf = solve_info['buf']
buffer_addr = int(state_info['buffer_addr'], 16)
content = claripy.BVV(buf.encode(), len(buf) * 8)
state.memory.store(buffer_addr, content)

# Process tainted bytes
tainted = [
    int(solve_info['taint'][0:2],16),
    int(solve_info['taint'][2:4],16),
    int(solve_info['taint'][4:6],16),
    int(solve_info['taint'][6:8],16),
]

# Get unique bytes and remove those
# have '0' value (not tainted)
tainted = set(tainted)
tainted.discard(0)

# Set buffer symbolic values
# and remember to shift left by 1
sym_bytes = []
for offs in tainted:
    sym_byte = claripy.BVS('t' + str(offs - 1), 8)
    state.memory.store(buffer_addr + offs - 1, sym_byte)
    sym_bytes.append(sym_byte)

# Launch simulation and explore paths
# from the beginning of target function
simulation = proj.factory.simgr(state)
simulation.explore(find=[branch1,branch2])

# Retrieve solutions
for sym_byte in sym_bytes:
    solution_state = simulation.found[0]
    res = solution_state.solver.eval(sym_byte, cast_to=bytes)
    print(res)

for sym_byte in sym_bytes:
    solution_state = simulation.found[1]
    res = solution_state.solver.eval(sym_byte, cast_to=bytes)
    print(res)
