import angr, simuvex

# load the file, set a base addr as the binary is PIE
project = angr.Project("crackme",load_options={'main_opts': {'custom_base_addr': 0x400000}})

# print info from the binary
print "[i] Architecture    : "+str(project.arch)
print "[i] Entry point     : "+hex(project.entry)
print "[i] Loader          : "+str(project.loader)
print "[i] Main bin object : "+str(project.loader.main_bin)

# angr didn't load the SimProcedures because the libc used is musl.
# function used
symbols = ['printf','fgets','puts','fflush','calloc','exit']
# Hook with libc.so.6
for symbol in symbols:
    project.hook_symbol(symbol,simuvex.SimProcedures['libc.so.6'][symbol])

# start the state in main, before the 0x6c6 function
# 0x7af: mov     rdi, rbx
state = project.factory.blank_state(addr=0x4007af)

# I start after the fgets, symbolize the user input
# len 32 bits
location = 0x601070
state.memory.store(location, state.se.BVS("answer", 32*8))

# place location in rbx
# 0x7af: mov rdi, rbx	=> rdi=location
state.registers.store('rbx', location)

# start the symbolic execution, create a PathGroup
group = project.factory.path_group(state)

# we want to explore until printf(sum is)
# 0x7b7 : lea rdi, format     ; "sum is %ld\n"
group.explore(find=0x4007b7)

# select the first solution
found = group.found[0]

# ask to the symbolic solver to get the value store at the location
solution = found.state.se.any_str(found.state.memory.load(location, 32))

# get only the string
solution = solution[:solution.find("\x00")]
print "[!] Found : '"+solution+"'"
