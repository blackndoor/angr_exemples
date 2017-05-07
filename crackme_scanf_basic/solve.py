#!/usr/bin/python
# python -W ignore solve.py

import angr, monkeyhex, claripy

# load the file
project = angr.Project('crackme')

# print info from the binary
print "[i] Architecture    : "+str(project.arch)
print "[i] Entry point     : "+hex(project.entry)
print "[i] Loader          : "+str(project.loader)
print "[i] Main bin object : "+str(project.loader.main_bin)

# create a new symbolic state, start at call check
state = project.factory.blank_state(addr=0x080485a2)

# Since I started execution partway through main(), after the user read
# I need to manually set the user input, and place it somewhere BSS
# len of the password is < 32
location = 0x0804a070
state.memory.store(location, state.se.BVS("answer", 32*8))

# I need to place my user input on the stack
# This is the arg of the call check()
state.stack_push(location)

# start the symbolic execution, create a PathGroup
group = project.factory.path_group(state)

# explore to the "well done" state (0x080485b6)
# avoiding the "get out" state (0x080485c8).
group.explore(find=0x080485b6, avoid=0x080485c8)

# select the first solution
found = group.found[0]

# ask to the symbolic solver to get the value store at the location BSS
solution = found.state.se.any_str(found.state.memory.load(location, 32))

# get only the string
solution = solution[:solution.find("\x00")]
print "[!] Found : '"+solution+"'"