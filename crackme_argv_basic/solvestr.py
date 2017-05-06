#!/usr/bin/python
# python -W ignore solve.py

import angr, monkeyhex, claripy

# load the file
project = angr.Project('crackmestr')

# print info from the binary
print "[i] Architecture    : "+str(project.arch)
print "[i] Entry point     : "+hex(project.entry)
print "[i] Loader          : "+str(project.loader)
print "[i] Main bin object : "+str(project.loader.main_bin)

# the binary is static and stripped
# to avoid bad behavior and longer analyze
# create a new symbolic state, start at check function
state = project.factory.blank_state(addr=0x080488e0)

# Since I started at check()
# I need to manually set the user argv1, and place it somewhere (heap)
# I don't know the password len so I symbolize 100 bits
location = 0x080eb0a0	# found with gdb
state.memory.store(location, state.se.BVS("answer", 100*8))

# I place my user input on the stack
# This is the arg of the call check()
state.stack_push(location)

# start the symbolic execution, create a PathGroup
group = project.factory.path_group(state)

# explore to the "well done" state (0x080484b3, found with IDA)
# avoiding the "get out" state (0x080484c5, found with IDA).
group.explore(find=0x080488F4, avoid=0x08048906)

# select the first solution
found = group.found[0]

# ask to the symbolic solver to get the value store at the location (heap)
solution = found.state.se.any_str(found.state.memory.load(location, 32))

# get only the string
solution = solution[:solution.find("\x00")]
print "[!] Found : '"+solution+"'"
