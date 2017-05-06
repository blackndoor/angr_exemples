#!/usr/bin/python
# python -W ignore solve.py

import angr, monkeyhex, claripy

# load the file
project = angr.Project('CrackMe')

# print info from the binary
print "[i] Architecture    : "+str(project.arch)
print "[i] Entry point     : "+hex(project.entry)
print "[i] Loader          : "+str(project.loader)
print "[i] Main bin object : "+str(project.loader.main_bin)

# set the argv1
# as I don't know the len, I symbolize 20 bits
argv1 = angr.claripy.BVS("argv1", 20*8)

# create a new symbolic state
state = project.factory.entry_state(args=["./CrackMe",argv1])

# the password is printchar
for i in xrange(20):
	state.add_constraints(argv1.get_byte(i) != '\x00')
	state.add_constraints(argv1.get_byte(i) >= ' ')
	state.add_constraints(argv1.get_byte(i) <= '~')

# create a new symbolic path
path = project.factory.path(state)

# start the symbolic execution, create a PathGroup
group = project.factory.path_group(state)

# explore to the "well done" state (0x40095C)
# avoiding the "get out" state (0x40070c, 0x40071f, 0x40073c, 0x400755, 0x400774, 0x400793, 0x4007af, 0x4007d3, 0x40081b, 0x400853, 0x400878, 0x4008b9,  0x400952)
group.explore(find=0x40095C, avoid=(0x40070c, 0x40071f, 0x40073c, 0x400755, 0x400774, 0x400793, 0x4007af, 0x4007d3, 0x40081b, 0x400853, 0x400878, 0x4008b9,  0x400952))

# select the first solution
found = group.found[0]

# ask to the symbolic solver to get the value of argv1 in the reached state
solution = found.state.se.any_str(argv1)

# get only the string
solution = solution[:solution.find("@")]
print "[!] Found : '"+solution+"'"
