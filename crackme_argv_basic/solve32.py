#!/usr/bin/python
# python -W ignore solve.py

import angr, monkeyhex, claripy

# load the file
project = angr.Project('crackme32')

# print info from the binary
print "[i] Architecture    : "+str(project.arch)
print "[i] Entry point     : "+hex(project.entry)
print "[i] Loader          : "+str(project.loader)
print "[i] Main bin object : "+str(project.loader.main_bin)

# set the argv1
# as I don't know the len, I symbolize 100 bits
argv1 = angr.claripy.BVS("argv1", 100*8)

# create a new symbolic state
state = project.factory.path(args=["./crackme32",argv1])

# start the symbolic execution, create a PathGroup
group = project.factory.path_group(state)

# explore to the "well done" state (0x080484b3 found with IDA)
# avoiding the "get out" state (0x080484c5 found with IDA).
group.explore(find=0x080484b3, avoid=0x080484c5)

# select the first solution
found = group.found[0]

# ask to the symbolic solver to get the value of argv1 in the reached state
solution = found.state.se.any_str(argv1)

# get only the string
solution = solution[:solution.find("\x00")]
print "[!] Found : '"+solution+"'"
