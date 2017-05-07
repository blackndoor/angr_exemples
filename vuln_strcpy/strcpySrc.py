import angr,claripy,simuvex
import sys

# helper function to grab function names from resolved symbols
# return the addr of the function and the testing string
def getFuncAddress( funcName, plt=None ):
	found = [
				addr for addr,func in cfg.kb.functions.iteritems()
				if funcName == func.name and (plt is None or func.is_plt == plt)
			]
	if len( found ) > 0:
		print "    Found : "+hex(found[0])
		return found[0],"test_string"
	else:
		print "    No address found.."
		sys.exit()

# load the binary, don't load extra libs to save time/memory from state explosion
project = angr.Project("strcpy", load_options={'auto_load_libs':False})

# print info from the binary
print "[i] Architecture    : "+str(project.arch)
print "[i] Entry point     : "+hex(project.entry)
print "[i] Loader          : "+str(project.loader)
print "[i] Main bin object : "+str(project.loader.main_bin)

# Set up CFG so we can grab function addresses from symbols.
# I set the fail_fast option to True to minimize how long this process takes.
cfg = project.analyses.CFG(fail_fast=True)

# Get addresses of our functions to find
name = 'plt.strcpy'
print "\n[i] Searching addr of "+name
addrStrcpy, testing = getFuncAddress(name, plt=True)

# Create the list of command-line arguments
argv = [project.filename]						# argv[0]
# Add testing string
argv.append(testing)							#argv[1]

# Initializes an entry state starting at the address of the program entry point
# simply pass it the same kind of argument vector that would be passed to the
# program, in execv() for example
state = project.factory.entry_state(args=argv)

# Create a new path group from the entry state
path_group = project.factory.path_group(state)

# we want to find a path to strcpy ONLY where we have control of the source buffer
def check(p):
	print "[i] Check if strcpy"
	# check first p.state.ip.args[0] (the current instruction pointer) to make sure
	# we're at our intended path destination
	if (p.state.ip.args[0] == addrStrcpy):
		print "    strcpy source control: ",
		# looking with gdb, I've found that the pointer to the
		# source buffer and the destination buffer given to strcpy() are on the stack
		# 0000| 0xffffce2c --> 0x8048538 (<main+109>:	add    esp,0x10)	retAddr
		# 0004| 0xffffce30 --> 0xffffce62 --> 0x0 							destAddr
		# 0008| 0xffffce34 --> 0xffffd120 ("test_string")					srcAddr
		# we pop the 3 addr
		retAddr  = p.state.stack_pop()
		destAddr = p.state.stack_pop()
		srcAddr  = p.state.stack_pop()
		# we get the content of the srcAddr
		checkSrc = p.state.se.any_str(p.state.memory.load(srcAddr, len(argv[1])))
		# check if the content of the srcAddr is the one given as argv1
		if argv[1] == checkSrc:
			# Ok we control the source buffer given to strcpy
			print "yes"
			return True
		else:
			print "no"
			return False
	else:
		return False

# we tell the explore function to find a path that satisfies our check method
path_group.explore(find=check)

