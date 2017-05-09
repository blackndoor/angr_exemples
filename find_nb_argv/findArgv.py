import angr,claripy,simuvex
import sys
import logging

# avoid WARNING from simuvex
logging.getLogger("simuvex").setLevel(logging.CRITICAL)

# grab function names and addr
def getFuncAddress( minAddr, maxAddr ):
	found = {
				func.name:addr for addr,func in cfg.kb.functions.iteritems()
				if addr >= minAddr and addr <= maxAddr
			}
	return found

# load the binary, don't load extra libs to save time/memory from state explosion
project = angr.Project("strcpy", load_options={'auto_load_libs':False})

# print info from the binary
print "[i] Architecture    : "+str(project.arch)
print "[i] Entry point     : "+hex(project.entry)
print "[i] Loader          : "+str(project.loader)
print "[i] Main bin object : "+str(project.loader.main_bin)

# min/max main_bin addr
# bad bad bad, but I haven't found a way to get the main_bin min and max
minAddr = int(str(project.loader.main_bin).split('[')[1].split(':')[0],16)
maxAddr = int(str(project.loader.main_bin).split(':')[1].split(']')[0],16)

# Set up CFG so we can grab function addresses from symbols.
# I set the fail_fast option to True to minimize how long this process takes.
cfg = project.analyses.CFG(fail_fast=True)

# collect symbol in project.loader.main_bin
print "\n[+] Symbols found",
symbols = getFuncAddress(minAddr,maxAddr)
print "["+str(len(symbols))+"]\n"

# Create the list of command-line arguments
argv = [project.filename]						# argv[0]

# Initializes an entry state starting at the address of the program entry point
# simply pass it the same kind of argument vector that would be passed to the
# program, in execv() for example
state = project.factory.entry_state(args=argv)

# Create a new path group from the entry state
path_group = project.factory.path_group(state)

# symboles used with no arg
symboleUsed = 0

# count the number of symbole used
def countSymbole(p):
	global symboleUsed
	# check if we hit a collected symbol
	if p.state.ip.args[0] in symbols.values():
		symboleUsed+=1
		return False
	return False

# we tell the explore function to find a path that satisfies our countSymbole method
# here, nothing satisfy the method as false is always return
print "[+] Collect the number of symbol used with no argvX\n"
path_group.explore(find=countSymbole)

# store the symbols used with 0 argv
symboleUsedNoArg = symboleUsed

# var needed
nbargFound   = False
nbargNeed    = 0

# max argNeed, adpat acordingly
nbargNeedMax = 4

print "[+] Number of argv needed:",
sys.stdout.flush()

while nbargNeed < nbargNeedMax:
	nbargNeed+=1
	# Create the list of command-line arguments
	argv = [project.filename]						# argv[0]
	for nb in range(nbargNeed):
		nb+=1
		argv.append("AAAA")

	# Initializes an entry state starting at the address of the program entry point
	state = project.factory.entry_state(args=argv)
	
	# Create a new path group from the entry state
	path_group = project.factory.path_group(state)

	# symboles used with nbargNeed
	symboleUsed = 0

	# count the number of symbole used
	def countSymbole(p):
		global symboleUsed
		# check if we hit a collected symbol
		if p.state.ip.args[0] in symbols.values():
			symboleUsed+=1
			return False
		return False

	# we tell the explore function to find a path that satisfies our countSymbole method
	# again, nothing satisfy the method as false is always return
	path_group.explore(find=countSymbole)

	# if the number of symbol used with ngArg is > something new happen
	# this only works if the c code is:
	#
	#	int main() {
	#		if(argc<x)
	#			exit();
	#		code...
	#	}
	#
	# it fails if c code is:
	#
	#	int main() {
	#		if(argc<2)
	#			exit();
	#		doSomethingWithArgv[1]...
	#		if(argc<3)
	#			exit();
	#		doSomethingWithArgv[2]...
	#		etc...
	#	}
	if symboleUsed > symboleUsedNoArg:
		nbargFound = True
		break

if nbargFound:
	print str(nbargNeed)
else:
	# in case there is no argvX or more than 4, the number of symbol
	# with nbArg is always equal
	nbargNeed=0
	print str(nbargNeed)+" (or more than 4)"

