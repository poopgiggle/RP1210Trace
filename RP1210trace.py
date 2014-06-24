#!/usr/bin/env python

import ctypes
from pydbg import *
from pydbg.defines import *
import sys
from RP1210Call import *
import utils
import re

RP1210calls = {'RP1210_SendMessage':None,'RP1210_ReadMessage':None,'RP1210_ClientConnect':None,'RP1210_ClientDisconnect':None,'RP1210_SendCommand':None}

#Obtain list of RP1210 DLLs registered on the system
logline = re.compile('APIImplementations=(.*)$')
try:
	rp1210ini = open("C:\\Windows\\RP121032.ini")
except:
	print("Could not open RP121032.ini")
	sys.exit(-1)
liblist = []
for line in rp1210ini.readlines():
	m = re.match(logline,line)
	if m:
		liblist = m.group(1).split(",")

for i in range(len(liblist)):
	liblist[i]+=".dll"



try:
	logfile = open("trace_out_2.txt","w")
except:
	print("Count not open logfile for writing")
	sys.exit(-1)

module_name = None
dbg = pydbg()
dbg.get_debug_privileges()
getproc = dbg.func_resolve("kernel32.dll","GetProcAddress")
procname = sys.argv[1]






#Wait until the desired process starts, then attach to it
attached = False
while not attached:
	for (pid,name) in dbg.enumerate_processes():
		if procname in name:
			dbg.attach(pid)
			print("Attaching to %s, pid %d" % (name,pid))
			attached = True
			break





generic_call_queue = []
read_call_queue = []

retholder = 0
bufholder = 0

hooks = utils.hook_container()

def generic_return_handler(debug,args,ret):
#	retval = debug.context.Eax
#	debug.bp_del(retholder)
#	retholder = 0
	generic_call_queue[-1].retval = ret
	print(str(generic_call_queue[-1].to_buffer()))
	logfile.write(str(generic_call_queue[-1].to_buffer()))
	logfile.write("\n")
	return DBG_CONTINUE

def smhandler(debug,args):
#	retholder = debug.get_arg(0)
	clientID = args[0]
	msgbuf = args[1]
	msglen = args[2]
	blockonsend = args[4]

#	debug.bp_set(retholder,handler=generic_return_handler)
	sent_message = debug.read_process_memory(msgbuf,msglen)

	generic_call_queue.append(SendMessage(clientID,msglen,blockonsend,sent_message))
	return DBG_CONTINUE

def rm_return_handler(debug,args,ret):
#	retval = debug.context.Eax
	try:
		msg = debug.read_process_memory(args[1],ret)
	except:
		msg = "Read Error"
	#debug.bp_del(retholder)
	read_call_queue[-1].retval = ret
	read_call_queue[-1].message = msg
	print(str(read_call_queue[-1].to_buffer()))
	logfile.write(str(read_call_queue[-1].to_buffer()))
	logfile.write("\n")
	return DBG_CONTINUE

def rmhandler(debug, args):
#	retholder = debug.get_arg(0)
	clientID = args[0]
	bufholder = args[1]
	bufsize = args[2]
	blockonread = args[3]

#	debug.bp_set(retholder,handler=rm_return_handler)
	read_call_queue.append(ReadMessage(clientID,bufsize,blockonread))
	return DBG_CONTINUE


def cchandler(debug,args):
#	retholder = debug.get_arg(0)
	device_id = args[1]
	fpchprotocol = args[2]
	txbufsize = args[3]
	rxbufsize = args[4]

	protocol_string = debug.read_process_memory(fpchprotocol,10)
	msg = debug.get_ascii_string(protocol_string)
	if not msg:
		msg = debug.get_unicode_string(protocol_string)
#	debug.bp_set(retholder,handler=generic_return_handler)
	generic_call_queue.append(ClientConnect(device_id,txbufsize,rxbufsize,msg))
	return DBG_CONTINUE

def cdhandler(debug,args):
#	retholder = debug.get_arg(0)
	device_id = args[0]

#	debug.bp_set(retholder,handler=generic_return_handler)
	generic_call_queue.append(ClientDisconnect(device_id))
	return DBG_CONTINUE

def schandler(debug,args):
#	retholder = debug.get_arg(0)
	commandnumber = args[0]
	clientID = args[1]
	fpchClientCommand = args[2]
	bufsize = args[3]

	commandbuf = debug.read_process_memory(fpchClientCommand,bufsize)
#	debug.bp_set(retholder,handler=generic_return_handler)
	generic_call_queue.append(SendCommand(commandnumber,clientID,commandbuf,bufsize))
	return DBG_CONTINUE

def get_proc_addr_hook(debug,args,ret):
	try:
		mem = debug.read_process_memory(args[1],40)
	except:
		return DBG_CONTINUE

	msg = debug.get_ascii_string(mem)
	if not msg:
		msg = debug.get_unicode_string(mem)

	if msg in RP1210calls.keys():
		RP1210calls[msg] = ret
		print("%s is at %d" % (msg,ret))
		if not None in RP1210calls.values():
			hooks.add(debug,RP1210calls["RP1210_ReadMessage"],4,rmhandler,rm_return_handler)
			hooks.add(debug,RP1210calls["RP1210_SendMessage"],5,smhandler,generic_return_handler)
			hooks.add(debug,RP1210calls["RP1210_ClientConnect"],6,cchandler,generic_return_handler)
			hooks.add(debug,RP1210calls["RP1210_ClientDisconnect"],1,cdhandler,generic_return_handler)
			hooks.add(debug,RP1210calls["RP1210_SendCommand"],4,schandler,generic_return_handler)
	return DBG_CONTINUE

def load_dll_handler(debug):
	last_dll = debug.get_system_dll(-1)
	#print(last_dll.name)
	if last_dll.name == "kernel32.dll":
		hooks.add(dbg,getproc,2,None,get_proc_addr_hook)

	return DBG_CONTINUE
'''	module_name = None
	for lib in liblist:
		if lib in last_dll.name:
			module_name = last_dll.name
			print("Loaded the RP1210 DLL %s" % module_name)
			break

	if module_name is not None:
		'''

#Check to see if a RP1210 DLL is loaded already
modules = dbg.enumerate_modules()
loaded = False
rp1210module = None
for module in map(lambda x: x[0],modules):
	if module.lower() in map(lambda x: x.lower(),liblist):
		loaded = True

		rp1210module = module
		break

if loaded:
	print("Found %s, resolving function addresses." % rp1210module)
	sendmsg = dbg.func_resolve_debuggee(rp1210module,"RP1210_SendMessage")
	readmsg = dbg.func_resolve_debuggee(rp1210module,"RP1210_ReadMessage")
	clientconnect = dbg.func_resolve_debuggee(rp1210module,"RP1210_ClientConnect")
	clientdisconnect = dbg.func_resolve_debuggee(rp1210module,"RP1210_ClientDisconnect")
	sendcommand = dbg.func_resolve_debuggee(rp1210module,"RP1210_SendCommand")

	hooks.add(dbg,sendmsg,5,smhandler,generic_return_handler)
	hooks.add(dbg,readmsg,4,rmhandler,rm_return_handler)
	hooks.add(dbg,clientconnect,6,cchandler,generic_return_handler)
	hooks.add(dbg,clientdisconnect,1,cdhandler,generic_return_handler)
	hooks.add(dbg,sendcommand,4,schandler,generic_return_handler)
else:
	print("Couldn't find module in memory, we'll wait for it.")
	dbg.set_callback(LOAD_DLL_DEBUG_EVENT,load_dll_handler)
dbg.run()



