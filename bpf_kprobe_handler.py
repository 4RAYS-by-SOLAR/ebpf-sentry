#!/usr/bin/python

from bcc import BPF
import threading
import queue
import insns_parser
import insns_encricher
from ctypes import c_int
from ebpfcodegenerator import generatecode

#for example, generate ebpf code for prevent pamspy tool
bpf_prog_txt = generatecode("pamspy")

insns_dict = {}
progs_dict = {}

func_list = insns_parser.get_func_numbers()

processing_queue = queue.Queue()
postprocessing_queue = queue.Queue()

def handle_generic_info(cpu, data, size):
	call_data = bpf_ctx["generic_info"].event(data)
	if call_data.random_id not in progs_dict:
		progs_dict.update({call_data.random_id:{"comm":call_data.comm, 
												"pid":call_data.pid, 
												"cmd":call_data.cmd, 
												"prog_type":call_data.prog_type, 
												"prog_name":call_data.prog_name,
												"insn_cnt":call_data.insn_cnt}})
		insns_dict.update({call_data.random_id:[]})
	else:
		progs_dict[call_data.random_id] = {"comm":call_data.comm, 
											"pid":call_data.pid, 
											"cmd":call_data.cmd, 
											"prog_type":call_data.prog_type, 
											"prog_name":call_data.prog_name,
											"insn_cnt":call_data.insn_cnt}

def handle_instructions(cpu, data, size):
	call_data = bpf_ctx["instructions"].event(data)
	if call_data.random_id not in progs_dict:
		progs_dict.update({call_data.random_id:{}})
		insns_dict.update({call_data.random_id:[]})
	insns_dict[call_data.random_id].append({"insn_num":call_data.insn_num,
											"code":call_data.code, 
											"reg": call_data.reg, 
											"off": call_data.off, 
											"imm": call_data.imm})
	if call_data.insn_num == (call_data.insn_cnt - 1):
		processing_queue.put({call_data.random_id:insns_dict[call_data.random_id]})

# Just a polling loop, nothing specila
def polling_loop(bpf_ctx):
	while 1:
		try:
			bpf_ctx.perf_buffer_poll()
		except KeyboardInterrupt:
			print()
			exit()

# Here we're just parsing instructions array
# Then we're sending parsed instructions to the next processing step
def processing_loop():
	while 1:
		insns = processing_queue.get()
		id = list(insns.keys())[0]
		insns_list = insns[id]
		parsed_insns = insns_parser.parse_insns_list(insns_list, func_list)
		processing_queue.task_done()
		postprocessing_queue.put({id:parsed_insns})

# Here we're waiting for all the data we need to make some detects
# Processing 
# Cleaning dicts because we're good guys
def postprocessing_loop():
	while 1:
		prog_insns = postprocessing_queue.get()
		id = list(prog_insns.keys())[0]
		prog_insns_parsed = prog_insns[id]
		while 1:
			if id in progs_dict:
				caller_info = progs_dict[id]
				break

		print(caller_info)

		string_list = insns_encricher.insns_postprocessing(prog_insns_parsed)
		print(string_list)

		for insn in prog_insns_parsed:
			print(insn['parsed_insn'])
			
		progs_dict.pop(id)
		insns_dict.pop(id)
		postprocessing_queue.task_done()

# Load BPF program
bpf_ctx = BPF(text=bpf_prog_txt)
event_name = bpf_ctx.get_syscall_fnname("bpf")
bpf_ctx.attach_kprobe(event=event_name, fn_name="syscall__bpf")

filtersInit = bpf_ctx.load_func("filtersInit", BPF.KPROBE)
funcPatternfilter = bpf_ctx.load_func("funcPatternfilter", BPF.KPROBE)
funcPatternProgname = bpf_ctx.load_func("funcPatternProgname", BPF.KPROBE)
successfulVerification = bpf_ctx.load_func("successfulVerification", BPF.KPROBE)
funcPatternfilterverdict = bpf_ctx.load_func("funcPatternfilterverdict", BPF.KPROBE)

prog_array = bpf_ctx.get_table("prog_array")
prog_array[c_int(2)] = c_int(filtersInit.fd)
prog_array[c_int(3)] = c_int(funcPatternfilter.fd)
prog_array[c_int(4)] = c_int(funcPatternfilterverdict.fd)
prog_array[c_int(5)] = c_int(funcPatternProgname.fd)
prog_array[c_int(6)] = c_int(successfulVerification.fd)

# Open perf "generic_info" buffer
bpf_ctx["generic_info"].open_perf_buffer(handle_generic_info)
bpf_ctx["instructions"].open_perf_buffer(handle_instructions)

polling_thread = threading.Thread(target=polling_loop, args=[bpf_ctx])
polling_thread.start()
print("[Polling loop] Thread started")

processing_thread = threading.Thread(target=processing_loop)
processing_thread.start()
print("[Processing loop] Thread started")

postprocessing_thread = threading.Thread(target=postprocessing_loop)
postprocessing_thread.start()
print("[Postrocessing loop] Thread started")