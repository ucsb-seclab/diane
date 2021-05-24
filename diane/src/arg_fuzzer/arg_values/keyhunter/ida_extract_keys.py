from idaapi import *
import struct

key_fn_addr = 0x281d0
key_strings = set()

xrefs_to_key_fn = [xref for xref in XrefsTo(key_fn_addr)]
for xref in xrefs_to_key_fn:
	call_addr = xref.frm
	print "call_addr=", hex(call_addr)
	max_instr_iter = 5
	instr = call_addr
	while max_instr_iter > 0:
		max_instr_iter -= 1
		instr = PrevHead(instr)
		opcode = GetMnem(instr)
		operand0 = GetOpnd(instr, 0)
		if opcode == 'LDR' and operand0 == 'R1':
			print "LDR R1=", hex(instr)
			str_xref_addr = GetOperandValue(instr, 1)
			print "str_xref_addr=", hex(str_xref_addr)
			str_addr = struct.unpack('<I', get_many_bytes(str_xref_addr, 4))[0]
			print "str_addr=", hex(str_addr)
			str = GetString(str_addr)
			print "string=", str
			key_strings.add(str)
			break

print key_strings
with open('key_strings.txt', 'w') as fp:
	for key_string in key_strings:
		fp.write(key_string + '\n')
