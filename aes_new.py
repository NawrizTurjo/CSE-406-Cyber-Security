# -*- coding: utf-8 -*-
"""
2105032_AES.py  --  CSE 406, Assignment 01 (January 2026)
Task 1: AES-128 with ECB and CBC modes (PKCS#7 padding)
"""

import time
import os
from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult


# ---------------------------------------------------------------------------
# ১. ইউটিলিটি ফাংশন
# ---------------------------------------------------------------------------

def bytes_to_hex_str(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


# ---------------------------------------------------------------------------
# ২. Key normalisation  (Task 1.1 requirement)
#    Assignment: "handle keys of other lengths (pad or truncate — justify)"
#    Choice: truncate if longer, zero-pad if shorter.
#    Justification: zero-padding is deterministic and never loses entropy
#    compared to truncation; both parties must use the same rule.
# ---------------------------------------------------------------------------

def normalise_key(key_bytes: bytes, target_len: int = 16) -> bytes:
    if len(key_bytes) == target_len:
        return key_bytes
    if len(key_bytes) > target_len:
        return key_bytes[:target_len]          # truncate
    return key_bytes.ljust(target_len, b'\x00')  # zero-pad


# ---------------------------------------------------------------------------
# ৩. PKCS#7 প্যাডিং
# ---------------------------------------------------------------------------

def pad_pkcs7(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        raise ValueError("Empty data cannot be unpadded")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError(f"Invalid PKCS#7 padding byte: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Inconsistent PKCS#7 padding bytes")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# ৪. Key Schedule (Key Expansion)
# ---------------------------------------------------------------------------

def key_expansion(key_bytes: bytes) -> list:
    """128-bit key থেকে 11টি round key তৈরি করা।"""
    words = [list(key_bytes[i*4:i*4+4]) for i in range(4)]

    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]          # RotWord
            temp = [Sbox[b] for b in temp]      # SubWord
            temp[0] ^= Rcon[i // 4]             # XOR Rcon
        words.append([words[i-4][j] ^ temp[j] for j in range(4)])

    # প্রতি 4টি word → একটি 4×4 column-major round key matrix
    round_keys = []
    for r_idx in range(11):
        matrix = [[0]*4 for _ in range(4)]
        for c in range(4):
            for r in range(4):
                matrix[r][c] = words[r_idx*4 + c][r]
        round_keys.append(matrix)

    return round_keys


# ---------------------------------------------------------------------------
# ৫. AES কোর ট্রান্সফরমেশন
# ---------------------------------------------------------------------------

def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = Sbox[state[r][c]]


def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]


def mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        for r in range(4):
            state[r][c] = (gf_mult(Mixer[r][0], col[0]) ^
                           gf_mult(Mixer[r][1], col[1]) ^
                           gf_mult(Mixer[r][2], col[2]) ^
                           gf_mult(Mixer[r][3], col[3]))


def add_round_key(state, round_key):
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]


def inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = InvSbox[state[r][c]]


def inv_shift_rows(state):
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]


def inv_mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        for r in range(4):
            state[r][c] = (gf_mult(InvMixer[r][0], col[0]) ^
                           gf_mult(InvMixer[r][1], col[1]) ^
                           gf_mult(InvMixer[r][2], col[2]) ^
                           gf_mult(InvMixer[r][3], col[3]))


# ---------------------------------------------------------------------------
# ৬. একক ব্লক এনক্রিপশন / ডিক্রিপশন (16 bytes)
# ---------------------------------------------------------------------------

def aes_encrypt_block(plaintext_block: bytes, round_keys: list) -> bytes:
    # Column-major state initialisation
    state = [[plaintext_block[r + 4*c] for c in range(4)] for r in range(4)]

    add_round_key(state, round_keys[0])

    for i in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[i])

    # Final round: no MixColumns
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])

    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[r + 4*c] = state[r][c]
    return bytes(out)


def aes_decrypt_block(ciphertext_block: bytes, round_keys: list) -> bytes:
    state = [[ciphertext_block[r + 4*c] for c in range(4)] for r in range(4)]

    add_round_key(state, round_keys[10])

    for i in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[i])
        inv_mix_columns(state)

    # Final inverse round: no InvMixColumns
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])

    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[r + 4*c] = state[r][c]
    return bytes(out)


# ---------------------------------------------------------------------------
# ৭. ECB Mode
# ---------------------------------------------------------------------------

def aes_encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    key = normalise_key(key)
    round_keys = key_expansion(key)
    padded = pad_pkcs7(plaintext)
    ct = bytearray()
    for i in range(0, len(padded), 16):
        ct.extend(aes_encrypt_block(padded[i:i+16], round_keys))
    return bytes(ct)


def aes_decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    key = normalise_key(key)
    round_keys = key_expansion(key)
    raw = bytearray()
    for i in range(0, len(ciphertext), 16):
        raw.extend(aes_decrypt_block(ciphertext[i:i+16], round_keys))
    return unpad_pkcs7(bytes(raw))


# ---------------------------------------------------------------------------
# ৮. CBC Mode
# ---------------------------------------------------------------------------

def aes_encrypt_cbc(plaintext: bytes, key: bytes) -> bytes:
    """রিটার্ন: IV (16 bytes) || Ciphertext"""
    key = normalise_key(key)
    round_keys = key_expansion(key)
    padded = pad_pkcs7(plaintext)
    iv = os.urandom(16)
    ct = bytearray(iv)
    prev = iv
    for i in range(0, len(padded), 16):
        block = bytes(p ^ c for p, c in zip(padded[i:i+16], prev))
        cb = aes_encrypt_block(block, round_keys)
        ct.extend(cb)
        prev = cb
    return bytes(ct)


def aes_decrypt_cbc(ciphertext: bytes, key: bytes) -> bytes:
    """ইনপুট: IV (16 bytes) || Ciphertext"""
    key = normalise_key(key)
    round_keys = key_expansion(key)
    iv, actual_ct = ciphertext[:16], ciphertext[16:]
    raw = bytearray()
    prev = iv
    for i in range(0, len(actual_ct), 16):
        block = actual_ct[i:i+16]
        db = aes_decrypt_block(block, round_keys)
        raw.extend(d ^ p for d, p in zip(db, prev))
        prev = block
    return unpad_pkcs7(bytes(raw))


# ---------------------------------------------------------------------------
# ৯. Test Driver  (Official Sample I/O format)
# ---------------------------------------------------------------------------

def run_ecb(key_ascii, plaintext_ascii):
    key_bytes = key_ascii.encode('ascii')
    pt_bytes  = plaintext_ascii.encode('ascii')

    print("==================== AES / ECB ====================\n")
    print(f"Key:\nIn ASCII: {key_ascii}")
    print(f"In HEX: {bytes_to_hex_str(key_bytes)}\n")
    print(f"Plain Text:\nIn ASCII: {plaintext_ascii}")
    print(f"In HEX: {bytes_to_hex_str(pt_bytes)}")

    padded = pad_pkcs7(pt_bytes)
    padded_ascii = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in padded)
    print(f"In ASCII (After Padding): {padded_ascii}")
    print(f"In HEX (After Padding): {bytes_to_hex_str(padded)}\n")

    # Key schedule
    t0 = time.perf_counter()
    rk = key_expansion(normalise_key(key_bytes))
    ks_time = (time.perf_counter() - t0) * 1000

    # Encryption
    t1 = time.perf_counter()
    ct = aes_encrypt_ecb(pt_bytes, key_bytes)
    enc_time = (time.perf_counter() - t1) * 1000

    safe_ct = ''.join(chr(b) if 32 <= b < 127 else '?' for b in ct)
    print(f"Ciphered Text:\nIn HEX: {bytes_to_hex_str(ct)}")
    print(f"In ASCII: {safe_ct}\n")

    # Decryption (show before/after unpadding)
    t2 = time.perf_counter()
    raw_padded = bytearray()
    for i in range(0, len(ct), 16):
        raw_padded.extend(aes_decrypt_block(ct[i:i+16], rk))
    pt_recovered = unpad_pkcs7(bytes(raw_padded))
    dec_time = (time.perf_counter() - t2) * 1000

    raw_ascii = ''.join(chr(b) if 32 <= b < 127 else '?' for b in raw_padded)
    print("Deciphered Text:")
    print(f"Before Unpadding:\nIn HEX: {bytes_to_hex_str(bytes(raw_padded))}")
    print(f"In ASCII: {raw_ascii}")
    print(f"After Unpadding:\nIn ASCII: {pt_recovered.decode('ascii')}")
    print(f"In HEX: {bytes_to_hex_str(pt_recovered)}\n")

    print(f"Execution Time Details:")
    print(f"Key Schedule Time: {ks_time} ms")
    print(f"Encryption Time: {enc_time} ms")
    print(f"Decryption Time: {dec_time} ms")


def run_cbc(key_ascii, plaintext_ascii):
    key_bytes = key_ascii.encode('ascii')
    pt_bytes  = plaintext_ascii.encode('ascii')

    print("==================== AES / CBC ====================\n")
    print(f"Key:\nIn ASCII: {key_ascii}")
    print(f"In HEX: {bytes_to_hex_str(key_bytes)}\n")
    print(f"Plain Text:\nIn ASCII: {plaintext_ascii}")
    print(f"In HEX: {bytes_to_hex_str(pt_bytes)}")

    padded = pad_pkcs7(pt_bytes)
    padded_ascii = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in padded)
    print(f"In ASCII (After Padding): {padded_ascii}")
    print(f"In HEX (After Padding): {bytes_to_hex_str(padded)}\n")

    # Key schedule
    t0 = time.perf_counter()
    rk = key_expansion(normalise_key(key_bytes))
    ks_time = (time.perf_counter() - t0) * 1000

    # Encryption
    t1 = time.perf_counter()
    ct_with_iv = aes_encrypt_cbc(pt_bytes, key_bytes)
    enc_time = (time.perf_counter() - t1) * 1000

    safe_ct = ''.join(chr(b) if 32 <= b < 127 else '?' for b in ct_with_iv)
    print("Ciphered Text:")
    print("(IV is the first 16 bytes, followed by the actual ciphertext)")
    print(f"In HEX: {bytes_to_hex_str(ct_with_iv)}")
    print(f"In ASCII: {safe_ct}\n")

    # Decryption
    iv  = ct_with_iv[:16]
    act = ct_with_iv[16:]
    t2 = time.perf_counter()
    raw_padded = bytearray()
    prev = iv
    for i in range(0, len(act), 16):
        b = act[i:i+16]
        db = aes_decrypt_block(b, rk)
        raw_padded.extend(d ^ p for d, p in zip(db, prev))
        prev = b
    pt_recovered = unpad_pkcs7(bytes(raw_padded))
    dec_time = (time.perf_counter() - t2) * 1000

    raw_ascii = ''.join(chr(b) if 32 <= b < 127 else '?' for b in raw_padded)
    print("Deciphered Text:")
    print(f"Before Unpadding:\nIn HEX: {bytes_to_hex_str(bytes(raw_padded))}")
    print(f"In ASCII: {raw_ascii}")
    print(f"After Unpadding:\nIn ASCII: {pt_recovered.decode('ascii')}")
    print(f"In HEX: {bytes_to_hex_str(pt_recovered)}\n")

    print(f"Execution Time Details:")
    print(f"Key Schedule Time: {ks_time} ms")
    print(f"Encryption Time: {enc_time} ms")
    print(f"Decryption Time: {dec_time} ms")


if __name__ == "__main__":
    KEY       = "BUET CSE20 Batch"
    PLAINTEXT = "We need picnic"
    run_ecb(KEY, PLAINTEXT)
    print("\n")
    run_cbc(KEY, PLAINTEXT)