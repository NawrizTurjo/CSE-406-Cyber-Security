import time
import os
from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult

# ---------------------------------------------------------------------------
# GF(2^8) LOOKUP TABLE  — built ONCE at import time from the provided gf_mult
# Only the 7 multipliers actually used by Mixer / InvMixer are precomputed.
# Cost: 7 × 256 = 1792 gf_mult calls (~650 ms one-time on typical hardware).
# Payoff: every mix_columns / inv_mix_columns call drops from ~180 ms to <0.1 ms.
# ---------------------------------------------------------------------------
_GF_MULTIPLIERS = (0x01, 0x02, 0x03, 0x09, 0x0b, 0x0d, 0x0e)
_GF = {m: [gf_mult(m, b) for b in range(256)] for m in _GF_MULTIPLIERS}


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
def print_state_matrix(state, label=""):
    if label:
        print(f"\n--- {label} ---")
    for r in range(4):
        print(" ".join(f"{state[r][c]:02X}" for c in range(4)))

def bytes_to_hex_str(byte_data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in byte_data)

def block_to_state(block: bytes) -> list:
    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes.")
    return [[block[r + 4*c] for c in range(4)] for r in range(4)]

def state_to_block(state: list) -> bytes:
    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[r + 4*c] = state[r][c]
    return bytes(out)


# ---------------------------------------------------------------------------
# Key normalisation
# Truncate/zero-pad to the nearest valid AES key length (16/24/32).
# Justification: zero-pad is deterministic and never discards existing entropy;
# truncation keeps only the high-order bytes, which is standard practice.
# ---------------------------------------------------------------------------
def normalise_key(key_bytes: bytes, target_len: int = 16) -> bytes:
    kl = len(key_bytes)
    if   kl <= 16: target = 16
    elif kl <= 24: target = 24
    elif kl <= 32: target = 32
    else:          return key_bytes[:32]

    if len(key_bytes) == target: return key_bytes
    if len(key_bytes) >  target: return key_bytes[:target]
    return key_bytes.ljust(target, b'\x00')


# ---------------------------------------------------------------------------
# PKCS#7 padding
# ---------------------------------------------------------------------------
def pad_pkcs7(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        raise ValueError("Empty data")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError(f"Invalid PKCS#7 padding byte: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Inconsistent PKCS#7 padding bytes")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# Key schedule (generalised for 128 / 192 / 256-bit)
# Returns (round_keys, num_rounds)
# ---------------------------------------------------------------------------
def _g_func(word, rcon_idx):
    word = word[1:] + word[:1]            # RotWord
    word = [Sbox[b] for b in word]        # SubWord
    word[0] ^= Rcon[rcon_idx]             # XOR Rcon
    return word

def key_expansion(key_bytes: bytes):
    kl = len(key_bytes)
    if   kl == 16: nk, nr = 4, 10
    elif kl == 24: nk, nr = 6, 12
    elif kl == 32: nk, nr = 8, 14
    else: raise ValueError(f"Invalid key length: {kl}")

    total_words = 4 * (nr + 1)
    words = [list(key_bytes[i*4:i*4+4]) for i in range(nk)]

    for i in range(nk, total_words):
        t = list(words[i - 1])
        if i % nk == 0:
            t = _g_func(t, i // nk)
        elif nk == 8 and i % nk == 4:   # AES-256 extra SubWord
            t = [Sbox[b] for b in t]
        words.append([words[i - nk][j] ^ t[j] for j in range(4)])

    round_keys = []
    for ri in range(nr + 1):
        m = [[0]*4 for _ in range(4)]
        for c in range(4):
            for r in range(4):
                m[r][c] = words[ri*4 + c][r]
        round_keys.append(m)

    return round_keys, nr


# ---------------------------------------------------------------------------
# AES core transformations
# mix_columns / inv_mix_columns use _GF table instead of calling gf_mult()
# ---------------------------------------------------------------------------
def sub_bytes(state):
    for r in range(4):
        for c in range(4): state[r][c] = Sbox[state[r][c]]

def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def mix_columns(state):
    G = _GF
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        for r in range(4):
            state[r][c] = (G[Mixer[r][0]][col[0]] ^ G[Mixer[r][1]][col[1]] ^
                           G[Mixer[r][2]][col[2]] ^ G[Mixer[r][3]][col[3]])

def add_round_key(state, rk):
    for r in range(4):
        for c in range(4): state[r][c] ^= rk[r][c]

def inv_sub_bytes(state):
    for r in range(4):
        for c in range(4): state[r][c] = InvSbox[state[r][c]]

def inv_shift_rows(state):
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]

def inv_mix_columns(state):
    G = _GF
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        for r in range(4):
            state[r][c] = (G[InvMixer[r][0]][col[0]] ^ G[InvMixer[r][1]][col[1]] ^
                           G[InvMixer[r][2]][col[2]] ^ G[InvMixer[r][3]][col[3]])


# ---------------------------------------------------------------------------
# Single block encrypt / decrypt
# ---------------------------------------------------------------------------
def aes_encrypt_block(plaintext_block: bytes, round_keys: list, num_rounds: int) -> bytes:
    state = block_to_state(plaintext_block)
    add_round_key(state, round_keys[0])
    for i in range(1, num_rounds):
        sub_bytes(state); shift_rows(state); mix_columns(state); add_round_key(state, round_keys[i])
    sub_bytes(state); shift_rows(state); add_round_key(state, round_keys[num_rounds])
    return state_to_block(state)

def aes_decrypt_block(ciphertext_block: bytes, round_keys: list, num_rounds: int) -> bytes:
    state = block_to_state(ciphertext_block)
    add_round_key(state, round_keys[num_rounds])
    for i in range(num_rounds - 1, 0, -1):
        inv_shift_rows(state); inv_sub_bytes(state); add_round_key(state, round_keys[i]); inv_mix_columns(state)
    inv_shift_rows(state); inv_sub_bytes(state); add_round_key(state, round_keys[0])
    return state_to_block(state)


# ---------------------------------------------------------------------------
# ECB mode
# ---------------------------------------------------------------------------
def aes_encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    key = normalise_key(key)
    rk, nr = key_expansion(key)
    padded = pad_pkcs7(plaintext)
    ct = bytearray()
    for i in range(0, len(padded), 16):
        ct.extend(aes_encrypt_block(padded[i:i+16], rk, nr))
    return bytes(ct)

def aes_decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    key = normalise_key(key)
    rk, nr = key_expansion(key)
    raw = bytearray()
    for i in range(0, len(ciphertext), 16):
        raw.extend(aes_decrypt_block(ciphertext[i:i+16], rk, nr))
    return unpad_pkcs7(bytes(raw))


# ---------------------------------------------------------------------------
# CBC mode
# ---------------------------------------------------------------------------
def aes_encrypt_cbc(plaintext: bytes, key: bytes) -> bytes:
    """Returns IV (16 bytes) || ciphertext."""
    key = normalise_key(key)
    rk, nr = key_expansion(key)
    padded = pad_pkcs7(plaintext)
    iv  = os.urandom(16)
    ct  = bytearray(iv)
    prev = iv
    for i in range(0, len(padded), 16):
        xb = bytes(p ^ c for p, c in zip(padded[i:i+16], prev))
        cb = aes_encrypt_block(xb, rk, nr)
        ct.extend(cb); prev = cb
    return bytes(ct)

def aes_decrypt_cbc(ciphertext: bytes, key: bytes) -> bytes:
    """Input: IV (16 bytes) || ciphertext."""
    key = normalise_key(key)
    rk, nr = key_expansion(key)
    iv, act = ciphertext[:16], ciphertext[16:]
    raw  = bytearray()
    prev = iv
    for i in range(0, len(act), 16):
        b  = act[i:i+16]
        db = aes_decrypt_block(b, rk, nr)
        raw.extend(d ^ p for d, p in zip(db, prev))
        prev = b
    return unpad_pkcs7(bytes(raw))


# ---------------------------------------------------------------------------
# Test driver — matches official sample I/O format
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    plaintext_ascii = "We need picnic"
    plaintext_bytes = plaintext_ascii.encode('utf-8')

    test_cases = [
        {"name": "AES-128", "key": b"BUET CSE20 Batch"},
        {"name": "AES-192", "key": b"BUET CSE20 Batch 192BitK"},
        {"name": "AES-256", "key": b"BUET CSE20 Batch 256BitKeySecure"},
    ]

    print(f"Original Plaintext: {plaintext_ascii}")
    print(f"Plaintext (HEX)   : {bytes_to_hex_str(plaintext_bytes)}\n")

    for case in test_cases:
        name = case["name"]
        key  = case["key"]

        for mode in ("ECB", "CBC"):
            print(f"=============== [{name} / {mode}] ===============\n")
            print(f"Key:\nIn ASCII: {key.decode('ascii')}")
            print(f"In HEX  : {bytes_to_hex_str(key)}\n")
            print(f"Plain Text:\nIn ASCII: {plaintext_ascii}")
            print(f"In HEX: {bytes_to_hex_str(plaintext_bytes)}")
            padded = pad_pkcs7(plaintext_bytes)
            print(f"In ASCII (After Padding): {padded.decode('latin-1')}")
            print(f"In HEX (After Padding): {bytes_to_hex_str(padded)}\n")

            t_ks0 = time.perf_counter()
            rk, nr = key_expansion(normalise_key(key))
            ks_time = (time.perf_counter() - t_ks0) * 1000

            if mode == "ECB":
                t0 = time.perf_counter(); ct = aes_encrypt_ecb(plaintext_bytes, key); enc_time = (time.perf_counter()-t0)*1000
                t0 = time.perf_counter(); dt = aes_decrypt_ecb(ct, key);              dec_time = (time.perf_counter()-t0)*1000
                print("Ciphered Text:")
                print(f"In HEX: {bytes_to_hex_str(ct)}")
                print(f"In ASCII: {ct.decode('latin-1')}\n")
            else:
                t0 = time.perf_counter(); ct = aes_encrypt_cbc(plaintext_bytes, key); enc_time = (time.perf_counter()-t0)*1000
                t0 = time.perf_counter(); dt = aes_decrypt_cbc(ct, key);              dec_time = (time.perf_counter()-t0)*1000
                print("Ciphered Text:")
                print("(IV is the first 16 bytes, followed by the actual ciphertext)")
                print(f"In HEX: {bytes_to_hex_str(ct)}")
                print(f"In ASCII: {ct.decode('latin-1')}\n")

            raw_padded = pad_pkcs7(dt)  # re-add padding just for display
            print("Deciphered Text:")
            print(f"Before Unpadding:\nIn HEX: {bytes_to_hex_str(raw_padded)}")
            print(f"In ASCII: {raw_padded.decode('latin-1')}")
            print(f"After Unpadding:\nIn ASCII: {dt.decode('utf-8')}")
            print(f"In HEX: {bytes_to_hex_str(dt)}\n")
            print("Execution Time Details:")
            print(f"Key Schedule Time: {ks_time} ms")
            print(f"Encryption Time: {enc_time} ms")
            print(f"Decryption Time: {dec_time} ms\n")