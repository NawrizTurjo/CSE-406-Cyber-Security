import time
import os
from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult

_GF_MULTIPLIERS = (0x01, 0x02, 0x03, 0x09, 0x0b, 0x0d, 0x0e)

# look-up table so gf_mult is not calling again and again
# this unlocks fast galois field multiplication

GF_LUT = {}

for multiplier in _GF_MULTIPLIERS:

    table = []

    for byte in range(256):

        result = gf_mult(multiplier, byte)

        table.append(result)

    GF_LUT[multiplier] = table


def print_state_matrix(state, label=""):
    if label:
        print(f"\n--- {label} ---")
    for r in range(4):
        row_str = " ".join(f"{state[r][c]:02X}" for c in range(4))
        print(row_str)

def bytes_to_hex_str(byte_data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in byte_data)

def block_to_state(block: bytes) -> list:
    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes.")

    state = [[0] * 4 for _ in range(4)]

    for r in range(4):
        for c in range(4):
            state[r][c] = block[r + 4 * c]

    return state

def state_to_block(state: list) -> bytes:
    if len(state) != 4 or any(len(row) != 4 for row in state):
        raise ValueError("State must be a 4x4 matrix.")

    block = bytearray(16)

    for r in range(4):
        for c in range(4):
            block[r + 4 * c] = state[r][c]

    return bytes(block)

def normalise_key(key_bytes: bytes, target_len: int = 16) -> bytes:

    key_len = len(key_bytes)
    
    if key_len <= 16:
        target_len = 16
    elif key_len <= 24:
        target_len = 24
    elif key_len <= 32:
        target_len = 32
    else:
        return key_bytes[:32]
    
    
    if len(key_bytes) == target_len:
        return key_bytes
    if len(key_bytes) > target_len:
        return key_bytes[:target_len]          # truncate
    return key_bytes.ljust(target_len, b'\x00')  # zero-pad, left justified



def pad_pkcs7(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    padding = bytes([pad_len] * pad_len) # pad_len num of padding bytes nibo
    return data + padding 

def unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        raise ValueError("Empty Data")
    pad_len = data[-1]

    if pad_len==0 or pad_len > 16:
        raise ValueError(f"Invalid PKCS#7 padding byte: {pad_len}")
    # scheme wise na mille inconsistent hobe
    if data[-pad_len:] != bytes([pad_len]*pad_len): 
        raise ValueError("Inconsistent PKCS#7 padding")
    unpadded_data = data[:-pad_len]
    return unpadded_data



def g_func(word, RCon_idx):
    
    # 1. RotWord
    word = word[1:] + word[:1] # [a,b,c,d] => [b,c,d,a]
    # 2.SubWord
    word = [Sbox[b] for b in word] # [a,b,c,d] => [Sbox[a], Sbox[b], Sbox[c], Sbox[d]]
    # 3.XOR Rcon
    word[0] = word[0] ^ Rcon[RCon_idx] # 

    return word

def key_expansion(key_bytes: bytes) -> list:
    
    """
    generalize to 128, 192 and 256 bit
    """
    key_len =  len(key_bytes)

    if key_len==16:
        num_key_word=4
        num_rounds=10
    elif key_len==24:
        num_key_word=6
        num_rounds=12
    elif key_len==32:
        num_key_word=8
        num_rounds=14
    else:
        raise ValueError("Invalid key length")
    
    total_words = 4 * (num_rounds + 1)
    
    words = [] # 4 bytes per word

    for i in range(0,num_key_word):
        # first 4 ta word copy korbo round key er jonne
        words.append(list(key_bytes[i*4 : i*4 + 4]))
    
    # baki 40 tar jonno
    for i in range (num_key_word,total_words):
        prev_word = list(words[i-1]) # keep previous ones

        if i % num_key_word == 0:
            # # 1. RotWord
            # prev_word = prev_word[1:] + prev_word[:1] 
            # # 2.SubWord
            # prev_word = [Sbox[b] for b in prev_word] 
            # # 3.XOR RCon
            # prev_word[0] = prev_word[0] ^ Rcon[i // 4]
            prev_word = g_func(prev_word, i//num_key_word)
        elif num_key_word == 8 and (i % num_key_word == 4):
            # special for 256-bit key
            prev_word = [Sbox[b] for b in prev_word]
        
        word_i = []
        # all words will be xor-ed
        for j in range(4):
            word_i.append(words[i-num_key_word][j] ^ prev_word[j])
        
        words.append(word_i)
    
    # for i in range(44):
    #     print(f"Word {i}: {bytes_to_hex_str(words[i])}")

    
    round_keys = []
    for r_idx in range(num_rounds + 1):
        sliced_words = words[r_idx * 4 : r_idx * 4 + 4]
        matrix = [[0]*4 for _ in range(4)]
        for c in range(4):
            # each word as column of the matrix (like word_0 goes to col_0)
            word = sliced_words[c]
            for r in range(4):
                matrix[r][c] = word[r]
        round_keys.append(matrix)
    
    return round_keys, num_rounds
            
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
            state[r][c] = (GF_LUT[Mixer[r][0]][col[0]]^
                            GF_LUT[Mixer[r][1]][col[1]]^
                            GF_LUT[Mixer[r][2]][col[2]]^
                            GF_LUT[Mixer[r][3]][col[3]])

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
            state[r][c] = (GF_LUT[InvMixer[r][0]][col[0]]^
                            GF_LUT[InvMixer[r][1]][col[1]]^
                            GF_LUT[InvMixer[r][2]][col[2]]^
                            GF_LUT[InvMixer[r][3]][col[3]])
            
def aes_encrypt_block(plaintext_block: bytes, round_keys: list, num_rounds: int) -> bytes:
    state = block_to_state(plaintext_block)
            
    # print_state_matrix(state, "Original Plaintext State Matrix")
    
    # --- Round 0 (Pre-round) ---
    add_round_key(state, round_keys[0])
    # print_state_matrix(state, "State After Round 0 (AddRoundKey)")
    
    # --- Round 1 to 9 ---
    for i in range(1, num_rounds):
        # print(f"\n==================== START ROUND {i} ====================")
        
        sub_bytes(state)
        # if i == 1: print_state_matrix(state, "Round 1: After SubBytes") 
        
        shift_rows(state)
        # if i == 1: print_state_matrix(state, "Round 1: After ShiftRows")
        
        mix_columns(state)
        # if i == 1: print_state_matrix(state, "Round 1: After MixColumns")
        
        add_round_key(state, round_keys[i])
        # if i == 1: print_state_matrix(state, "Round 1: After AddRoundKey")

        
    # --- Round 10 (Final Round - No MixColumns) ---
    # print(f"\n==================== START ROUND 10 (Final Round) ====================")
    sub_bytes(state)
    # print_state_matrix(state, "Round 10: After SubBytes")
    
    shift_rows(state)
    # print_state_matrix(state, "Round 10: After ShiftRows")
    
    add_round_key(state, round_keys[num_rounds])
    # print_state_matrix(state, "Round 10: After Final AddRoundKey")
    
    output_block = state_to_block(state)
            
    return output_block

def aes_decrypt_block(ciphertext_block: bytes, round_keys: list, num_rounds: int) -> bytes:
    state = block_to_state(ciphertext_block)
            
    add_round_key(state, round_keys[num_rounds])
    
    for i in range(num_rounds-1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[i])
        inv_mix_columns(state)
        
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])
    
    output_block = state_to_block(state)
            
    return output_block

# --- ECB Mode ---
def aes_encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    key = normalise_key(key)
    round_keys, num_rounds = key_expansion(key)
    padded_data = pad_pkcs7(plaintext)
    ciphertext = bytearray()
    
    for i in range(0, len(padded_data), 16):
        current_block = padded_data[i:i+16]
        cipher_block = aes_encrypt_block(current_block, round_keys, num_rounds)
        ciphertext.extend(cipher_block)
        
    return bytes(ciphertext)

def aes_decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    key = normalise_key(key)
    round_keys, num_rounds = key_expansion(key)
    plaintext_padded = bytearray()
    
    for i in range(0, len(ciphertext), 16):
        current_block = ciphertext[i:i+16]
        plain_block = aes_decrypt_block(current_block, round_keys, num_rounds)
        plaintext_padded.extend(plain_block)
        
    return unpad_pkcs7(bytes(plaintext_padded))


# --- CBC Mode ---
def aes_encrypt_cbc(plaintext: bytes, key: bytes) -> tuple:
    key = normalise_key(key)
    round_keys, num_rounds = key_expansion(key)
    padded_data = pad_pkcs7(plaintext)
    
    iv = os.urandom(16)
    ciphertext = bytearray(iv)  
    
    prev_block = iv
    for i in range(0, len(padded_data), 16):
        current_block = padded_data[i:i+16]
        xor_block = bytearray(16)
        for r in range(4):
            for c in range(4):
                xor_block[r + 4 * c] = current_block[r + 4 * c] ^ prev_block[r + 4 * c]
        cipher_block = aes_encrypt_block(xor_block, round_keys, num_rounds)
        ciphertext.extend(cipher_block)
        prev_block = cipher_block
        
    return bytes(ciphertext)

def aes_decrypt_cbc(ciphertext: bytes, key: bytes) -> bytes:
    key = normalise_key(key)
    round_keys, num_rounds = key_expansion(key)
    
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    plaintext_padded = bytearray()
    
    prev_block = iv
    for i in range(0, len(actual_ciphertext), 16):
        current_block = actual_ciphertext[i:i+16]
        decrypted_block = aes_decrypt_block(current_block, round_keys, num_rounds)
        plain_block = bytearray(16)
        for r in range(4):
            for c in range(4):
                plain_block[r + 4 * c] = decrypted_block[r + 4 * c] ^ prev_block[r + 4 * c]
        plaintext_padded.extend(plain_block)
        prev_block = current_block
        
    return unpad_pkcs7(bytes(plaintext_padded))


if __name__ == "__main__":
    plaintext_ascii = "We need picnic"
    plaintext_bytes = plaintext_ascii.encode('utf-8')
    
    test_cases = [
        {"name": "AES-128", "key": b"BUET CSE20 Batch"},
        {"name": "AES-192", "key": b"BUET CSE20 Batch 192BitK"},
        {"name": "AES-256", "key": b"BUET CSE20 Batch 256BitKeySecure"}
    ]
    
    print(f"Original Plaintext: {plaintext_ascii}")
    print(f"Plaintext (HEX)   : {bytes_to_hex_str(plaintext_bytes)}\n")
    
    for case in test_cases:
        name = case["name"]
        key = case["key"]
        
        print("=" * 60)
        print(f"                         {name}              ")
        print("=" * 60)
        
        # ----------------------------- ECB MODE TEST -----------------------------
        
        
        print(f"=============== [{name} / ECB] ===============")
        print()
        print("Key:")
        print(f"In ASCII: {key.decode('ascii')}")
        print(f"In HEX  : {bytes_to_hex_str(key)}\n")

        print("Plain Text:")
        print(f"In ASCII: {plaintext_ascii}")
        print(f"In HEX: {bytes_to_hex_str(plaintext_bytes)}")

        padded_bytes=pad_pkcs7(plaintext_bytes)
        print(f"In ASCII (After Padding): {padded_bytes.decode('utf-8')}")
        print(f"In HEX (After Padding): {bytes_to_hex_str(padded_bytes)}\n")

        
        start_ks = time.perf_counter()
        round_keys, num_rounds = key_expansion(key)
        ks_time = (time.perf_counter() - start_ks) * 1000
        
        start_enc = time.perf_counter()
        ct_ecb = aes_encrypt_ecb(plaintext_bytes, key)
        enc_time = (time.perf_counter() - start_enc) * 1000
        
        start_dec = time.perf_counter()
        dt_ecb = aes_decrypt_ecb(ct_ecb, key)
        dec_time = (time.perf_counter() - start_dec) * 1000
        
        print("Ciphered Text:")
        print(f"In HEX: {bytes_to_hex_str(ct_ecb)}")
        print(f"In ASCII: {ct_ecb.decode('latin-1')}\n")

        print("Deciphered Text:")
        print("Before Unpadding:")
        dt_ecb_padded = pad_pkcs7(dt_ecb)
        print(f"In HEX: {bytes_to_hex_str(dt_ecb_padded)}")
        print(f"In ASCII: {dt_ecb_padded.decode('latin-1')}")
        
        print(f"After Unpadding:")
        print(f"In ASCII: {dt_ecb.decode('utf-8')}")
        print(f"In HEX: {bytes_to_hex_str(dt_ecb)}\n")
        
        # print(f"Execution Times : Key Schedule: {ks_time:.4f}ms | Encrypt: {enc_time:.4f}ms | Decrypt: {dec_time:.4f}ms")
        print("Execution Time Details:")
        print(f"Key Schedule Time: {ks_time}")
        print(f"Encryption Time: {enc_time}")
        print(f"Decryption Time: {dec_time}")
        # print(f"Sanity Check    : {'MATCHED' if dt_ecb == plaintext_bytes else 'MISMATCH'}\n")
        print("")
        
        
        # ----------------------------- CBC MODE TEST -----------------------------
        
        
        print(f"=============== [{name} / CBC] ===============")
        print()

        print("Key:")
        print(f"In ASCII: {key.decode('ascii')}")
        print(f"In HEX  : {bytes_to_hex_str(key)}\n")

        print("Plain Text:")
        print(f"In ASCII: {plaintext_ascii}")
        print(f"In HEX: {bytes_to_hex_str(plaintext_bytes)}")

        padded_bytes=pad_pkcs7(plaintext_bytes)
        print(f"In ASCII (After Padding): {padded_bytes.decode('utf-8')}")
        print(f"In HEX (After Padding): {bytes_to_hex_str(padded_bytes)}\n")
        
        
        start_ks = time.perf_counter()
        round_keys, num_rounds = key_expansion(key)
        ks_time = (time.perf_counter() - start_ks) * 1000
        
        start_enc = time.perf_counter()
        ct_cbc = aes_encrypt_cbc(plaintext_bytes, key)
        enc_time = (time.perf_counter() - start_enc) * 1000
        
        start_dec = time.perf_counter()
        dt_cbc = aes_decrypt_cbc(ct_cbc, key)
        dec_time = (time.perf_counter() - start_dec) * 1000
        
        # print(f"Ciphertext (HEX): {bytes_to_hex_str(ct_cbc)}")
        # print(f"Decrypted Text  : {dt_cbc.decode('utf-8')}")

        print("Ciphered Text:")
        print("(IV is the first 16 bytes, followed by the actual ciphertext)")
        print(f"In HEX: {bytes_to_hex_str(ct_cbc)}")
        print(f"In ASCII: {ct_cbc.decode('latin-1')}\n")

        print("Deciphered Text:")
        print("Before Unpadding:")
        dt_cbc_padded = pad_pkcs7(dt_cbc)
        print(f"In HEX: {bytes_to_hex_str(dt_cbc_padded)}")
        print(f"In ASCII: {dt_cbc_padded.decode('latin-1')}")
        
        print(f"After Unpadding:")
        print(f"In ASCII: {dt_cbc.decode('utf-8')}")
        print(f"In HEX: {bytes_to_hex_str(dt_cbc)}\n")
        
        # print(f"Execution Times : Key Schedule: {ks_time:.4f}ms | Encrypt: {enc_time:.4f}ms | Decrypt: {dec_time:.4f}ms")
        print("Execution Time Details:")
        print(f"Key Schedule Time: {ks_time}")
        print(f"Encryption Time: {enc_time}")
        print(f"Decryption Time: {dec_time}")

        # print(f"Sanity Check    : {'MATCHED' if dt_cbc == plaintext_bytes else 'MISMATCH'}\n")
        