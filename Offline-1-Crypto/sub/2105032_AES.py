import time
import os
# aes_helpers.py থেকে প্রয়োজনীয় জিনিসগুলো ইম্পোর্ট করা হলো
from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult

# --- ১. ইউটিলিটি ফাংশন (ম্যাট্রিক্স সুন্দর করে প্রিন্ট করার জন্য) ---
def print_state_matrix(state, label=""):
    """৪x৪ স্টেট ম্যাট্রিক্সকে কলাম-মেজর বা রো-মেজর ফরম্যাটে সুন্দর করে HEX প্রিন্ট করার ফাংশন"""
    if label:
        print(f"\n--- {label} ---")
    for r in range(4):
        row_str = " ".join(f"{state[r][c]:02X}" for c in range(4))
        print(row_str)

def bytes_to_hex_str(byte_data: bytes) -> str:
    """বাইট ডেটাকে স্পেস দিয়ে HEX স্ট্রিংয়ে কনভার্ট করার ফাংশন"""
    return " ".join(f"{b:02X}" for b in byte_data)


# --- ২. প্যাডিং (PKCS#7) ---
def pad_pkcs7(data: bytes) -> bytes:
    """মেসেজকে ১৬ বাইটের মাল্টিপল বানানোর জন্য PKCS#7 প্যাডিং যোগ করার ফাংশন"""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad_pkcs7(data: bytes) -> bytes:
    """ডিক্রিপশনের পর প্যাডিং রিমুভ করার ফাংশน"""
    pad_len = data[-1]
    return data[:-pad_len]


# --- ৩. কী এক্সপেনশন (Key Schedule) ---
def key_expansion_generalized(key_bytes: bytes) -> tuple:
    """
    ১২৮, ১৯২ বা ২৫৬ বিটের কী-কে এক্সপ্যান্ড করার জেনারেলাইজড ফাংশন।
    রিটার্ন করবে: (round_keys_list, Nr)
    """
    key_len = len(key_bytes)
    
    # কী সাইজ অনুযায়ী Nk এবং Nr নির্ধারণ
    if key_len == 16:
        Nk, Nr = 4, 10
    elif key_len == 24:
        Nk, Nr = 6, 12
    elif key_len == 32:
        Nk, Nr = 8, 14
    else:
        raise ValueError("Unsupported key length! Must be 16, 24, or 32 bytes.")
        
    total_words = 4 * (Nr + 1)
    words = []
    
    # প্রাথমিক ওয়ার্ডসমূহ ইনিশিয়ালাইজ করা
    for i in range(Nk):
        words.append(list(key_bytes[i*4 : (i+1)*4]))
        
    # এক্সপেনশন কোর লুপ
    for i in range(Nk, total_words):
        temp = list(words[i - 1])
        
        if i % Nk == 0:
            # RotWord + SubWord + Rcon XOR
            temp = temp[1:] + temp[:1]
            temp = [Sbox[b] for b in temp]
            temp[0] = temp[0] ^ Rcon[i // Nk]
        elif Nk == 8 and i % Nk == 4:
            # AES-256 এর বিশেষ নিয়ম: শুধু SubWord
            temp = [Sbox[b] for b in temp]
            
        word_i = [words[i - Nk][j] ^ temp[j] for j in range(4)]
        words.append(word_i)
        
    # ৪x৪ স্টেট ম্যাট্রিক্সের লিস্ট তৈরি করা
    round_keys = []
    for r_idx in range(Nr + 1):
        matrix = [[0]*4 for _ in range(4)]
        for c in range(4):
            word = words[r_idx * 4 + c]
            for r in range(4):
                matrix[r][c] = word[r]
        round_keys.append(matrix)
        
    return round_keys, Nr

def key_expansion(key_bytes: bytes) -> list:
    """পুরোনো ইন্টারফেস বজায় রাখার জন্য কী এক্সপেনশন ওয়ান-স্টপ ফাংশন"""
    round_keys, _ = key_expansion_generalized(key_bytes)
    return round_keys
            


# --- ৪. AES কোর লেয়ার ফাংশনসমূহ ---
def sub_bytes(state):
    """Sbox ব্যবহার করে স্টেটের প্রতিটি বাইট সাবস্টিটিউট করা"""
    for r in range(4):
        for c in range(4):
            state[r][c] = Sbox[state[r][c]]

def shift_rows(state):
    """রো ১, ২, ৩ কে যথাক্রমে ১, ২, ৩ বাইট বামে সার্কুলার শিফট করা"""
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def mix_columns(state):
    """gf_mult এবং Mixer ম্যাট্রিক্স ব্যবহার করে কলাম মিক্সিং করা"""
    for c in range(4):
        # কলাম c এর জন্য নতুন ৪টি ভ্যালু হিসাব করুন
        s0 = gf_mult(Mixer[0][0], state[0][c]) ^ gf_mult(Mixer[0][1], state[1][c]) ^ gf_mult(Mixer[0][2], state[2][c]) ^ gf_mult(Mixer[0][3], state[3][c])
        s1 = gf_mult(Mixer[1][0], state[0][c]) ^ gf_mult(Mixer[1][1], state[1][c]) ^ gf_mult(Mixer[1][2], state[2][c]) ^ gf_mult(Mixer[1][3], state[3][c])
        s2 = gf_mult(Mixer[2][0], state[0][c]) ^ gf_mult(Mixer[2][1], state[1][c]) ^ gf_mult(Mixer[2][2], state[2][c]) ^ gf_mult(Mixer[2][3], state[3][c])
        s3 = gf_mult(Mixer[3][0], state[0][c]) ^ gf_mult(Mixer[3][1], state[1][c]) ^ gf_mult(Mixer[3][2], state[2][c]) ^ gf_mult(Mixer[3][3], state[3][c])
        state[0][c], state[1][c], state[2][c], state[3][c] = s0, s1, s2, s3

def add_round_key(state, round_key):
    """কারেন্ট স্টেটের সাথে রাউন্ড কী ম্যাট্রিক্সের XOR করা"""
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]

def inv_sub_bytes(state):
    """InvSbox ব্যবহার করে স্টেটের প্রতিটি বাইট প্রতিস্থাপন করা"""
    for r in range(4):
        for c in range(4):
            state[r][c] = InvSbox[state[r][c]]

def inv_shift_rows(state):
    """রো ১, ২, ৩ কে যথাক্রমে ১, ২, ৩ বাইট ডানে সার্কুলার শিফট করা (এনক্র�def aes_encrypt_block(plaintext_block: bytes, round_keys: list, verbose=False) -> bytes:
    """১৬ বাইটের একটি ব্লককে ধাপে ধাপে এনক্রিপ্ট করার ফাংশন"""
    Nr = len(round_keys) - 1
    state = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = plaintext_block[r + 4 * c]
            
    if verbose: print_state_matrix(state, "Original Plaintext State Matrix")
    
    # --- Round 0 (Pre-round) ---
    add_round_key(state, round_keys[0])
    if verbose: print_state_matrix(state, "State After Round 0 (AddRoundKey)")
    
    # --- Round 1 to Nr-1 ---
    for i in range(1, Nr):
        if verbose: print(f"\n==================== START ROUND {i} ====================")
        sub_bytes(state)
        if verbose and i == 1: print_state_matrix(state, "Round 1: After SubBytes") 
        shift_rows(state)
        if verbose and i == 1: print_state_matrix(state, "Round 1: After ShiftRows")
        mix_columns(state)
        if verbose and i == 1: print_state_matrix(state, "Round 1: After MixColumns")
        add_round_key(state, round_keys[i])
        if verbose and i == 1: print_state_matrix(state, "Round 1: After AddRoundKey")
        
    # --- Round Nr (Final Round) ---
    if verbose: print(f"\n==================== START ROUND {Nr} (Final Round) ====================")
    sub_bytes(state)
    if verbose: print_state_matrix(state, f"Round {Nr}: After SubBytes")
    shift_rows(state)
    if verbose: print_state_matrix(state, f"Round {Nr}: After ShiftRows")
    add_round_key(state, round_keys[Nr])
    if verbose: print_state_matrix(state, f"Round {Nr}: After Final AddRoundKey")
    
    output_block = bytearray(16)
    for r in range(4):
        for c in range(4):
            output_block[r + 4 * c] = state[r][c]
            
    return bytes(output_block)

def aes_decrypt_block(ciphertext_block: bytes, round_keys: list, verbose=False) -> bytes:
    """১৬ বাইটের একটি সাইফারটেক্সট ব্লককে ডিক্রিপ্ট করার ফাংশন"""
    Nr = len(round_keys) - 1
    state = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = ciphertext_block[r + 4 * c]
            
    add_round_key(state, round_keys[Nr])
    
    for i in range(Nr - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[i])
        inv_mix_columns(state)
        
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])
    
    output_block = bytearray(16)
    for r in range(4):
        for c in range(4):
            output_block[r + 4 * c] = state[r][c]
            
    return bytes(output_block)nd 1: After MixColumns")
        add_round_key(state, round_keys[i])
        if verbose and i == 1: print_state_matrix(state, "Round 1: After AddRoundKey")
        
    # --- Round 10 (Final Round) ---
    if verbose: print(f"\n==================== START ROUND 10 (Final Round) ====================")
    sub_bytes(state)
    if verbose: print_state_matrix(state, "Round 10: After SubBytes")
    shift_rows(state)
    if verbose: print_state_matrix(state, "Round 10: After ShiftRows")
    add_round_key(state, round_keys[10])
    if verbose: print_state_matrix(state, "Round 10: After Final AddRoundKey")
    
    output_block = bytearray(16)
    for r in range(4):
        for c in range(4):
            output_block[r + 4 * c] = state[r][c]
            
    return bytes(output_block)

def aes_decrypt_block(ciphertext_block: bytes, round_keys: list, verbose=False) -> bytes:
    """১৬ বাইটের একটি সাইফারটেক্সট ব্লককে ডিক্রিপ্ট করার ফাংশন"""
    state = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = ciphertext_block[r + 4 * c]
            
    add_round_key(state, round_keys[10])
    
    for i in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[i])
        inv_mix_columns(state)
        
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])
    
    output_block = bytearray(16)
    for r in range(4):
        for c in range(4):
            output_block[r + 4 * c] = state[r][c]
            
    return bytes(output_block)

# --- ECB Mode ---
def aes_encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    """পুরো প্লেইনটেক্সটকে PKCS#7 প্যাডিং করে ECB মোড অনুযায়ী এনক্রিপ্ট করার ফাংশন"""
    round_keys = key_expansion(key)
    padded_data = pad_pkcs7(plaintext)
    ciphertext = bytearray()
    
    # প্রতি ১৬ বাইটের ব্লককে স্বাধীনভাবে এনক্রিপ্ট করা
    for i in range(0, len(padded_data), 16):
        block = padded_data[i:i+16]
        cipher_block = aes_encrypt_block(block, round_keys, verbose=False)
        ciphertext.extend(cipher_block)
        
    return bytes(ciphertext)

def aes_decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """ECB মোডে এনক্রিপ্ট করা সাইফারটেক্সট ডিক্রিপ্ট করে আনপ্যাডিং করার ফাংশন"""
    round_keys = key_expansion(key)
    plaintext_padded = bytearray()
    
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        plain_block = aes_decrypt_block(block, round_keys, verbose=False)
        plaintext_padded.extend(plain_block)
        
    return unpad_pkcs7(bytes(plaintext_padded))


# --- CBC Mode ---
def aes_encrypt_cbc(plaintext: bytes, key: bytes) -> tuple:
    """র্যান্ডম IV তৈরি করে CBC চেইনিং নিয়মে এনক্রিপ্ট করার ফাংশন। রিটার্ন করে: (IV + Ciphertext)"""
    round_keys = key_expansion(key)
    padded_data = pad_pkcs7(plaintext)
    
    # ১৬ বাইটের ক্রিপ্টোগ্রাফিক্যালি স্ট্রং র্যান্ডম IV জেনারেট করা
    iv = os.urandom(16)
    ciphertext = bytearray(iv)  # অ্যাসাইনমেন্ট রুল: সাইফারটেক্সটের শুরুতে IV কনক্যাটিনেট থাকবে
    
    prev_block = iv
    for i in range(0, len(padded_data), 16):
        block = padded_data[i:i+16]
        # এনক্রিপশনের আগে কারেন্ট ব্লককে আগের সাইফার ব্লকের সাথে XOR করা
        xor_block = bytes(p ^ c for p, c in zip(block, prev_block))
        cipher_block = aes_encrypt_block(xor_block, round_keys, verbose=False)
        ciphertext.extend(cipher_block)
        prev_block = cipher_block
        
    return bytes(ciphertext)

def aes_decrypt_cbc(ciphertext: bytes, key: bytes) -> bytes:
    """CBC মোডের (IV + Ciphertext) ইনপুট থেকে ডিক্রিপ্ট করার ফাংশন"""
    round_keys = key_expansion(key)
    
    # প্রথম ১৬ বাইটকে IV হিসেবে আলাদা করা
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    plaintext_padded = bytearray()
    
    prev_block = iv
    for i in range(0, len(actual_ciphertext), 16):
        block = actual_ciphertext[i:i+16]
        decrypted_block = aes_decrypt_block(block, round_keys, verbose=False)
        # ডিক্রিপশনের পর আগের সাইফার ব্লকের সাথে XOR করে মূল প্লেইনটেক্সট উদ্ধার করা
        plain_block = bytes(d ^ p for d, p in zip(decrypted_block, prev_block))
        plaintext_padded.extend(plain_block)
        prev_block = block
        
    return unpad_pkcs7(bytes(plaintext_padded))


# # --- ৬. টেস্ট ড্রাইভার (PDF এর টেস্ট কেস দিয়ে ভেরিফিকেশন) ---
# if __name__ == "__main__":
#     print("================ AES-128 Step-by-Step Simulation ================")
    
#     # PDF থেকে নেওয়া অবিকল ইনপুট স্ট্রিং
#     key_ascii = "Thats my Kung Fu" # ১৬ ক্যারেক্টার
#     plaintext_ascii = "Two One Nine Two" # ১৬ ক্যারেক্টার
    
#     # বাইট ফর্মে রূপান্তর
#     key_bytes = key_ascii.encode('ascii')
#     plaintext_bytes = plaintext_ascii.encode('ascii')
    
#     print(f"Key (ASCII)        : {key_ascii}")
#     print(f"Key (HEX)          : {bytes_to_hex_str(key_bytes)}") # 54 68 61 74...
#     print(f"Plaintext (ASCII)  : {plaintext_ascii}")
#     print(f"Plaintext (HEX)    : {bytes_to_hex_str(plaintext_bytes)}") # 54 77 6F 20...
    
#     # স্টেপ ১: কী এক্সপেনশন রান করা
#     start_time = time.perf_counter()
#     all_round_keys = key_expansion(key_bytes)
#     key_schedule_time = (time.perf_counter() - start_time) * 1000
    
#     print(f"\nKey Schedule Execution Time: {key_schedule_time:.4f} ms")
    
#     # নোট: রাউন্ড কী-গুলো হেক্স ফরম্যাটে দেখতে চাইলে নিচের লুপটির কমেন্ট সরাতে পারো:
#     # for idx, key_matrix in enumerate(all_round_keys):
#     #     print_state_matrix(key_matrix, label=f"Round {idx} Key")
    
#     # স্টেপ ২: ব্লক এনক্রিপশন রান করা ও ইন্টারমিডিয়েট ভ্যালু চেক করা
#     print("\n--- Starting Block Encryption (Verification Mode) ---")
#     start_enc = time.perf_counter()
#     cipher_block = aes_encrypt_block(plaintext_bytes, all_round_keys)
#     encryption_time = (time.perf_counter() - start_enc) * 1000
    
#     print("\n--- Encryption Complete ---")
#     print(f"Final Ciphertext (HEX): {bytes_to_hex_str(cipher_block)}")
#     print(f"Encryption Execution Time: {encryption_time:.4f} ms")
#     # PDF Check: Page 17 এর ciphertext লাইনের সাথে আউটপুট মিলিয়ে দেখুন
#     # এক্সপেক্টেড সাইফারটেক্সট: 29 C3 50 5F 57 14 20 F6 40 22 99 B3 1A 02 D7 3A
    
#     # স্টেপ ৩: ব্লক ডিক্রিপশন রান করা ও ভেরিফাই করা
#     print("\n--- Starting Block Decryption (Verification Mode) ---")
#     start_dec = time.perf_counter()
#     decrypted_block = aes_decrypt_block(cipher_block, all_round_keys)
#     decryption_time = (time.perf_counter() - start_dec) * 1000
    
#     print("\n--- Decryption Complete ---")
#     print(f"Deciphered Text (HEX)  : {bytes_to_hex_str(decrypted_block)}")
    
#     # বাইটকে পুনরায় ASCII স্ট্রিংয়ে কনভার্ট করা
#     try:
#         decrypted_ascii = decrypted_block.decode('ascii')
#         print(f"Deciphered Text (ASCII): {decrypted_ascii}")
#     except Exception:
#         print("Deciphered Text (ASCII): [Decoding Error]")
        
#     print(f"Decryption Execution Time: {decryption_time:.4f} ms")
    
#     # চূড়ান্ত সমতা পরীক্ষা (Sanity Check)
#     if decrypted_block == plaintext_bytes:
#         print("\n[SUCCESS] Decryption Works Perfectly! Original Plaintext matches Decrypted Plaintext.")
#     else:
#         print("\n[ERROR] Decryption Mismatch! Check the Inverse Rounds or Core States.")

# --- ৬. টেস্ট ড্রাইভার (OFFICIAL SAMPLE IO FORMAT) ---
if __name__ == "__main__":
    # অফিশিয়াল ল্যাব স্যাম্পল টেস্ট কেসসমূহ (128, 192, 256 বিটের জন্য)
    keys = {
        128: "BUET CSE20 Batch",          # 16 bytes
        192: "BUET CSE20 Batch 2026",     # 24 bytes
        256: "BUET CSE20 Batch 2026!BUET" # 32 bytes
    }
    plaintext_ascii = "We need picnic"
    plaintext_bytes = plaintext_ascii.encode('ascii')
    
    for key_size, key_ascii in keys.items():
        key_bytes = key_ascii.encode('ascii')
        print(f"\n==================== AES-{key_size} / CBC ====================\n")
        print("Key:")
        print(f"In ASCII: {key_ascii}")
        print(f"In HEX: {bytes_to_hex_str(key_bytes)}\n")
        
        print("Plain Text:")
        print(f"In ASCII: {plaintext_ascii}")
        print(f"In HEX: {bytes_to_hex_str(plaintext_bytes)}")
        
        # প্যাডিং প্রদর্শন
        padded_bytes = pad_pkcs7(plaintext_bytes)
        padded_ascii_str = padded_bytes.decode('ascii', errors='replace').replace('\x02', '\\x02')
        print(f"In ASCII (After Padding): {padded_ascii_str}")
        print(f"In HEX (After Padding): {bytes_to_hex_str(padded_bytes)}\n")
        
        # --- ১. কী শিডিউল টাইমিং হিসাব ---
        start_ks = time.perf_counter()
        all_round_keys, Nr = key_expansion_generalized(key_bytes)
        key_schedule_time = (time.perf_counter() - start_ks) * 1000
        
        # --- ২. CBC এনক্রিপশন রান ও টাইমিং হিসাব ---
        start_enc = time.perf_counter()
        ciphertext_cbc = aes_encrypt_cbc(plaintext_bytes, key_bytes)
        encryption_time = (time.perf_counter() - start_enc) * 1000
        
        print("Ciphered Text:")
        print("(IV is the first 16 bytes, followed by the actual ciphertext)")
        print(f"In HEX: {bytes_to_hex_str(ciphertext_cbc)}")
        print(f"In ASCII: {ciphertext_cbc.decode('ascii', errors='replace')}\n")
        
        # --- ৩. CBC ডিক্রিপশন রান ও টাইমিং হিসাব ---
        start_dec = time.perf_counter()
        iv = ciphertext_cbc[:16]
        actual_ct = ciphertext_cbc[16:]
        raw_decrypted_padded = bytearray()
        prev_b = iv
        for i in range(0, len(actual_ct), 16):
            b = actual_ct[i:i+16]
            d_b = aes_decrypt_block(b, all_round_keys, verbose=False)
            raw_decrypted_padded.extend(bytes(d ^ p for d, p in zip(d_b, prev_b)))
            prev_b = b
            
        decrypted_plain = unpad_pkcs7(bytes(raw_decrypted_padded))
        decryption_time = (time.perf_counter() - start_dec) * 1000
        
        print("Deciphered Text:")
        print("Before Unpadding:")
        print(f"In HEX: {bytes_to_hex_str(bytes(raw_decrypted_padded))}")
        print(f"In ASCII: {bytes(raw_decrypted_padded).decode('ascii', errors='replace')}")
        
        print("After Unpadding:")
        print(f"In ASCII: {decrypted_plain.decode('ascii')}")
        print(f"In HEX: {bytes_to_hex_str(decrypted_plain)}\n")
        
        print("Execution Time Details:")
        print(f"Key Schedule Time: {key_schedule_time:.4f} ms")
        print(f"Encryption Time: {encryption_time:.4f} ms")
        print(f"Decryption Time: {decryption_time:.4f} ms")