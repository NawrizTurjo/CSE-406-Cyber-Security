import time
import os
# aes_helpers.py থেকে প্রয়োজনীয় জিনিসগুলো ইম্পোর্ট করা হলো
from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult

def gf_mult(a,b):
    """
        A fast galois field multiplication implementation since Bitvector performs slow in complex tasks
        source: https://gist.github.com/meagtan/dc1adff8d84bb895891d8fd027ec9d8c
    """
    min_poly  = 0x11B
    res = 0
    while b:
        if (b & 1):
            res^=a
        if (a & 0x80):
            a = (a << 1) ^ min_poly
        else:
            a <<= 1
        b >>= 1
    return res


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
        raise ValueError("State must be a 4×4 matrix.")

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


# --- ২. প্যাডিং (PKCS#7) ---
def pad_pkcs7(data: bytes) -> bytes:
    """মেসেজকে ১৬ বাইটের মাল্টিপল বানানোর জন্য PKCS#7 প্যাডিং যোগ করার ফাংশন"""
    pad_len = 16 - (len(data) % 16)
    padding = bytes([pad_len] * pad_len) # pad_len num of padding bytes nibo
    return data + padding 

def unpad_pkcs7(data: bytes) -> bytes:
    """ডিক্রিপশনের পর প্যাডিং রিমুভ করার ফাংশน"""
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


# --- ৩. কী এক্সপেনশন (Key Schedule) ---

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
        col = [state[r][c] for r in range(4)]
        for r in range(4):
            state[r][c] = (gf_mult(Mixer[r][0], col[0])^
                            gf_mult(Mixer[r][1], col[1])^
                            gf_mult(Mixer[r][2], col[2])^
                            gf_mult(Mixer[r][3], col[3]))

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
    """রো ১, ২, ৩ কে যথাক্রমে ১, ২, ৩ বাইট ডানে সার্কুলার শিফট করা (এনক্রিপশনের উল্টো)"""
    state[1] = state[1][-1:] + state[1][:-1]  # ডানে ১ বাইট শিফট
    state[2] = state[2][-2:] + state[2][:-2]  # ডানে ২ বাইট শিফট
    state[3] = state[3][-3:] + state[3][:-3]  # ডানে ৩ বাইট শিফট

def inv_mix_columns(state):
    """gf_mult এবং InvMixer ম্যাট্রিক্স ব্যবহার করে ইনভার্স কলাম মিক্সিং করা"""
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        for r in range(4):
            state[r][c] = (gf_mult(InvMixer[r][0], col[0])^
                            gf_mult(InvMixer[r][1], col[1])^
                            gf_mult(InvMixer[r][2], col[2])^
                            gf_mult(InvMixer[r][3], col[3]))
            


# --- ৫. মূল ব্লক এনক্রিপশন (১ ব্লক = ১৬ বাইট) ---
def aes_encrypt_block(plaintext_block: bytes, round_keys: list, num_rounds: int) -> bytes:
    """১৬ বাইটের একটি ব্লককে ধাপে ধাপে প্রিন্ট করে এনক্রিপ্ট করার ফাংশন"""
    
    # কলাম-মেজর অর্ডারে স্টেট ম্যাট্রিক্স ইনিশিয়ালাইজ করা
    # state = [[0]*4 for _ in range(4)]
    # for r in range(4):
    #     for c in range(4):
    #         state[r][c] = plaintext_block[r + 4 * c]
    state = block_to_state(plaintext_block)
            
    # print_state_matrix(state, "Original Plaintext State Matrix")
    
    # --- Round 0 (Pre-round) ---
    add_round_key(state, round_keys[0])
    # print_state_matrix(state, "State After Round 0 (AddRoundKey)")
    # PDF Check: এই ম্যাট্রিক্সটি পিডিএফ-এর Page 4 এর "new State Matrix"-এর সাথে মিলবে
    
    # --- Round 1 to 9 ---
    for i in range(1, num_rounds):
        # print(f"\n==================== START ROUND {i} ====================")
        
        sub_bytes(state)
        # if i == 1: print_state_matrix(state, "Round 1: After SubBytes") 
        # PDF Check: পিডিএফ Page 5 এর ম্যাট্রিক্সের সাথে মিলবে
        
        shift_rows(state)
        # if i == 1: print_state_matrix(state, "Round 1: After ShiftRows")
        # PDF Check: পিডিএফ Page 6 এর ম্যাট্রিক্সের সাথে মিলবে
        
        mix_columns(state)
        # if i == 1: print_state_matrix(state, "Round 1: After MixColumns")
        # PDF Check: পিডিএফ Page 7 এর ম্যাট্রিক্সের সাথে মিলবে
        
        add_round_key(state, round_keys[i])
        # if i == 1: print_state_matrix(state, "Round 1: After AddRoundKey")
        # PDF Check: পিডিএফ Page 8 এর ম্যাট্রিক্সের সাথে মিলবে
        
    # --- Round 10 (Final Round - No MixColumns) ---
    # print(f"\n==================== START ROUND 10 (Final Round) ====================")
    sub_bytes(state)
    # print_state_matrix(state, "Round 10: After SubBytes")
    
    shift_rows(state)
    # print_state_matrix(state, "Round 10: After ShiftRows")
    # PDF Check: পিডিএফ Page 17 এর প্রথম ম্যাট্রিক্সের সাথে মিলবে
    
    add_round_key(state, round_keys[num_rounds])
    # print_state_matrix(state, "Round 10: After Final AddRoundKey")
    # PDF Check: পিডিএফ Page 17 এর দ্বিতীয় ম্যাট্রিক্সের সাথে মিলবে (Ciphertext)
    
    # স্টেট ম্যাট্রিক্সকে পুনরায় ১৬-বাইটের ফ্ল্যাট লিনিয়ার বাইট অ্যারেতে রূপান্তর
    # output_block = bytearray(16)
    # for r in range(4):
    #     for c in range(4):
    #         output_block[r + 4 * c] = state[r][c]
    output_block = state_to_block(state)
            
    return output_block

def aes_decrypt_block(ciphertext_block: bytes, round_keys: list, num_rounds: int) -> bytes:
    """১৬ বাইটের একটি সাইফারটেক্সট ব্লককে ডিক্রিপ্ট করার ফাংশন"""
    
    # কলাম-মেজর অর্ডারে স্টেট ম্যাট্রিক্স ইনিশিয়ালাইজ করা
    # state = [[0]*4 for _ in range(4)]
    # for r in range(4):
    #     for c in range(4):
    #         state[r][c] = ciphertext_block[r + 4 * c]
    state = block_to_state(ciphertext_block)
            
    # --- Initial Round: AddRoundKey (Round 10 Key ব্যবহার করে) ---
    add_round_key(state, round_keys[num_rounds])
    
    # --- Round 9 থেকে 1 পর্যন্ত উল্টো লুপ ---
    for i in range(num_rounds-1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[i])
        inv_mix_columns(state)
        
    # --- Final Round: (Round 0 Key এর জন্য, যেখানে InvMixColumns হবে না) ---
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])
    
    # স্টেট ম্যাট্রিক্সকে পুনরায় ১৬-বাইটের ফ্ল্যাট বাইট অ্যারেতে রূপান্তর
    # output_block = bytearray(16)
    # for r in range(4):
    #     for c in range(4):
    #         output_block[r + 4 * c] = state[r][c]
    output_block = state_to_block(state)
            
    return output_block

# --- ECB Mode ---
def aes_encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    """পুরো প্লেইনটেক্সটকে PKCS#7 প্যাডিং করে ECB মোড অনুযায়ী এনক্রিপ্ট করার ফাংশন"""
    key = normalise_key(key)
    round_keys, num_rounds = key_expansion(key)
    padded_data = pad_pkcs7(plaintext)
    ciphertext = bytearray()
    
    # প্রতি ১৬ বাইটের ব্লককে স্বাধীনভাবে এনক্রিপ্ট করা
    for i in range(0, len(padded_data), 16):
        current_block = padded_data[i:i+16]
        cipher_block = aes_encrypt_block(current_block, round_keys, num_rounds)
        ciphertext.extend(cipher_block)
        
    return bytes(ciphertext)

def aes_decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """ECB মোডে এনক্রিপ্ট করা সাইফারটেক্সট ডিক্রিপ্ট করে আনপ্যাডিং করার ফাংশন"""
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
    """র্যান্ডম IV তৈরি করে CBC চেইনিং নিয়মে এনক্রিপ্ট করার ফাংশন। রিটার্ন করে: (IV + Ciphertext)"""
    key = normalise_key(key)
    round_keys, num_rounds = key_expansion(key)
    padded_data = pad_pkcs7(plaintext)
    
    # ১৬ বাইটের ক্রিপ্টোগ্রাফিক্যালি স্ট্রং র্যান্ডম IV জেনারেট করা
    iv = os.urandom(16)
    ciphertext = bytearray(iv)  # অ্যাসাইনমেন্ট রুল: সাইফারটেক্সটের শুরুতে IV কনক্যাটিনেট থাকবে
    
    prev_block = iv
    for i in range(0, len(padded_data), 16):
        current_block = padded_data[i:i+16]
        # এনক্রিপশনের আগে কারেন্ট ব্লককে আগের সাইফার ব্লকের সাথে XOR করা
        # xor_block = bytes(p ^ c for p, c in zip(current_block, prev_block))
        xor_block = bytearray(16)
        for r in range(4):
            for c in range(4):
                xor_block[r + 4 * c] = current_block[r + 4 * c] ^ prev_block[r + 4 * c]
        cipher_block = aes_encrypt_block(xor_block, round_keys, num_rounds)
        ciphertext.extend(cipher_block)
        prev_block = cipher_block
        
    return bytes(ciphertext)

def aes_decrypt_cbc(ciphertext: bytes, key: bytes) -> bytes:
    """CBC মোডের (IV + Ciphertext) ইনপুট থেকে ডিক্রিপ্ট করার ফাংশন"""
    key = normalise_key(key)
    round_keys, num_rounds = key_expansion(key)
    
    # প্রথম ১৬ বাইটকে IV হিসেবে আলাদা করা
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    plaintext_padded = bytearray()
    
    prev_block = iv
    for i in range(0, len(actual_ciphertext), 16):
        current_block = actual_ciphertext[i:i+16]
        decrypted_block = aes_decrypt_block(current_block, round_keys, num_rounds)
        # ডিক্রিপশনের পর আগের সাইফার ব্লকের সাথে XOR করে মূল প্লেইনটেক্সট উদ্ধার করা
        # plain_block = bytes(d ^ p for d, p in zip(decrypted_block, prev_block))
        plain_block = bytearray(16)
        for r in range(4):
            for c in range(4):
                plain_block[r + 4 * c] = decrypted_block[r + 4 * c] ^ prev_block[r + 4 * c]
        plaintext_padded.extend(plain_block)
        prev_block = current_block
        
    return unpad_pkcs7(bytes(plaintext_padded))


# --- ৭. উন্নত টেস্ট ড্রাইভার (ECB & CBC for 128, 192, 256 bits) ---
if __name__ == "__main__":
    plaintext_ascii = "We need picnic to celebrate our crypto system success!"
    plaintext_bytes = plaintext_ascii.encode('utf-8')
    
    # ৩টি ভিন্ন সাইজের টেস্ট কী (১৬, ২৪ এবং ৩২ বাইট)
    test_cases = [
        {"name": "AES-128", "key": b"BUET CSE20 Batch"},
        {"name": "AES-192", "key": b"BUET CSE20 Batch 192BitK"},
        {"name": "AES-256", "key": b"BUET CSE20 Batch 256BitKeySecure"}
    ]
    
    print("============================================================")
    print("         AES MULTI-VARIATION & MULTI-MODE TESTER            ")
    print("============================================================\n")
    print(f"Original Plaintext: {plaintext_ascii}")
    print(f"Plaintext (HEX)   : {bytes_to_hex_str(plaintext_bytes)}\n")
    
    for case in test_cases:
        name = case["name"]
        key = case["key"]
        
        print("=" * 60)
        print(f"              🚀 TESTING VARIATION: {name}              ")
        print("=" * 60)
        print(f"Key (ASCII): {key.decode('ascii')}")
        print(f"Key (HEX)  : {bytes_to_hex_str(key)}\n")
        
        # ----------------------------- ECB MODE TEST -----------------------------
        print(f"--- [{name} / ECB Mode] ---")
        start_ks = time.perf_counter()
        round_keys, num_rounds = key_expansion(key)
        ks_time = (time.perf_counter() - start_ks) * 1000
        
        start_enc = time.perf_counter()
        ct_ecb = aes_encrypt_ecb(plaintext_bytes, key)
        enc_time = (time.perf_counter() - start_enc) * 1000
        
        start_dec = time.perf_counter()
        dt_ecb = aes_decrypt_ecb(ct_ecb, key)
        dec_time = (time.perf_counter() - start_dec) * 1000
        
        print(f"Ciphertext (HEX): {bytes_to_hex_str(ct_ecb[:32])} ... [Truncated]")
        print(f"Decrypted Text  : {dt_ecb.decode('utf-8')}")
        print(f"Execution Times : Key Schedule: {ks_time:.4f}ms | Encrypt: {enc_time:.4f}ms | Decrypt: {dec_time:.4f}ms")
        print(f"Sanity Check    : {'✔️ MATCHED' if dt_ecb == plaintext_bytes else '❌ MISMATCH'}\n")
        
        # ----------------------------- CBC MODE TEST -----------------------------
        print(f"--- [{name} / CBC Mode] ---")
        start_enc = time.perf_counter()
        ct_cbc = aes_encrypt_cbc(plaintext_bytes, key)
        enc_time = (time.perf_counter() - start_enc) * 1000
        
        start_dec = time.perf_counter()
        dt_cbc = aes_decrypt_cbc(ct_cbc, key)
        dec_time = (time.perf_counter() - start_dec) * 1000
        
        print(f"Ciphertext (HEX): {bytes_to_hex_str(ct_cbc[:32])} ... [Truncated]")
        print(f"Decrypted Text  : {dt_cbc.decode('utf-8')}")
        print(f"Execution Times : Encrypt (with IV): {enc_time:.4f}ms | Decrypt: {dec_time:.4f}ms")
        print(f"Sanity Check    : {'✔️ MATCHED' if dt_cbc == plaintext_bytes else '❌ MISMATCH'}\n")
        
    print("============================================================")
    print("          ALL TEST VARIATIONS COMPLETED SUCCESSFULLY         ")
    print("============================================================")

# # --- ৬. টেস্ট ড্রাইভার (OFFICIAL SAMPLE IO FORMAT) ---
# if __name__ == "__main__":
#     # অফিশিয়াল ল্যাব স্যাম্পল টেস্ট কেস
#     key_ascii = "BUET CSE20 Batch"
#     plaintext_ascii = "We need picnic"
    
#     key_bytes = key_ascii.encode('ascii')
#     plaintext_bytes = plaintext_ascii.encode('ascii')
    
#     print("==================== AES / CBC ====================\n")
#     print("Key:")
#     print(f"In ASCII: {key_ascii}")
#     print(f"In HEX: {bytes_to_hex_str(key_bytes)}\n")
    
#     print("Plain Text:")
#     print(f"In ASCII: {plaintext_ascii}")
#     print(f"In HEX: {bytes_to_hex_str(plaintext_bytes)}")
    
#     # প্যাডিং প্রদর্শন
#     padded_bytes = pad_pkcs7(plaintext_bytes)
#     # প্রিন্ট করার জন্য সেফ ASCII রিপ্রেজেন্টেশন (নন-প্রিন্টেবেল ক্যারেক্টার হ্যান্ডেল করা)
#     padded_ascii_str = padded_bytes.decode('ascii', errors='replace').replace('\x02', '\\x02')
#     print(f"In ASCII (After Padding): {padded_ascii_str}")
#     print(f"In HEX (After Padding): {bytes_to_hex_str(padded_bytes)}\n")
    
#     # --- ১. কী শিডিউল টাইমিং হিসাব ---
#     start_ks = time.perf_counter()
#     all_round_keys = key_expansion(key_bytes)
#     key_schedule_time = (time.perf_counter() - start_ks) * 1000
    
#     # --- ২. CBC এনক্রিপশন রান ও টাইমিং হিসাব ---
#     start_enc = time.perf_counter()
#     ciphertext_cbc = aes_encrypt_cbc(plaintext_bytes, key_bytes)
#     encryption_time = (time.perf_counter() - start_enc) * 1000
    
#     print("Ciphered Text:")
#     print("(IV is the first 16 bytes, followed by the actual ciphertext)")
#     print(f"In HEX: {bytes_to_hex_str(ciphertext_cbc)}")
#     # বাইনারি সাইফারকে সেফ স্ট্রিং রিপ্রেজেন্টেশনে প্রিন্ট করা
#     print(f"In ASCII: {ciphertext_cbc.decode('ascii', errors='replace').replace('\ufffd', '?')}\n")
    
#     # --- ৩. CBC ডিক্রিপশন রান ও টাইমিং হিসাব ---
#     start_dec = time.perf_counter()
#     # আনপ্যাডিং ছাড়া র ডেটা ভেরিফিকেশনের জন্য ডিক্রিপশনের ভেতরের অংশটুকু এক্সপোজ করা হলো ড্রাইভারের খাতিরে:
#     iv = ciphertext_cbc[:16]
#     actual_ct = ciphertext_cbc[16:]
#     raw_decrypted_padded = bytearray()
#     prev_b = iv
#     for i in range(0, len(actual_ct), 16):
#         b = actual_ct[i:i+16]
#         d_b = aes_decrypt_block(b, all_round_keys)
#         raw_decrypted_padded.extend(bytes(d ^ p for d, p in zip(d_b, prev_b)))
#         prev_b = b
        
#     decrypted_plain = unpad_pkcs7(bytes(raw_decrypted_padded))
#     decryption_time = (time.perf_counter() - start_dec) * 1000
    
#     print("Deciphered Text:")
#     print("Before Unpadding:")
#     print(f"In HEX: {bytes_to_hex_str(bytes(raw_decrypted_padded))}")
#     print(f"In ASCII: {bytes(raw_decrypted_padded).decode('ascii', errors='replace')}")
    
#     print("After Unpadding:")
#     print(f"In ASCII: {decrypted_plain.decode('ascii')}")
#     print(f"In HEX: {bytes_to_hex_str(decrypted_plain)}\n")
    
#     print("Execution Time Details:")
#     print(f"Key Schedule Time: {key_schedule_time} ms")
#     print(f"Encryption Time: {encryption_time} ms")
#     print(f"Decryption Time: {decryption_time} ms")

# # --- ৬. টেস্ট ড্রাইভার (OFFICIAL SAMPLE IO FORMAT - ECB MODE) ---
# if __name__ == "__main__":
#     # অফিশিয়াল ল্যাব স্যাম্পল টেস্ট কেস
#     key_ascii = "BUET CSE20 Batch"
#     plaintext_ascii = "We need picnic"
    
#     key_bytes = key_ascii.encode('ascii')
#     plaintext_bytes = plaintext_ascii.encode('ascii')
    
#     print("==================== AES / ECB ====================\n")
#     print("Key:")
#     print(f"In ASCII: {key_ascii}")
#     print(f"In HEX: {bytes_to_hex_str(key_bytes)}\n")
    
#     print("Plain Text:")
#     print(f"In ASCII: {plaintext_ascii}")
#     print(f"In HEX: {bytes_to_hex_str(plaintext_bytes)}")
    
#     # প্যাডিং প্রদর্শন
#     padded_bytes = pad_pkcs7(plaintext_bytes)
#     # প্রিন্ট করার জন্য সেফ ASCII রিপ্রেজেন্টেশন (নন-প্রিন্টেবেল ক্যারেক্টার হ্যান্ডেল করা)
#     padded_ascii_str = padded_bytes.decode('ascii', errors='replace').replace('\x02', '\\x02')
#     print(f"In ASCII (After Padding): {padded_ascii_str}")
#     print(f"In HEX (After Padding): {bytes_to_hex_str(padded_bytes)}\n")
    
#     # --- ১. কী শিডিউল টাইমিং হিসাব ---
#     start_ks = time.perf_counter()
#     all_round_keys = key_expansion(key_bytes)
#     key_schedule_time = (time.perf_counter() - start_ks) * 1000
    
#     # --- ২. ECB এনক্রিপশন রান ও টাইমিং হিসাব ---
#     start_enc = time.perf_counter()
#     ciphertext_ecb = aes_encrypt_ecb(plaintext_bytes, key_bytes)
#     encryption_time = (time.perf_counter() - start_enc) * 1000
    
#     print("Ciphered Text:")
#     print(f"In HEX: {bytes_to_hex_str(ciphertext_ecb)}")
#     # বাইনারি সাইফারকে সেফ স্ট্রিং রিপ্রেজেন্টেশনে প্রিন্ট করা (.replace('\ufffd', '?') দিয়ে উইন্ডোজ টার্মিনালে UnicodeEncodeError রোধ করা হয়েছে)
#     safe_ascii_ct = ciphertext_ecb.decode('ascii', errors='replace').replace('\ufffd', '?')
#     print(f"In ASCII: {safe_ascii_ct}\n")
    
#     # --- ৩. ECB ডিক্রিপশন রান ও টাইমিং হিসাব ---
#     start_dec = time.perf_counter()
#     # আনপ্যাডিং ছাড়া র ডেটা ভেরিফিকেশনের জন্য ডিক্রিপশনের ভেতরের অংশটুকু এক্সপোজ করা হলো ড্রাইভারের খাতিরে:
#     raw_decrypted_padded = bytearray()
#     for i in range(0, len(ciphertext_ecb), 16):
#         b = ciphertext_ecb[i:i+16]
#         d_b = aes_decrypt_block(b, all_round_keys)
#         raw_decrypted_padded.extend(d_b)
        
#     decrypted_plain = unpad_pkcs7(bytes(raw_decrypted_padded))
#     decryption_time = (time.perf_counter() - start_dec) * 1000
    
#     print("Deciphered Text:")
#     print("Before Unpadding:")
#     print(f"In HEX: {bytes_to_hex_str(bytes(raw_decrypted_padded))}")
#     print(f"In ASCII: {bytes(raw_decrypted_padded).decode('ascii', errors='replace').replace('\ufffd', '?')}")
    
#     print("After Unpadding:")
#     print(f"In ASCII: {decrypted_plain.decode('ascii')}")
#     print(f"In HEX: {bytes_to_hex_str(decrypted_plain)}\n")
    
#     print("Execution Time Details:")
#     print(f"Key Schedule Time: {key_schedule_time} ms")
#     print(f"Encryption Time: {encryption_time} ms")
#     print(f"Decryption Time: {decryption_time} ms")
