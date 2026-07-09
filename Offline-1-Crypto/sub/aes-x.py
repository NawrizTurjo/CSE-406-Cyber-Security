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

def g_func(word, iter):
    
    # 1. RotWord
    word = word[1:] + word[:1] # [a,b,c,d] => [b,c,d,a]
    # 2.SubWord
    word = [Sbox[b] for b in word] # [a,b,c,d] => [Sbox[a], Sbox[b], Sbox[c], Sbox[d]]
    # 3.XOR Rcon
    word[0] = word[0] ^ Rcon[iter//4] # 

    return word

def key_expansion(key_bytes: bytes) -> list:
    
    words = [] # 4 bytes per word

    for i in range(0,4):
        # first 4 ta word copy korbo round key er jonne
        words.append(list(key_bytes[i*4 : i*4 + 4]))
    
    # baki 40 tar jonno
    for i in range (4,44):
        prev_word = list(words[i-1]) # keep previous ones

        if i % 4 == 0:
            # # 1. RotWord
            # prev_word = prev_word[1:] + prev_word[:1] 
            # # 2.SubWord
            # prev_word = [Sbox[b] for b in prev_word] 
            # # 3.XOR RCon
            # prev_word[0] = prev_word[0] ^ Rcon[i // 4]
            prev_word = g_func(prev_word, i)
        
        word_i = []
        # all words will be xor-ed
        for j in range(4):
            word_i.append(words[i-4][j] ^ prev_word[j])
        
        words.append(word_i)
    
    for i in range(44):
        print(f"Word {i}: {bytes_to_hex_str(words[i])}")

    
    round_keys = []
    for r_idx in range(11):
        sliced_words = words[r_idx * 4 : r_idx * 4 + 4]
        matrix = [[0]*4 for _ in range(4)]
        for c in range(4):
            # each word as column of the matrix (like word_0 goes to col_0)
            word = sliced_words[c]
            for r in range(4):
                matrix[r][c] = word[r]
        round_keys.append(matrix)
    
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
    """রো ১, ২, ৩ কে যথাক্রমে ১, ২, ৩ বাইট ডানে সার্কুলার শিফট করা (এনক্রিপশনের উল্টো)"""
    state[1] = state[1][-1:] + state[1][:-1]  # ডানে ১ বাইট শিফট
    state[2] = state[2][-2:] + state[2][:-2]  # ডানে ২ বাইট শিফট
    state[3] = state[3][-3:] + state[3][:-3]  # ডানে ৩ বাইট শিফট

def inv_mix_columns(state):
    """gf_mult এবং InvMixer ম্যাট্রিক্স ব্যবহার করে ইনভার্স কলাম মিক্সিং করা"""
    for c in range(4):
        # কলাম c এর জন্য ইনভার্স ম্যাট্রিক্স মাল্টিপ্লিকেশন
        s0 = gf_mult(InvMixer[0][0], state[0][c]) ^ gf_mult(InvMixer[0][1], state[1][c]) ^ gf_mult(InvMixer[0][2], state[2][c]) ^ gf_mult(InvMixer[0][3], state[3][c])
        s1 = gf_mult(InvMixer[1][0], state[0][c]) ^ gf_mult(InvMixer[1][1], state[1][c]) ^ gf_mult(InvMixer[1][2], state[2][c]) ^ gf_mult(InvMixer[1][3], state[3][c])
        s2 = gf_mult(InvMixer[2][0], state[0][c]) ^ gf_mult(InvMixer[2][1], state[1][c]) ^ gf_mult(InvMixer[2][2], state[2][c]) ^ gf_mult(InvMixer[2][3], state[3][c])
        s3 = gf_mult(InvMixer[3][0], state[0][c]) ^ gf_mult(InvMixer[3][1], state[1][c]) ^ gf_mult(InvMixer[3][2], state[2][c]) ^ gf_mult(InvMixer[3][3], state[3][c])
        state[0][c], state[1][c], state[2][c], state[3][c] = s0, s1, s2, s3

def aes_encrypt(plaintext_block: bytes, round_keys: list) -> bytes:
    

if __name__ == "__main__":

    # -----------------------------
    # Example plaintext and key
    # -----------------------------
    plaintext = b"Hello AES World!"
    key = b"Thats my Kung Fu"   # Exactly 16 bytes

    print("=" * 60)
    print("AES DEMO")
    print("=" * 60)

    print(f"\nPlaintext : {plaintext}")
    print(f"Key       : {key}")

    print("\nPlaintext (HEX):")
    print(bytes_to_hex_str(plaintext))

    print("\nKey (HEX):")
    print(bytes_to_hex_str(key))

    # =====================================================
    # PKCS#7 Padding
    # =====================================================
    print("\n" + "=" * 60)
    print("PKCS#7 PADDING")
    print("=" * 60)

    padded = pad_pkcs7(plaintext)

    print(f"Original Length : {len(plaintext)} bytes")
    print(f"Padded Length   : {len(padded)} bytes")

    print("\nPadded Data (HEX):")
    print(bytes_to_hex_str(padded))

    # =====================================================
    # Unpadding
    # =====================================================
    print("\n" + "=" * 60)
    print("PKCS#7 UNPADDING")
    print("=" * 60)

    unpadded = unpad_pkcs7(padded)

    print("Recovered Plaintext:")
    print(unpadded)

    # =====================================================
    # Key Expansion
    # =====================================================
    print("\n" + "=" * 60)
    print("KEY EXPANSION")
    print("=" * 60)

    round_keys = key_expansion(key)

    print(f"\nTotal Round Keys Generated: {len(round_keys)}")

    for i, rk in enumerate(round_keys):
        print_state_matrix(rk, f"Round Key {i}")

    print("\nDone!")
