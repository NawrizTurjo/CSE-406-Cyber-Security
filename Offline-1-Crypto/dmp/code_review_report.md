# Code Review Report: 2105032_*.py

This report provides a detailed idiomatic and security code review for the cryptography assignment files in [2105032](file:///e:/4-1%20Course%20Works/CSE-406-Cyber-Security/Offline-1-Crypto/2105032).

---

## Findings

| File | Code/Context | Issue | Why it matters | Suggested Fix |
|:---|:---|:---|:---|:---|
| **2105032_dh.py** | `random.seed(2105032)` (Line 6) | Global predictable seed | Using a static seed makes all generated primes, private keys, and public keys completely deterministic and predictable, defeating the purpose of cryptography. | Remove the hardcoded seed. Use Python's cryptographically secure `secrets` module instead of `random`. |
| **2105032_dh.py** | `random.randint(...)`, `random.getrandbits(...)` | Insecure pseudo-random number generator (PRNG) | The standard `random` module uses the Mersenne Twister algorithm, which is not cryptographically secure. An attacker observing outputs can predict future keys. | Use `secrets.randbits(k)` and `secrets.randbelow(n)` for security-sensitive random number generation. |
| **2105032_dh.py** | `def binpower(...)` (Lines 10-20) | Dead/Unused Code | The function `binpower` is defined but never called because `check_composite` uses Python's built-in `pow()` instead. | Remove `binpower` to reduce clutter. |
| **2105032_dh.py** / **2105032_alice.py** / **2105032_bob.py** | Inconsistent import and usage of `randint` | Multiple styles of importing and calling `randint` | Clutters the code and makes it harder to read or refactor. | Standardize imports. Ideally, import only the needed module and use it consistently. |
| **2105032_bob.py** | `conn.recv(4)` (Lines 72, 75) | TCP Socket streaming fragmentation bug | TCP is stream-oriented, and `recv(N)` is only guaranteed to return *up to* `N` bytes. It can return fewer, leading to truncated header fields and subsequent parser crashes. | Use the helper `recv_all(conn, 4)` to guarantee receiving the complete field. |
| **2105032_alice.py** / **2105032_bob.py** / **2105032_image.py** | `def derive_aes_key(s: int)` | Code Duplication | The exact same key derivation function is copy-pasted across three different files. | Move this utility function into a shared module like `2105032_AES.py` and import it. |
| **2105032_alice.py** / **2105032_bob.py** | `s_bytes[-16:]` or zero-padded `s` | Weak key derivation method | Slicing the raw bytes of a Diffie-Hellman shared secret is a crude key derivation method. The entropy of a DH shared secret may not be uniformly distributed. | Use a standard Key Derivation Function (KDF) like HKDF or PBKDF2 to derive secure keys. |
| **2105032_AES.py** | `xor_block` byte-by-byte double loop (Lines 340-342, 362-364) | Inefficient byte XORing | Flat 1D byte blocks are being accessed with 2D coordinates `r + 4 * c` inside a nested loop just to XOR them. This is slow and verbose. | Perform the XOR operation using a single line list comprehension or generator expression over the flat arrays. |
| **2105032_AES.py** | `normalise_key` zero-padding (Line 95) | Zero-padded short keys | Zero-padding short keys to fit AES size requirements lowers the key's entropy, making brute-force attacks significantly easier. | Reject short keys or derive a proper-length key using a KDF rather than zero-padding. |
| **2105032_AES.py** | Commented-out debug prints and obsolete functions | Clutter / Dead code | Commented-out lines like `optimized_gf_mult` (Lines 5-21) and print statements reduce readability. | Clean up commented-out debug code. Use proper logging modules if debug messages are needed dynamically. |
| **2105032_image.py** | `encrypted_pixels_ecb[:len(pixel_data)]` (Lines 39, 51) | Ciphertext Truncation | PKCS#7 padding adds up to 16 bytes of padding. Slicing the ciphertext to match the original size truncates the final block, making it cryptographically undecryptable. | Keep the padded ciphertext length and update the BMP file size headers, or use a stream mode (like CTR) that does not expand size. |
| **2105032_image.py** | `encrypted_pixels_cbc = encrypted_bytes_cbc[16:]` | CBC IV Discarded | Discarding the IV for CBC mode makes the first block of the image impossible to decrypt. | Preserve the IV (e.g., prepended to the ciphertext) for decryption. |

---

## Proposed Changes

To address these issues and make the code clean, robust, and idiomatic:

1. **Unify Shared Utilities**: Define `derive_aes_key` inside `2105032_AES.py` so that it doesn't need to be duplicated in Alice, Bob, and Image scripts.
2. **Solve TCP Fragmentation**: Replace all direct `conn.recv(...)` calls for fixed-size headers with `recv_all(conn, ...)` in both `2105032_alice.py` and `2105032_bob.py`.
3. **Crypto Security Upgrade**:
   - Swap the insecure standard `random` module with the cryptographically secure `secrets` module in `2105032_dh.py`, `2105032_alice.py`, and `2105032_bob.py`.
   - Remove `random.seed(...)` to ensure real randomness.
4. **Code Clean-up**:
   - Remove unused code (like `binpower` and `optimized_gf_mult`).
   - Clean up commented-out debugging code.
   - Refactor the verbose, nested XOR loop in `2105032_AES.py` into a Pythonic one-liner.
5. **Acknowledge BMP Constraints**: Note in the code comments of `2105032_image.py` that truncating padded ciphertext is done strictly for visualization purposes (keeping BMP size intact for image viewers) but breaks cryptographic decryption.

---

## Refactored and Simplified Code

Below are the idiomatic, cleaned-up versions of the files.

### 1. Refactored `2105032_AES.py`
We move `derive_aes_key` here, simplify the XOR operations, and clean up dead code.

```python
import time
import os
from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult

_GF_MULTIPLIERS = (0x01, 0x02, 0x03, 0x09, 0x0b, 0x0d, 0x0e)
GF_LUT = {
    multiplier: [gf_mult(multiplier, byte) for byte in range(256)]
    for multiplier in _GF_MULTIPLIERS
}

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

def normalise_key(key_bytes: bytes) -> bytes:
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
        return key_bytes[:target_len]
    return key_bytes.ljust(target_len, b'\x00')

def derive_aes_key(s: int) -> bytes:
    """Derive a 128-bit AES key from a DH shared secret."""
    num_bytes = max(1, (s.bit_length() + 7) // 8)
    s_bytes = s.to_bytes(num_bytes, byteorder='big')
    if len(s_bytes) >= 16:
        return s_bytes[-16:]
    return s_bytes.rjust(16, b'\x00')

def pad_pkcs7(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        raise ValueError("Empty Data")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError(f"Invalid PKCS#7 padding byte: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len): 
        raise ValueError("Inconsistent PKCS#7 padding")
    return data[:-pad_len]

def g_func(word, RCon_idx):
    # RotWord + SubWord + XOR Rcon
    word = word[1:] + word[:1]
    word = [Sbox[b] for b in word]
    word[0] ^= Rcon[RCon_idx]
    return word

def key_expansion(key_bytes: bytes) -> list:
    key_len = len(key_bytes)
    if key_len == 16:
        num_key_word, num_rounds = 4, 10
    elif key_len == 24:
        num_key_word, num_rounds = 6, 12
    elif key_len == 32:
        num_key_word, num_rounds = 8, 14
    else:
        raise ValueError("Invalid key length")
    
    total_words = 4 * (num_rounds + 1)
    words = [list(key_bytes[i*4 : i*4 + 4]) for i in range(num_key_word)]
    
    for i in range(num_key_word, total_words):
        prev_word = list(words[i-1])
        if i % num_key_word == 0:
            prev_word = g_func(prev_word, i // num_key_word)
        elif num_key_word == 8 and (i % num_key_word == 4):
            prev_word = [Sbox[b] for b in prev_word]
        
        word_i = [w_prev ^ w_k for w_prev, w_k in zip(words[i - num_key_word], prev_word)]
        words.append(word_i)
    
    round_keys = []
    for r_idx in range(num_rounds + 1):
        sliced_words = words[r_idx * 4 : r_idx * 4 + 4]
        matrix = [[sliced_words[c][r] for c in range(4)] for r in range(4)]
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
            state[r][c] = (GF_LUT[Mixer[r][0]][col[0]] ^
                           GF_LUT[Mixer[r][1]][col[1]] ^
                           GF_LUT[Mixer[r][2]][col[2]] ^
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
            state[r][c] = (GF_LUT[InvMixer[r][0]][col[0]] ^
                           GF_LUT[InvMixer[r][1]][col[1]] ^
                           GF_LUT[InvMixer[r][2]][col[2]] ^
                           GF_LUT[InvMixer[r][3]][col[3]])
            
def aes_encrypt_block(plaintext_block: bytes, round_keys: list, num_rounds: int) -> bytes:
    state = block_to_state(plaintext_block)
    add_round_key(state, round_keys[0])
    for i in range(1, num_rounds):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[i])
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[num_rounds])
    return state_to_block(state)

def aes_decrypt_block(ciphertext_block: bytes, round_keys: list, num_rounds: int) -> bytes:
    state = block_to_state(ciphertext_block)
    add_round_key(state, round_keys[num_rounds])
    for i in range(num_rounds - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[i])
        inv_mix_columns(state)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])
    return state_to_block(state)

def aes_encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    key = normalise_key(key)
    round_keys, num_rounds = key_expansion(key)
    padded_data = pad_pkcs7(plaintext)
    ciphertext = bytearray()
    for i in range(0, len(padded_data), 16):
        current_block = padded_data[i : i + 16]
        cipher_block = aes_encrypt_block(current_block, round_keys, num_rounds)
        ciphertext.extend(cipher_block)
    return bytes(ciphertext)

def aes_decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    key = normalise_key(key)
    round_keys, num_rounds = key_expansion(key)
    plaintext_padded = bytearray()
    for i in range(0, len(ciphertext), 16):
        current_block = ciphertext[i : i + 16]
        plain_block = aes_decrypt_block(current_block, round_keys, num_rounds)
        plaintext_padded.extend(plain_block)
    return unpad_pkcs7(bytes(plaintext_padded))

def aes_encrypt_cbc(plaintext: bytes, key: bytes) -> bytes:
    key = normalise_key(key)
    round_keys, num_rounds = key_expansion(key)
    padded_data = pad_pkcs7(plaintext)
    
    iv = os.urandom(16)
    ciphertext = bytearray(iv)  
    
    prev_block = iv
    for i in range(0, len(padded_data), 16):
        current_block = padded_data[i : i + 16]
        xor_block = bytes(b1 ^ b2 for b1, b2 in zip(current_block, prev_block))
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
        current_block = actual_ciphertext[i : i + 16]
        decrypted_block = aes_decrypt_block(current_block, round_keys, num_rounds)
        plain_block = bytes(b1 ^ b2 for b1, b2 in zip(decrypted_block, prev_block))
        plaintext_padded.extend(plain_block)
        prev_block = current_block
    return unpad_pkcs7(bytes(plaintext_padded))
```

### 2. Refactored `2105032_dh.py`
We replace `random` with `secrets` for real CSPRNG behaviour, remove `random.seed()`, clean up `binpower`, and restore parameter generation time tracking.

```python
import time
import secrets
from random import randint  # kept if needed for non-secure iter, but secrets preferred

def check_composite(n, a, d, s):
    x = pow(a, d, n)
    if x == 1 or x == (n - 1):
        return False
    for _ in range(s - 1):
        x = pow(x, 2, n)
        if x == (n - 1):
            return False
    return True

def miller_rabin(n, iter=40):
    if n < 4:
        return n == 2 or n == 3
    if n % 2 == 0:
        return False
    
    s = 0
    d = n - 1
    while (d & 1) == 0:
        d >>= 1
        s += 1
    
    for _ in range(iter):
        a = secrets.randbelow(n - 3) + 2  # Secure random integer in [2, n - 2]
        if check_composite(n, a, d, s):
            return False
    return True

def generate_prime(bit_length):
    while True:
        candidate = secrets.randbits(bit_length)
        candidate |= (1 << (bit_length - 1))  # force MSB=1
        candidate |= 1                        # force LSB=1
        if miller_rabin(candidate):
            return candidate

def generate_safe_prime(bit_length):
    while True:
        q = generate_prime(bit_length - 1)
        P = 2 * q + 1
        if miller_rabin(P):
            return P, q

def find_generator(P, q):
    while True:
        g = secrets.randbelow(P - 3) + 2  # Secure random integer in [2, P - 2]
        if pow(g, 2, P) != 1 and pow(g, q, P) != 1:
            return g

def generate_dh_parameters(bit_length):
    P, q = generate_safe_prime(bit_length)
    g = find_generator(P, q)
    return P, g

def run_dh_trial(bit_length):
    t_pg_start = time.perf_counter()
    P, g = generate_dh_parameters(bit_length)
    time_pg = (time.perf_counter() - t_pg_start) * 1000
    
    t0 = time.perf_counter()
    # K_a is secure random from [2^(bit_length-1), P-2]
    lower_bound = 2**(bit_length - 1)
    K_a = secrets.randbelow(P - 1 - lower_bound) + lower_bound
    A = pow(g, K_a, P)
    time_A = (time.perf_counter() - t0) * 1000
    
    t1 = time.perf_counter()
    K_b = secrets.randbelow(P - 1 - lower_bound) + lower_bound
    B = pow(g, K_b, P)
    time_B = (time.perf_counter() - t1) * 1000

    t2 = time.perf_counter()
    s_alice = pow(B, K_a, P)
    s_bob = pow(A, K_b, P)
    time_s = (time.perf_counter() - t2) * 1000

    assert s_alice == s_bob, "[ERROR] Shared secrets do not match!"
    return time_A, time_B, time_s, time_pg

if __name__ == "__main__":
    print("=" * 80)
    print("          Diffie-Hellman Performance Report")
    print("=" * 80)

    key_sizes = [128, 192, 256]
    num_trials = 5  # Safely scaled down as prime generation is slow without seed

    print(f"\n{'k (bits)':<10} | {'Time A (ms)':<15} | {'Time B (ms)':<15} | {'Time s (ms)':<15} | {'Time P,g (ms)':<15}")
    print("-" * 80)

    for k in key_sizes:
        totals = [0.0, 0.0, 0.0, 0.0]
        for _ in range(num_trials):
            tA, tB, ts, t_pg = run_dh_trial(k)
            totals[0] += tA
            totals[1] += tB
            totals[2] += ts
            totals[3] += t_pg

        avg = [t / num_trials for t in totals]
        print(f"{k:<10} | {avg[0]:<15.4f} | {avg[1]:<15.4f} | {avg[2]:<15.4f} | {avg[3]:<15.4f}")

    print("\n[SUCCESS] Diffie-Hellman key exchange verified and complete.")
```

### 3. Refactored `2105032_alice.py`
Uses `secrets`, fixes TCP `recv_all` for headers, imports `derive_aes_key` from `2105032_AES`.

```python
import socket
import importlib
import time
import secrets
import os

dh_mod = importlib.import_module("2105032_dh")
aes_mod = importlib.import_module("2105032_AES")

def recv_all(sock, length):
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(min(4096, length - len(buf)))
        if not chunk:
            raise ConnectionError("Socket closed before all data received")
        buf.extend(chunk)
    return bytes(buf)

def run_alice():
    host = '127.0.0.1'
    port = 65432
    
    print("==================== ALICE (SENDER) ====================\n")
    
    k_bits = 128
    print(f"[DH] Generating {k_bits}-bit parameters...")
    P, g = dh_mod.generate_dh_parameters(k_bits)
    
    lower_bound = 2**(k_bits - 1)
    K_a = secrets.randbelow(P - 1 - lower_bound) + lower_bound
    A = pow(g, K_a, P)
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[Socket] Connecting to Bob at {host}:{port}...")
    client_socket.connect((host, port))
    
    dh_payload = f"{P},{g},{A}"
    print("[DH] Sending P, g, and Public Key A to Bob...")
    client_socket.sendall(dh_payload.encode('ascii'))
    
    response = client_socket.recv(4096).decode('ascii')
    B = int(response)
    print(f"[DH] Received Public Key B from Bob: {B}")
    
    s = pow(B, K_a, P)
    aes_key = aes_mod.derive_aes_key(s)
    print(f"[Key Derived] Shared Secret computed successfully.")
    print(f"  Derived AES Key (HEX): {aes_mod.bytes_to_hex_str(aes_key)}\n")
    
    ready_signal = recv_all(client_socket, 5).decode('ascii')
    if ready_signal == "READY":
        print("[Status] Bob is READY for transmission.")
        
    mode = input("\nSend: (1) Text  (2) File: ").strip()
    
    if mode == "1":
        msg_type = b"TEXT"
        payload = input("Enter plaintext: ").encode('utf-8')
        filename_bytes = b""
    else:
        file_path = input("Enter file path: ").strip()
        if not os.path.exists(file_path):
            print(f"[ERROR] '{file_path}' File Not Found. Tearing Down Connection")
            client_socket.close()
            return
            
        msg_type = b"FILE"
        filename = os.path.basename(file_path).encode('utf-8')
        filename_bytes = filename
        with open(file_path, "rb") as f:
            payload = f.read()

    print("\n[AES] Encrypting using CBC mode...")
    time_s = time.perf_counter()
    ciphertext = aes_mod.aes_encrypt_cbc(payload, aes_key)
    encryption_time = (time.perf_counter() - time_s) * 1000
    print(f"Encryption time: {encryption_time:.4f} ms")

    if msg_type == b"FILE":
        encrypted_file_name = "encrypted_" + filename.decode('utf-8')
        with open(encrypted_file_name, "wb") as f_out:
            f_out.write(ciphertext)
        print(f"[Local] Encrypted payload saved as '{encrypted_file_name}'")

    name_len = len(filename_bytes)
    header = msg_type + name_len.to_bytes(4, 'big') + filename_bytes + len(ciphertext).to_bytes(10, 'big')
    
    print("[Socket] Sending structured protocol header...")
    client_socket.sendall(header)
    
    recv_all(client_socket, 4)  # Wait for ACK
    
    print("[Socket] Streaming encrypted payload...")
    client_socket.sendall(ciphertext)
    
    print(f"\n[SUCCESS] {msg_type.decode()} transmitted successfully!")
    client_socket.close()

if __name__ == "__main__":
    run_alice()
```

### 4. Refactored `2105032_bob.py`
Uses `secrets`, fixes TCP header parsing using `recv_all`, imports `derive_aes_key` from `2105032_AES`.

```python
import socket
import importlib
import secrets
import time

dh_mod = importlib.import_module("2105032_dh")
aes_mod = importlib.import_module("2105032_AES")

def recv_all(sock, length):
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(min(4096, length - len(buf)))
        if not chunk:
            raise ConnectionError("Socket closed before all data received")
        buf.extend(chunk)
    return bytes(buf)

def run_bob():
    host = '127.0.0.1'
    port = 65432
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)
    
    print("==================== BOB (RECEIVER / SERVER) ====================")
    print(f"[Socket] Waiting for Alice to connect on port {port}...\n")
    
    conn, addr = server_socket.accept()
    print(f"[Socket] Connected by Alice from {addr}")
    
    # Simple handshake framing: read up to a delimiter or standard buffer size
    data = conn.recv(4096).decode('ascii')
    P_str, g_str, A_str = data.split(',')
    P = int(P_str)
    g = int(g_str)
    A = int(A_str)
    
    k_bits = 128
    lower_bound = 2**(k_bits - 1)
    K_b = secrets.randbelow(P - 1 - lower_bound) + lower_bound
    B = pow(g, K_b, P)
    
    print("[DH] Sending Public Key B to Alice...")
    conn.sendall(str(B).encode('ascii'))
    
    s = pow(A, K_b, P)
    aes_key = aes_mod.derive_aes_key(s)
    print(f"[Key derived] Shared Secret computed successfully.")
    print(f"Derived AES Key (HEX): {aes_mod.bytes_to_hex_str(aes_key)}\n")
    
    conn.sendall("READY".encode('ascii'))

    print("[Socket] Waiting for transmission...")
    
    msg_type = recv_all(conn, 4).decode('ascii')
    name_len = int.from_bytes(recv_all(conn, 4), 'big')
    filename = recv_all(conn, name_len).decode('utf-8') if name_len > 0 else ""
    ct_len = int.from_bytes(recv_all(conn, 10), 'big')
    
    conn.sendall(b"ACK_")
    
    ciphertext = recv_all(conn, ct_len)
    print(f"[AES] CT (HEX Truncated): {aes_mod.bytes_to_hex_str(ciphertext[:32])} ...")
    
    time_s = time.perf_counter()
    decrypted = aes_mod.aes_decrypt_cbc(ciphertext, aes_key)
    decryption_time = (time.perf_counter() - time_s) * 1000
    print(f"Decryption Time: {decryption_time:.4f} ms")
    
    if msg_type == "TEXT":
        print("\n--- TRANSMISSION SUCCESS ---")
        print(f"Recovered Text (ASCII): {decrypted.decode('utf-8')}")
    else:
        out_name = "received_" + filename
        with open(out_name, "wb") as f:
            f.write(decrypted)
        print(f"\n--- TRANSMISSION SUCCESS ---")
        print(f"File saved: '{out_name}' ({len(decrypted)} bytes)")
    
    conn.close()
    server_socket.close()

if __name__ == "__main__":
    run_bob()
```

### 5. Refactored `2105032_image.py`
Cleaned up the duplicate KDF (now imports from `aes_mod`), added comments clarifying the visual-preservation padding constraint.

```python
import importlib
import time
aes_mod = importlib.import_module("2105032_AES")

def encrypt_image_bonus(input_bmp_path, key_bytes):
    with open(input_bmp_path, "rb") as f:
        full_image_bytes = f.read()
        
    offset = int.from_bytes(full_image_bytes[10:14], 'little')
    header = full_image_bytes[:offset]
    pixel_data = full_image_bytes[offset:]
    
    print("[ECB] Encrypting image pixels...")
    ecb_time_s = time.perf_counter()
    encrypted_pixels_ecb = aes_mod.aes_encrypt_ecb(pixel_data, key_bytes)
    ecb_time_e = time.perf_counter()
    
    with open("encrypted_ecb.bmp", "wb") as f:
        # Note: Ciphertext is sliced to preserve visual metadata bounds,
        # but this is not cryptographically decryptable unless padded length is preserved.
        f.write(header + encrypted_pixels_ecb[:len(pixel_data)])
        
    print("[CBC] Encrypting image pixels...")
    cbc_time_s = time.perf_counter()
    encrypted_bytes_cbc = aes_mod.aes_encrypt_cbc(pixel_data, key_bytes)
    cbc_time_e = time.perf_counter()
    
    # CBC ciphertext includes 16 bytes IV at the start
    encrypted_pixels_cbc = encrypted_bytes_cbc[16:]
    
    with open("encrypted_cbc.bmp", "wb") as f:
        f.write(header + encrypted_pixels_cbc[:len(pixel_data)])
        
    print("[SUCCESS] ECB and CBC images generated successfully.")

    ecb_time = (cbc_time_e - cbc_time_s) * 1000
    cbc_time = (cbc_time_e - cbc_time_s) * 1000
    return ecb_time, cbc_time

def main():
    image_path = input("Enter BMP image path: ").strip()
    shared_secret = input("Enter shared secret: ")

    try:
        num = int(shared_secret)
        key_bytes = aes_mod.derive_aes_key(num)
    except ValueError:
        key_bytes = shared_secret.encode('utf-8')
    
    ecb_time, cbc_time = encrypt_image_bonus(image_path, key_bytes)
    print(f"ECB encryption time: {ecb_time:.2f} ms")
    print(f"CBC encryption time: {cbc_time:.2f} ms")

if __name__ == "__main__":
    main()
```

---

## Notes
- **PrNG reproducibility trade-off**: Changing standard `random` to `secrets` ensures cryptographic security but removes deterministic output replication from a fixed seed. If grading tests require deterministic key sequences, `random.seed(2105032)` should be kept but noted as a security vulnerability.
- **Visual vs. Functional Decryptability in BMP**: The slicing `[:len(pixel_data)]` is necessary to ensure the resulting `.bmp` files open correctly in standard image viewers without file layout errors, but the last block cannot be decrypted back to plaintext.
