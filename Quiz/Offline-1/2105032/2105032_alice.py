import socket
import importlib
import time
import random
import os

dh_mod = importlib.import_module("2105032_dh")
aes_mod = importlib.import_module("2105032_AES")

def derive_aes_key(s: int) -> bytes:

    num_bytes = max (1, (s.bit_length() + 7) // 8) # ceiling to need bytes
    s_bytes = s.to_bytes(num_bytes, byteorder='big')

    if len(s_bytes) >= 16:
        return s_bytes[-16:]
    else:
        pad_len = 16 - num_bytes
        padding = b'\x00' * pad_len
        return padding + s_bytes

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
    
    K_a = random.randint(2**(k_bits - 1), P - 2)
    A = pow(g, K_a, P)
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[Socket] Connecting to Bob at {host}:{port}...")
    client_socket.connect((host, port))
    
    dh_payload = f"{P},{g},{A}"
    print("[DH] Sending P, g, and Public Key A to Bob...")
    print(f"P = {P}")
    print(f"g = {g}")
    print(f"A (g^K_a mod P) = {A}")
    client_socket.send(dh_payload.encode('ascii'))
    
    response = client_socket.recv(4096).decode('ascii')
    B = int(response)
    print(f"[DH] Received Public Key B from Bob.")
    print(f"B (g^K_b mod P) = {B}")
    
    # s is the secret key
    s = pow(B, K_a, P)
    aes_key = derive_aes_key(s)
    print(f"[Key Derived] Shared Secret computed successfully.")
    print(f"  Derived AES Key (HEX): {aes_mod.bytes_to_hex_str(aes_key)}\n")
    
    ready_signal = client_socket.recv(1024).decode('ascii')
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

    print(f"Encryption time: {encryption_time} ms")

    if msg_type == b"FILE":
        encrypted_file_name = "encrypted_" + filename.decode('utf-8')
        with open(encrypted_file_name, "wb") as f_out:
            f_out.write(ciphertext)
        print(f"[Local] Encrypted payload saved as '{encrypted_file_name}'")

    name_len = len(filename_bytes)
    header = msg_type + name_len.to_bytes(4, 'big') + filename_bytes + len(ciphertext).to_bytes(10, 'big')
    
    print("[Socket] Sending structured protocol header...")
    client_socket.sendall(header)
    
    client_socket.recv(4) # ACK patahlo
    
    print("[Socket] Streaming encrypted payload...")
    client_socket.sendall(ciphertext)
    
    print(f"\n[SUCCESS] {msg_type.decode()} transmitted successfully!")
    print(f"Sent Ciphertext (HEX Truncated): {aes_mod.bytes_to_hex_str(ciphertext[:32])} ...")
    
    client_socket.close()
    print("[Status] Connection safely closed.")

if __name__ == "__main__":
    run_alice()