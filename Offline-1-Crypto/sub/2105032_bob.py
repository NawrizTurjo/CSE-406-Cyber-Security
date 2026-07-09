import socket
import importlib
import random

# মডিউল ডাইনামিক ইম্পোর্ট
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


def receive_file_bonus(conn, aes_key):
    # মেটাডেটা রিসিভ করা
    metadata = conn.recv(1024).decode('ascii')
    file_name, cipher_len = metadata.split(':')
    cipher_len = int(cipher_len)
    
    # অ্যাকনলেজমেন্ট পাঠানো
    conn.send(b"ACK")
    
    # সম্পূর্ণ সাইফারটেক্সট বাফারিং করে রিড করা
    ciphertext = recv_all(conn, cipher_len)
        
    # AES-CBC মোডে ডিক্রিপ্ট করা
    print(f"[AES] Decrypting arbitrary file: {file_name}")
    decrypted_file_bytes = aes_mod.aes_decrypt_cbc(bytes(ciphertext), aes_key)
    
    # রিসিভড ফাইলটি ডিস্কে সেভ করা
    out_name = "received_" + file_name
    with open(out_name, "wb") as f:
        f.write(decrypted_file_bytes)
    print(f"[TRANSMISSION SUCCESS] File saved as '{out_name}'")

def run_bob():
    host = '127.0.0.1'
    port = 65432
    
    # সার্ভার সকেট সেটআপ
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)
    
    print("==================== BOB (RECEIVER / SERVER) ====================")
    print(f"[Socket] Waiting for Alice to connect on port {port}...\n")
    
    conn, addr = server_socket.accept()
    print(f"[Socket] Connected by Alice from {addr}")
    
    # ১. অ্যালিসের কাছ থেকে DH প্যারামিটার ও পাবলিক কী A গ্রহণ করা
    data = conn.recv(4096).decode('ascii')
    P_str, g_str, A_str = data.split(',')
    P = int(P_str)
    g = int(g_str)
    A = int(A_str)
    print("[DH] Received P, g, and Public Key A from Alice.")
    
    # ২. ববের নিজের প্রাইভেট কী ও পাবলিক কী B তৈরি
    k_bits = 128
    K_b = random.randint(2**(k_bits - 1), P - 2)
    B = pow(g, K_b, P)
    
    # ৩. অ্যালিসকে পাবলিক কী B পাঠানো
    print("[DH] Sending Public Key B to Alice...")
    conn.send(str(B).encode('ascii'))
    
    # ৪. শেয়ার্ড সিক্রেট ও AES কী ডিরাইভ করা
    s = pow(A, K_b, P)
    aes_key = derive_aes_key(s)
    print(f"[Key derived] Shared Secret computed successfully.")
    print(f"Derived AES Key (HEX): {aes_mod.bytes_to_hex_str(aes_key)}\n")
    
    # অ্যালিসকে সিগন্যাল পাঠানো যে বব প্রস্তুত
    conn.send("READY".encode('ascii'))
    
    # # ৫. সকেট থেকে এনক্রিপ্টেড সাইফারটেক্সট বাইট রিসিভ করা
    # print("[Socket] Waiting for ciphered text stream from Alice...")
    # header = conn.recv(64).decode('ascii')
    # ct_len = int(header.rstrip('|').split('|')[0])
    # conn.send(b"OK")

    # ciphertext = recv_all(conn, ct_len)
    
    # if ciphertext:
    #     print(f"[AES] Ciphertext received (HEX): {aes_mod.bytes_to_hex_str(ciphertext)}")
        
    #     # ৬. AES-CBC মোডে ডিক্রিপ্ট করা
    #     print("[AES] Decrypting and unpadding message...")
    #     decrypted_plain_bytes = aes_mod.aes_decrypt_cbc(ciphertext, aes_key)
        
    #     print("\n--- TRANSMISSION SUCCESS ---")
    #     print(f"Recovered Text (ASCII): {decrypted_plain_bytes.decode('utf-8')}")
    #     print(f"Recovered Text (HEX)  : {aes_mod.bytes_to_hex_str(decrypted_plain_bytes)}")
        
    # conn.close()
    # server_socket.close()

    # ৫. Unified recv
    print("[Socket] Waiting for transmission...")
    
    # Header: TYPE(4) + NAMELEN(4) + NAME + CTLEN(10)
    type_bytes = conn.recv(4)
    msg_type = type_bytes.decode('ascii')
    
    name_len = int.from_bytes(conn.recv(4), 'big')
    filename = conn.recv(name_len).decode('utf-8') if name_len > 0 else ""
    ct_len = int.from_bytes(recv_all(conn, 10), 'big')
    conn.send(b"ACK_")
    
    ciphertext = recv_all(conn, ct_len)
    print(f"[AES] CT (HEX): {aes_mod.bytes_to_hex_str(ciphertext)}")
    
    decrypted = aes_mod.aes_decrypt_cbc(ciphertext, aes_key)
    
    if msg_type == "TEXT":
        print("\n--- TRANSMISSION SUCCESS ---")
        print(f"Recovered Text (ASCII): {decrypted.decode('utf-8')}")
        print(f"Recovered Text (HEX)  : {aes_mod.bytes_to_hex_str(decrypted)}")
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