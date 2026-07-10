import socket
import importlib
import time
import random

# importlib ব্যবহার করে নিউমেরিক ফাইলের ফাংশন ইম্পোর্ট করা
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


def send_file_bonus(client_socket, file_path, aes_key):
    import os
    file_name = os.path.basename(file_path)
    
    # ফাইল বাইনারি মোডে রিড করা
    with open(file_path, "rb") as f:
        file_bytes = f.read()
        
    # CBC মোডে সম্পূর্ণ ফাইল এনক্রিপ্ট করা
    ciphertext = aes_mod.aes_encrypt_cbc(file_bytes, aes_key)
    
    # মেটাডেটা পাঠানো (Filename এবং Ciphertext Size)
    metadata = f"{file_name}:{len(ciphertext)}"
    client_socket.send(metadata.encode('ascii'))
    
    # ববের কাছ থেকে অ্যাকনলেজমেন্ট নেওয়া
    client_socket.recv(1024)
    
    # সম্পূর্ণ সাইফারটেক্সট স্ট্রিম পাঠানো
    client_socket.sendall(ciphertext)
    print(f"[SUCCESS] File '{file_name}' encrypted and transmitted.")

def run_alice():
    host = '127.0.0.1'
    port = 65432
    
    print("==================== ALICE (SENDER) ====================\n")
    
    # ১. Diffie-Hellman প্যারামিটার ও কী জেনারেশন (১২৮-বিট কী সাইজ)
    k_bits = 128
    print(f"[DH] Generating {k_bits}-bit parameters...")
    P, g = dh_mod.generate_dh_parameters(k_bits)
    
    K_a = random.randint(2**(k_bits - 1), P - 2)
    A = pow(g, K_a, P)
    
    # ২. ববের সাথে TCP সকেট কানেকশন তৈরি করা
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[Socket] Connecting to Bob at {host}:{port}...")
    client_socket.connect((host, port))
    
    # ৩. কী এক্সচেঞ্জ ফেস: P, g, A কমা দিয়ে সেপারেট করে পাঠানো
    dh_payload = f"{P},{g},{A}"
    print("[DH] Sending P, g, and Public Key A to Bob...")
    print(f"P = {P}")
    print(f"g = {g}")
    print(f"g^K_a = {A}")
    client_socket.send(dh_payload.encode('ascii'))
    
    # ৪. ববের পাবলিক কী B রিসিভ করা
    response = client_socket.recv(4096).decode('ascii')
    B = int(response)
    print(f"[DH] Received Public Key B from Bob.")
    print(f"g^K_b = {B}")
    
    # ৫. শেয়ার্ড সিক্রেট ও AES কী ডিরাইভ করা
    s = pow(B, K_a, P)
    aes_key = derive_aes_key(s)
    print(f"[Key derived] Shared Secret computed successfully.")
    print(f"Derived AES Key (HEX): {aes_mod.bytes_to_hex_str(aes_key)}\n")
    
    # বব প্রস্তুত কিনা তার সিগন্যাল রিড করা
    ready_signal = client_socket.recv(1024).decode('ascii')
    if ready_signal == "READY":
        print("[Status] Bob is READY for transmission.")
        
    # # ৬. ট্রান্সমিশন ফেস: মেসেজ ইনপুট নেওয়া ও এনক্রিপ্ট করে পাঠানো
    # plaintext = input("\nEnter plaintext message to send to Bob: ")
    # plaintext_bytes = plaintext.encode('utf-8')
    
    # print("\n[AES] Encrypting message using CBC mode...")
    # ciphertext_cbc = aes_mod.aes_encrypt_cbc(plaintext_bytes, aes_key)

    # ct_len = len(ciphertext_cbc)
    # client_socket.send(f"{ct_len}|".encode('ascii'))
    # client_socket.recv(16)  # wait for ACK
    # client_socket.sendall(ciphertext_cbc)

    # print(f"Ciphertext sent (HEX): {aes_mod.bytes_to_hex_str(ciphertext_cbc)}")
    # print("[Status] Ciphertext transmitted successfully. Closing connection.")
    # client_socket.close()
    
    # ৬. ট্রান্সমিশন ফেস
    mode = input("\nSend (1) Text  (2) File: ").strip()
    
    if mode == "1":
        msg_type = b"TEXT"
        payload = input("Enter plaintext: ").encode('utf-8')
        filename_bytes = b""
    else:
        import os
        file_path = input("Enter file path: ").strip()
        msg_type = b"FILE"
        filename = os.path.basename(file_path).encode('utf-8')
        filename_bytes = filename
        with open(file_path, "rb") as f:
            payload = f.read()

    print("\n[AES] Encrypting...")
    ciphertext = aes_mod.aes_encrypt_cbc(payload, aes_key)

    # Header: TYPE(4)|NAMELEN(4)|NAME|CTLEN(10)|
    name_len = len(filename_bytes)
    header = msg_type + name_len.to_bytes(4, 'big') + filename_bytes + len(ciphertext).to_bytes(10, 'big')
    client_socket.sendall(header)
    client_socket.recv(4)  # ACK
    client_socket.sendall(ciphertext)
    print(f"[Sent] {msg_type.decode()} | CT HEX: {aes_mod.bytes_to_hex_str(ciphertext)}")
    client_socket.close()

if __name__ == "__main__":
    run_alice()