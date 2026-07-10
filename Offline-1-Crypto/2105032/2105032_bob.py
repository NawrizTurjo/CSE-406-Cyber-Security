import socket
import importlib
import random
import time

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
    
    data = conn.recv(4096).decode('ascii')
    P_str, g_str, A_str = data.split(',')
    P = int(P_str)
    g = int(g_str)
    A = int(A_str)
    print("[DH] Received P, g, and Public Key A from Alice.")
    print(f"P = {P}")
    print(f"g = {g}")
    print(f"g^K_a = {A}")
    
    k_bits = 128
    K_b = random.randint(2**(k_bits - 1), P - 2)
    B = pow(g, K_b, P)
    
    print("[DH] Sending Public Key B to Alice...")
    print(f"g^K_b = {B}")
    conn.send(str(B).encode('ascii'))
    
    s = pow(A, K_b, P)
    aes_key = derive_aes_key(s)
    print(f"[Key derived] Shared Secret computed successfully.")
    print(f"Derived AES Key (HEX): {aes_mod.bytes_to_hex_str(aes_key)}\n")
    
    conn.send("READY".encode('ascii'))

    print("[Socket] Waiting for transmission...")
    
    type_bytes = conn.recv(4)
    msg_type = type_bytes.decode('ascii')
    
    name_len = int.from_bytes(conn.recv(4), 'big')
    filename = conn.recv(name_len).decode('utf-8') if name_len > 0 else ""
    ct_len = int.from_bytes(recv_all(conn, 10), 'big')
    conn.send(b"ACK_")
    
    ciphertext = recv_all(conn, ct_len)
    print(f"[AES] CT (HEX Truncated): {aes_mod.bytes_to_hex_str(ciphertext[:32])} ...")
    
    time_s = time.perf_counter()
    decrypted = aes_mod.aes_decrypt_cbc(ciphertext, aes_key)
    decryption_time = (time.perf_counter() - time_s) * 1000
    
    print(f"Decryption Time: {decryption_time}")
    
    if msg_type == "TEXT":
        print("\n--- TRANSMISSION SUCCESS ---")
        print(f"Recovered Text (ASCII): {decrypted.decode('utf-8')}")
        print(f"Recovered Text (HEX Truncated)  : {aes_mod.bytes_to_hex_str(decrypted[:32])} ...")
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