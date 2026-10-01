import importlib
import time
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

def encrypt_image_bonus(input_bmp_path, key_bytes):
    with open(input_bmp_path, "rb") as f:
        # read as binary file
        full_image_bytes = f.read()
        
    # bmp is bascially Header|Data
    # bytes 10-13 carries bfOffBits -> says where pixel data starts
    # means 0 to offset is Header part, and Offset to end is data part
    # offset data are arranged in little endian way
    offset = int.from_bytes(full_image_bytes[10:14], 'little')
    header = full_image_bytes[:offset]
    pixel_data = full_image_bytes[offset:]
    
    print("[ECB] Encrypting image pixels...")
    
    ecb_time_s = time.perf_counter()
    encrypted_pixels_ecb = aes_mod.aes_encrypt_ecb(pixel_data, key_bytes)
    ecb_time_e = time.perf_counter()
    
    with open("encrypted_ecb.bmp", "wb") as f:
        # writing to encrypted file
        # header must be preserved
        f.write(header + encrypted_pixels_ecb[:len(pixel_data)])
        
    print("[CBC] Encrypting image pixels...")

    cbc_time_s = time.perf_counter()
    encrypted_bytes_cbc = aes_mod.aes_encrypt_cbc(pixel_data, key_bytes)
    cbc_time_e = time.perf_counter()
    
    encrypted_pixels_cbc = encrypted_bytes_cbc[16:] # first 16 are IV, discarded
    
    with open("encrypted_cbc.bmp", "wb") as f:
        # writing similarly
        f.write(header + encrypted_pixels_cbc[:len(pixel_data)])
        
    print("[SUCCESS] ECB and CBC images generated successfully.")

    ecb_time = (ecb_time_e - ecb_time_s) * 1000
    cbc_time = (cbc_time_e - cbc_time_s) * 1000

    return ecb_time, cbc_time



def main():
    image_path = input("Enter BMP image path: ").strip()

    shared_secret = input("Enter shared secret: ")

    try:
        num = int(shared_secret)
        s = derive_aes_key(num)
    except ValueError:
        s = shared_secret.encode('utf-8')
    
    key_bytes = s

    ecb_time, cbc_time = encrypt_image_bonus(image_path, key_bytes)
    print(f"ECB encryption time: {ecb_time:.2f} ms")
    print(f"CBC encryption time: {cbc_time:.2f} ms")

if __name__ == "__main__":
    main()