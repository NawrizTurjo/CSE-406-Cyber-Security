import importlib
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
    # ইমেজটি বাইনারি মোডে রিড করা
    with open(input_bmp_path, "rb") as f:
        full_image_bytes = f.read()
        
    # BMP হেডার আলাদা করা (ডাইনামিকালি bfOffBits অফসেট ব্যবহার করে, কারণ ৩২-বিট BMP এর হেডার সাইজ আলাদা হতে পারে)
    offset = int.from_bytes(full_image_bytes[10:14], 'little')
    header = full_image_bytes[:offset]
    pixel_data = full_image_bytes[offset:]
    
    # ১. ECB মোডে পিক্সেল ডেটা এনক্রিপ্ট করা
    print("[ECB] Encrypting image pixels...")
    encrypted_pixels_ecb = aes_mod.aes_encrypt_ecb(pixel_data, key_bytes)
    # হেডার অপরিবর্তিত রেখে নতুন ফাইল সেভ করা
    with open("encrypted_ecb.bmp", "wb") as f:
        f.write(header + encrypted_pixels_ecb[:len(pixel_data)])
        
    # ২. CBC মোডে পিক্সেল ডেটা এনক্রিপ্ট করা
    print("[CBC] Encrypting image pixels...")
    # cbc মোড (IV + Ciphertext) রিটার্ন করে, তাই IV বাদে শুধু সাইফার পার্টটুকুHeaders এর সাথে জোড়া দেব
    encrypted_bytes_cbc = aes_mod.aes_encrypt_cbc(pixel_data, key_bytes)
    encrypted_pixels_cbc = encrypted_bytes_cbc[16:] # প্রথম ১৬ বাইট IV বাদ দিলাম
    
    with open("encrypted_cbc.bmp", "wb") as f:
        f.write(header + encrypted_pixels_cbc[:len(pixel_data)])
        
    print("[SUCCESS] ECB and CBC images generated successfully.")



def main():
    image_path = input("Enter BMP image path: ").strip()

    shared_secret = int(input("Enter shared secret: "))
    key_bytes = derive_aes_key(shared_secret)

    encrypt_image_bonus(image_path, key_bytes)

if __name__ == "__main__":
    main()