import importlib
aes_mod = importlib.import_module("2105032_AES")

def encrypt_image_bonus(input_bmp_path, key_bytes):
    # ইমেজটি বাইনারি মোডে রিড করা
    with open(input_bmp_path, "rb") as f:
        full_image_bytes = f.read()
        
    # BMP হেডার (প্রথম ৫৪ বাইট) আলাদা করা
    header = full_image_bytes[:54]
    pixel_data = full_image_bytes[54:]
    
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

# টেস্ট করার জন্য ড্রাইভার:
encrypt_image_bonus("test_64x64.bmp", b"BUET CSE20 Batch")