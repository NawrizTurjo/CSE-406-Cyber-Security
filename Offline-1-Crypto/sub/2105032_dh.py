import time
import random
# pycryptodome প্যাকেজ থেকে নিরাপদ বড় প্রাইম জেনারেট করার ফাংশন ইম্পোর্ট করা হলো
from Crypto.Util.number import getPrime

# --- ১. পাবলিক প্যারামিটার জেনারেশন ---
def generate_dh_parameters(bit_length):
    """নির্দিষ্ট বিট লেন্থের প্রাইম P এবং একটি জেনারেটর g তৈরি করার ফাংশন"""
    # bit_length সাইজের ক্রিপ্টোগ্রাফিক্যালি সেফ প্রাইম নাম্বার জেনারেট করা
    P = getPrime(bit_length)
    
    # g এর মান সাধারণত ২ থেকে P-১ এর মধ্যে একটি ছোট সুবিধাজনক সংখ্যা নেওয়া হয়
    # ল্যাব স্ট্যান্ডার্ড অনুযায়ী g = ২ অথবা ৫ বহুল ব্যবহৃত। আমরা এখানে ২ সিলেক্ট করছি।
    g = 2 
    return P, g

# --- ২. কী জেনারেশন ও শেয়ার্ড সিক্রেট গণনা ---
def run_dh_trial(bit_length):
    """Diffie-Hellman এর একটি একক ট্রায়াল রান করে এক্সিকিউশন টাইম পরিমাপ করার ফাংশন"""
    
    # ক) প্যারামিটার জেনারেশন
    P, g = generate_dh_parameters(bit_length)
    
    # টাইমিং ট্র্যাক করা শুরু (কী জেনারেশন থেকে শেয়ার্ড সিক্রেট পর্যন্ত)
    start_time = time.perf_counter()
    
    # খ) অ্যালিসের প্রাইভেট কী ও পাবলিক কী গণনা
    # Ka এর মান মিনিমাম k-bits দীর্ঘ হতে হবে
    K_a = random.randint(2**(bit_length - 1), P - 2)
    A = pow(g, K_a, P) # A = g^Ka mod P
    
    # গ) ববের প্রাইভেট কী ও পাবলিক কী গণনা
    K_b = random.randint(2**(bit_length - 1), P - 2)
    B = pow(g, K_b, P) # B = g^Kb mod P
    
    # ঘ) শেয়ার্ড সিক্রেট গণনা (উভয় প্রান্তে)
    s_alice = pow(B, K_a, P) # s = B^Ka mod P
    s_bob = pow(A, K_b, P)   # s = A^Kb mod P
    
    end_time = time.perf_counter()
    execution_time_ms = (end_time - start_time) * 1000
    
    # ভেরিফিকেশন চেক: দুই প্রান্তের কী মিলল কিনা
    assert s_alice == s_bob, "[ERROR] Shared secrets do not match!"
    
    return execution_time_ms

# --- ৩. পারফরম্যান্স রিপোর্টিং ড্রাইভার কোড ---
if __name__ == "__main__":
    print("==================== Diffie-Hellman Performance Report ====================\n")
    
    # অ্যাসাইনমেন্টে রিকোয়ার্ড বিট সাইজসমূহ
    key_sizes = [128, 192, 256]
    num_trials = 5 # সর্বনিম্ন ৫টি ট্রায়ালের গড় নিতে হবে
    
    # টেবিল হেডার প্রিন্ট করা (অফিশিয়াল অ্যাসাইনমেন্ট ফরম্যাট)
    print(f"{'k (bits)':<10} | {'Computation time for shared key s (ms)':<40}")
    print("-" * 55)
    
    for k in key_sizes:
        total_time = 0.0
        for _ in range(num_trials):
            total_time += run_dh_trial(k)
            
        avg_time = total_time / num_trials
        print(f"{k:<10} | {avg_time:<40.4f}")
        
    print("\n[SUCCESS] Diffie-Hellman key exchange simulation completed successfully.")