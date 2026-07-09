import time
import random
import math
from random import randint

random.seed(42)

# algorithm from: https://cp-algorithms.com/algebra/primality_tests.html

def binpower(base, e, mod):
    result = 1
    base %= mod

    while e:
        if e&1:
            result = result * base % mod
        base = base * base % mod
        e>>=1
    
    return result


def check_composite(n, a, d, s):
    # x = binpower(a,d,n)
    x = pow(a,d,n) # python's built-in is faster ig
    if x==1 or x==(n-1):
        return False
    
    for _ in range(s-1):
        x = x * x % n
        if x==(n-1):
            return False
    
    return True

def miller_rabin(n, iter=40):
    if n<4:
        return n==2 or n==3

    if n%2==0:
        return False
    
    s=0
    d=n-1
    while (d&1)==0:
        d>>=1
        s+=1
    
    for _ in range (iter):
        a = randint(2, n - 2)
        if check_composite(n,a,d,s):
            return False
    
    return True


def generate_prime(bit_length):
    """
    generate an odd prime with bit length = bit_length
    """
    while True:
        candidate = random.getrandbits(bit_length)
        candidate |= (1 << (bit_length - 1))  # force MSB=1
        candidate |= 1                        # force LSB=1

        if miller_rabin(candidate):
            return candidate

def generate_safe_prime(bit_length):
    """
    safe prime, P = 2q+1, where q is also a prime number
    """
    while True:
        q = generate_prime(bit_length - 1)
        P = 2 * q + 1 # P is size of bit_length, so q becomes bit_lenght-1 bits
        if miller_rabin(P):
            return P, q

def find_generator(P, q):
    """
        for 1<g<P, st: g^((P-1)/r) != 1 (mod P) for every prime r, P=2q+1=> P-1=2q; therefore, r = {2,q}
        => so check only g^2 mod P != 1 and g^q mod P != 1 conditions
    """
    while True:
        g = random.randint(2, P - 2)
        
        if pow(g, 2, P) != 1 and pow(g, q, P) != 1:
            return g

def generate_dh_parameters(bit_length):
    P, q = generate_safe_prime(bit_length)
    g = find_generator(P, q)
    return P, g

def run_dh_trial(bit_length):
    """
        1. random secret, K_a and K_b st: they are >= bit_length bits
        2. A = g^K_a mod P, B = g^K_b mod P
        3. s(shared) = B^K_a mod P = A^K_b mod P
    """
    
    # _t = time.perf_counter()
    P, g = generate_dh_parameters(bit_length)
    # time_0 = (time.perf_counter() - _t) * 1000
    
    
    t0 = time.perf_counter()
    """
        choosing K_a:
        P is k-bit prime,
        2^(k-1) ≤ P < 2^k.
        roughly, P~= 2^k, means P-2 is also in range of [2^(k-1), 2^k)
        so, we can take: 2^(k-1) {k-bit} <= K_a <= P-2 {k-bit} to make K_a k-bit length.
        and yeah, P can't be 2^(k-1)+1 as P=2q+1 where q is (k-1) bit number as we generated earlier.
        thus K_a, K_b IS indeed k-bit random number ranging from 11...{k}..11 to P-2
    """
    K_a = random.randint(2**(bit_length - 1), P - 2) 
    A = pow(g, K_a, P)
    time_A = (time.perf_counter() - t0) * 1000
    
    t1 = time.perf_counter()
    K_b = random.randint(2**(bit_length - 1), P - 2)
    B = pow(g, K_b, P)
    time_B = (time.perf_counter() - t1) * 1000

    t2 = time.perf_counter()
    s_alice = pow(B, K_a, P)
    s_bob   = pow(A, K_b, P)
    time_s  = (time.perf_counter() - t2) * 1000

    assert s_alice == s_bob, "[ERROR] Shared secrets do not match!"

    # return time_A, time_B, time_s, time_0
    return time_A, time_B, time_s

if __name__ == "__main__":
    print("=" * 65)
    print("          Diffie-Hellman Performance Report")
    print("=" * 65)
    # print("version: with built-in(s) function")

    key_sizes  = [128, 192, 256]
    num_trials = 10

    # print(f"\n{'k (bits)':<10} | {'Time A (ms)':<15} | {'Time B (ms)':<15} | {'Time s (ms)':<15} | {'Time P,g (ms)':<15}")
    print(f"\n{'k (bits)':<10} | {'Time A (ms)':<15} | {'Time B (ms)':<15} | {'Time s (ms)':<15}")
    print("-" * 62)

    for k in key_sizes:
        totals = [0.0, 0.0, 0.0]
        for _ in range(num_trials):
            tA, tB, ts = run_dh_trial(k)
            totals[0] += tA
            totals[1] += tB
            totals[2] += ts
            # totals[3] += t0

        avg = [t / num_trials for t in totals]
        # print(f"{k:<10} | {avg[0]:<15.4f} | {avg[1]:<15.4f} | {avg[2]:<15.4f} | {avg[3]:<15.4f}")
        print(f"{k:<10} | {avg[0]:<15.4f} | {avg[1]:<15.4f} | {avg[2]:<15.4f} ")

    print("\n[SUCCESS] Diffie-Hellman key exchange verified and complete.")