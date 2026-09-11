# 🔐 CSE 406 — Cyber Security Sessional
## Assignment 01: AES + Diffie-Hellman Cryptosystem
## Offline 1: AES + Diffie-Hellman Cryptosystem

> **Course:** CSE 406 · Cyber Security Sessional · January 2026
> **Deadline:** 11:59 PM, 3 July 2026
> **Course:** CSE 406 · Cyber Security Sessional · January 2026  
> **Student ID:** 2105032  
> **Section:** A2  

---

## 📋 Table of Contents

- [Overview](#-overview)
- [System Architecture](#-system-architecture)
- [AES Overview](#-aes-overview-aes-128)
  - [Round Operations](#round-operations)
  - [What's Provided](#whats-provided-to-you)
- [Diffie-Hellman Overview](#-diffie-hellman-key-exchange)
- [Tasks](#-tasks)
  - [Task 1 — AES Implementation (40 pts)](#task-1--independent-implementation-of-aes-128-bit--40-pts)
  - [Task 2 — Diffie-Hellman Implementation (25 pts)](#task-2--independent-implementation-of-diffie-hellman--25-pts)
  - [Task 3 — Full Cryptosystem via Sockets (20 pts)](#task-3--full-cryptosystem-via-sockets--20-pts)
  - [Bonus Tasks](#-bonus-tasks)
- [Mark Breakdown](#-mark-breakdown)
- [Design Decisions & Implementation Logic](#-design-decisions--implementation-logic)
- [Cryptosystem Architecture](#-cryptosystem-architecture)
- [AES Block Cipher Fundamentals](#-aes-block-cipher-fundamentals)
  - [1. Round Transformations](#1-round-transformations)
  - [2. Key Expansion Schedule](#2-key-expansion-schedule)
  - [3. Modes of Operation & PKCS#7 Padding](#3-modes-of-operation--pkcs7-padding)
- [Diffie-Hellman Key Exchange Protocol](#-diffie-hellman-key-exchange-protocol)
  - [1. Protocol Exchange Sequence](#1-protocol-exchange-sequence)
  - [2. Safe Prime Generation & Miller-Rabin Primality](#2-safe-prime-generation--miller-rabin-primality)
  - [3. Primitive Root (Generator) Selection](#3-primitive-root-generator-selection)
  - [4. Shared Secret & Symmetric Key Derivation](#4-shared-secret--symmetric-key-derivation)
- [Task Specifications & Core Deliverables](#-task-specifications--core-deliverables)
  - [Task 1: AES Implementation (40 pts)](#task-1-aes-implementation-40-pts)
  - [Task 2: Diffie-Hellman Key Exchange (25 pts)](#task-2-diffie-hellman-key-exchange-25-pts)
  - [Task 3: Full Cryptosystem via TCP Sockets (20 pts)](#task-3-full-cryptosystem-via-tcp-sockets-20-pts)
  - [Bonus Tasks (15 pts)](#bonus-tasks-15-pts)
- [Design Decisions & Performance Optimizations](#-design-decisions--performance-optimizations)
  - [1. Galois Field Multiplication Lookup (`GF_LUT`) inside AES](#1-galois-field-multiplication-lookup-gf_lut-inside-aes)
  - [2. Key Size Polymorphism & Normalization](#2-key-size-polymorphism--normalization)
  - [3. Mathematical Group Simplifications in Generator Finding](#3-mathematical-group-simplifications-in-generator-finding)
  - [4. Miller-Rabin Witness Exponentiation Efficiency](#4-miller-rabin-witness-exponentiation-efficiency)
  - [5. BMP Image Header Preservation and IV Handling](#5-bmp-image-header-preservation-and-iv-handling)
  - [6. Custom Socket Header Framing and Flow Control](#6-custom-socket-header-framing-and-flow-control)
- [Benchmark Results & Performance Analysis](#-benchmark-results--performance-analysis)
  - [1. GF LUT Optimization Impact (926x Speedup)](#1-gf-lut-optimization-impact-926x-speedup)
  - [2. AES Encryption & Decryption Performance](#2-aes-encryption--decryption-performance)
  - [3. Diffie-Hellman Key Agreement Timings](#3-diffie-hellman-key-agreement-timings)
- [How to Run It](#-how-to-run-it)
- [Project Report](#-project-report)
- [File Layout](#-file-layout)
- [Evaluation & Mark Breakdown](#-evaluation--mark-breakdown)
- [Submission Guidelines](#-submission-guidelines)
- [Plagiarism Policy](#%EF%B8%8F-plagiarism-policy)

---

## 🌐 Overview

The goal of this assignment is to build a complete **symmetric-key cryptosystem** from scratch:
The objective of this assignment is to engineer an end-to-end, production-grade **hybrid symmetric-key cryptosystem** from scratch in Python:

1. Two parties exchange a secret key securely using **Diffie-Hellman** over a finite field.
2. The sender encrypts plaintext using **AES-128** with the shared key.
3. The ciphertext travels over a channel (TCP socket); the receiver decrypts it.
1. **Key Agreement**: Two untrusted parties negotiate an ephemeral symmetric key over a public, unauthenticated channel using the **Diffie-Hellman (DH)** key exchange algorithm over a finite multiplicative group.
2. **Bulk Symmetric Encryption**: Plaintext data is segmented, padded, and encrypted using a custom-engineered **Advanced Encryption Standard (AES)** engine supporting 128, 192, and 256-bit keys across both **ECB** and **CBC** modes of operation.
3. **Transport Layer Security**: Alice (client) and Bob (server) communicate across a real TCP network socket, coordinating key exchange parameters and securely transmitting arbitrary text messages and binary files.
4. **Security & Performance Extensions**:
   - Visualizing the security limitations of ECB vs. CBC mode on 24-bit bitmap images.
   - Accelerating Galois field operations by over **900x** via import-time lookup tables (`GF_LUT`).
   - Establishing custom application-level TCP framing with length headers and acknowledgment handshakes.

> You are **not** required to implement Galois field arithmetic from scratch — finite-field building blocks are provided in `aes_helpers.py`. Focus on cipher structure and algorithmic correctness.

---

## 🏗 System Architecture
## 🏗 Cryptosystem Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Public Parameters: P, g                       │
└──────────────────────────┬──────────────────────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
        ALICE           Channel           BOB
     (Secret: Kₐ)                    (Secret: K_b)
           │                               │
    A = g^Kₐ mod P  ──────────────►        │
           │               ◄──────  B = g^K_b mod P
           │                               │
    s = B^Kₐ mod P        =        s = A^K_b mod P
           │                               │
           └──────── Shared Secret s ──────┘
                     (= g^(Kₐ·K_b) mod P)
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
       AES Encrypt (Alice)       AES Decrypt (Bob)
       Plaintext ──► CT    ──►   CT ──► Plaintext
```

---

## 🔒 AES Overview (AES-128)
## 🔒 AES Block Cipher Fundamentals

AES is a block cipher that operates on a **4×4 byte state matrix** (128 bits). It runs for:
AES operates on a $4 \times 4$ column-major byte matrix (the **State**). Key sizes and round parameters are governed by the NIST FIPS-197 standard:

| Key Size | Rounds |
|----------|--------|
| 128-bit  | 10     |
| 192-bit  | 12     |
| 256-bit  | 14     |
| Key Size | Key Length ($N_k$ words) | Block Size ($N_b$ words) | Rounds ($N_r$) |
|:---:|:---:|:---:|:---:|
| **AES-128** | 4 words (16 bytes) | 4 words (16 bytes) | 10 rounds |
| **AES-192** | 6 words (24 bytes) | 4 words (16 bytes) | 12 rounds |
| **AES-256** | 8 words (32 bytes) | 4 words (16 bytes) | 14 rounds |

**This assignment targets AES-128 (10 rounds).** Each round (except the last) consists of four operations applied in sequence:
### 1. Round Transformations

---
Each intermediate round applies four invertible transformations:

### Round Operations
1. **`SubBytes` / `InvSubBytes`**: Non-linear byte substitution using a fixed Rijndael S-box constructed via multiplicative inversion in $\text{GF}(2^8)$ followed by an affine transformation.
2. **`ShiftRows` / `InvShiftRows`**: Cyclical left shifts of the state rows:
   - Row 0: No shift
   - Row 1: Shift left by 1 byte
   - Row 2: Shift left by 2 bytes
   - Row 3: Shift left by 3 bytes
3. **`MixColumns` / `InvMixColumns`**: Linear diffusion transformation where each 4-byte column is treated as a polynomial over $\text{GF}(2^8)$ and multiplied modulo $x^4 + 1$ with a fixed polynomial:
   $$c(x) = \{03\}x^3 + \{01\}x^2 + \{01\}x + \{02\}$$
   *(Omitted in the final round $N_r$).*
4. **`AddRoundKey`**: Bitwise XOR of the state with the corresponding 128-bit round subkey derived from the key schedule.

#### 1. `subBytes` / `invSubBytes`
Replace every byte in the state using a fixed 256-entry S-box lookup table.
### 2. Key Expansion Schedule

```
state[i][j] = Sbox[ state[i][j] ]          # encryption
state[i][j] = InvSbox[ state[i][j] ]       # decryption
```
The original key is expanded into $(N_r + 1)$ 128-bit round subkeys. For word index $i$:
* If $i \equiv 0 \pmod{N_k}$: $w[i] = w[i - N_k] \oplus \text{SubWord}(\text{RotWord}(w[i-1])) \oplus \text{Rcon}[i / N_k]$
* For AES-256 with $N_k = 8$ and $i \equiv 4 \pmod{N_k}$: $w[i] = w[i - N_k] \oplus \text{SubWord}(w[i-1])$
* Otherwise: $w[i] = w[i - N_k] \oplus w[i - 1]$

Both `Sbox` and `InvSbox` are provided in `aes_helpers.py`.
### 3. Modes of Operation & PKCS#7 Padding

---
* **ECB (Electronic Codebook)**: Each 16-byte block is encrypted independently. Preserves plaintext patterns across identical blocks.
* **CBC (Cipher Block Chaining)**: Each plaintext block is XORed with the preceding ciphertext block before encryption ($C_i = E_K(P_i \oplus C_{i-1})$), initialized with a random 16-byte Initialization Vector ($C_0 = \text{IV}$).
* **PKCS#7 Padding**: Appends $N$ bytes (each with value $N$) such that total length is a multiple of 16. If data is already an exact multiple of 16 bytes, a full block of `\x10` padding is appended.

#### 2. `shiftRows` / `invShiftRows`
Cyclically shift each row of the 4×4 state:

| Row | Encrypt (shift left) | Decrypt (shift right) |
|-----|---------------------|-----------------------|
| R₀  | 0 bytes             | 0 bytes               |
| R₁  | 1 byte              | 1 byte                |
| R₂  | 2 bytes             | 2 bytes               |
| R₃  | 3 bytes             | 3 bytes               |

Byte *values* are unchanged — only their positions move.

---

#### 3. `mixColumns` / `invMixColumns`
Multiply each column of the state by a fixed 4×4 matrix over **GF(2⁸)**:
## 🤝 Diffie-Hellman Key Exchange Protocol

```python
# You do NOT implement field arithmetic — use the provided helper:
from aes_helpers import gf_mult, Mixer, InvMixer
Diffie-Hellman relies on the computational difficulty of the **Discrete Logarithm Problem (DLP)** in the multiplicative group $\mathbb{Z}_P^*$: given $g, P,$ and $A = g^a \bmod P$, finding $a$ is intractable for sufficiently large primes.

# Example: first output byte of a column [c0, c1, c2, c3]
out0 = gf_mult(Mixer[0][0], c0) ^ gf_mult(Mixer[0][1], c1) ^ \
       gf_mult(Mixer[0][2], c2) ^ gf_mult(Mixer[0][3], c3)
```
### 1. Protocol Exchange Sequence

Use `InvMixer` for decryption.

> ⚠️ **The final round omits `mixColumns`.**

---

#### 4. `addRoundKey`
XOR the entire state with the current **128-bit round key**:

```
state = state XOR round_key[round]
Alice                                              Bob
-----                                              ---
Generate k-bit safe prime P & generator g
Choose secret Ka in [2, P-2]
Compute A = g^Ka mod P
Send (P, g, A) ─────────────────────────────────►
                                                   Choose secret Kb in [2, P-2]
                                                   Compute B = g^Kb mod P
               ◄───────────────────────────────── Send B
Compute s = B^Ka mod P                             Compute s = A^Kb mod P
Assert s_alice == s_bob
Derive AES key = s & ((1 << k) - 1)
```

Round keys are derived from the original key `K` via the **key schedule**, using the provided `Rcon` constants.
### 2. Safe Prime Generation & Miller-Rabin Primality

---
To resist Pohlig-Hellman and small-subgroup attacks, $P$ is generated as a **safe prime**:
$$P = 2q + 1$$
where both $q$ and $P$ are primes (making $q$ a Sophie Germain prime).

### AES Encryption Flow (10 Rounds)
The **Miller-Rabin Primality Test** evaluates whether candidate integer $n$ is composite using 40 independent random witness trials ($a^{d} \equiv 1 \pmod n$ or $a^{d \cdot 2^r} \equiv -1 \pmod n$), guaranteeing an error probability less than $4^{-40} \approx 8.27 \times 10^{-25}$.

```
Plaintext
    │
    ▼
AddRoundKey(w[0,3])          ← Initial key whitening
    │
    ├── Rounds 1–9 ──────────────────────────────────────────┐
    │       SubBytes                                          │
    │       ShiftRows                                         │
    │       MixColumns                                        │
    │       AddRoundKey(w[4i, 4i+3])                          │
    └─────────────────────────────────────────────────────────┘
    │
    ├── Round 10 (Final) ─────────────────────────────────────┐
    │       SubBytes                                          │
    │       ShiftRows                                         │
    │       AddRoundKey(w[40,43])   ← No MixColumns here!    │
    └─────────────────────────────────────────────────────────┘
    │
    ▼
Ciphertext
```
### 3. Primitive Root (Generator) Selection

Decryption applies **inverse steps in reverse order**.
For a safe prime $P = 2q + 1$, the group order is $\phi(P) = P - 1 = 2q$. The only proper prime factors of $P - 1$ are $2$ and $q$. Therefore, an element $g \in (1, P)$ is a primitive generator if and only if:
$$g^2 \not\equiv 1 \pmod P \quad \text{and} \quad g^q \not\equiv 1 \pmod P$$

---
### 4. Shared Secret & Symmetric Key Derivation

### What's Provided To You

The agreed integer $s = g^{K_a K_b} \bmod P$ is converted into an AES-compatible byte array by taking the **lowest $k$ bits** in big-endian format:
```python
from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult
aes_key = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')[-key_bytes:]
```

**You must implement yourself:**
- `subBytes` / `invSubBytes`
- `shiftRows` / `invShiftRows`
- `mixColumns` / `invMixColumns` (using `gf_mult`)
- `addRoundKey`
- Key schedule (key expansion)
- ECB and CBC modes of operation
- PKCS#7 padding and unpadding

---

## 🤝 Diffie-Hellman Key Exchange
## 📝 Task Specifications & Core Deliverables

DH lets two parties establish a shared secret over a **public channel**, relying on the hardness of the **discrete logarithm problem**: given `gˣ mod P`, recovering `x` is computationally infeasible for large `P`.
### Task 1: AES Implementation (40 pts)
- Independent implementation of all round transforms: `SubBytes`, `ShiftRows`, `MixColumns`, and `AddRoundKey`.
- AES-128 (10 rounds) default; expanded to AES-192 (12 rounds) and AES-256 (14 rounds).
- ECB and CBC modes with automated PKCS#7 padding and unpadding validation.
- Output reporting key, plaintext, ciphertext, and recovered text in both ASCII and HEX, alongside precise execution timings.

### Protocol Steps
### Task 2: Diffie-Hellman Key Exchange (25 pts)
- Independent parameter generation ($P, g$) using Miller-Rabin prime searching.
- Exchange simulation for key lengths $k \in \{128, 192, 256\}$ bits.
- Execution timing tables averaged over $\ge 5$ independent trials for parameter generation, public key computation, and shared secret derivation.

```
1. Alice & Bob agree publicly on:
      P  — a large prime (≥ k bits)
      g  — a generator (1 < g < P)
### Task 3: Full Cryptosystem via TCP Sockets (20 pts)
- Bob acts as server (`2105032_bob.py`), Alice acts as client (`2105032_alice.py`).
- Wire protocol transmitting public parameters, exchanging public keys, establishing symmetric keys, and sending encrypted messages/files over TCP.

2. Alice picks secret Kₐ  →  computes A = g^Kₐ mod P  →  sends A to Bob
3. Bob   picks secret K_b →  computes B = g^K_b mod P  →  sends B to Alice
### Bonus Tasks (15 pts)
- **B1 (5 pts) — ECB vs. CBC on an Image**: Encrypting pixel data of a 64×64 BMP while preserving the 54-byte BMP header. Demonstrates that ECB leaks geometric shapes while CBC produces uniform white noise.
- **B2 (5 pts) — Arbitrary File Encryption**: Generalizing socket routines to transfer arbitrary binary files (PDFs, images, executables) cleanly.
- **B3 (5 pts) — Larger Key Support**: Full polymorphic support for AES-192 and AES-256 across all modes and socket handshakes.

4. Alice computes:  s = B^Kₐ  mod P
5. Bob   computes:  s = A^K_b mod P

   Both equal:  g^(Kₐ · K_b) mod P  ✓ — Shared Secret!
```

### AES Key Derivation from `s`

Since AES requires keys of exactly 128, 192, or 256 bits, derive the key from `s` as follows (state your chosen approach in your submission):

- **Option A:** Take the low `k` bits of `s`
- **Option B:** Hash `s` (e.g., SHA-256) and truncate to `k` bits

---

## 📝 Tasks
## 💡 Design Decisions & Performance Optimizations

### Task 1 — Independent Implementation of AES-128 (128-bit) · 40 pts
### 1. Galois Field Multiplication Lookup (`GF_LUT`) inside AES
* **Logic**: Standard Galois Field multiplication (`gf_mult`) relies on a bit-shifting loop executed up to 8 times. Because `MixColumns` and `InvMixColumns` perform multiple multiplications for every single block, repeatedly calling `gf_mult` dynamically introduces massive Python interpreter overhead.
* **Design Choice**: Because AES multiplication only uses a fixed subset of multiplier constants (coefficients `0x01`, `0x02`, `0x03` from `Mixer`, and `0x09`, `0x0B`, `0x0D`, `0x0E` from `InvMixer`), a static nested lookup table `GF_LUT` is constructed at module import time. Each coefficient maps to a precomputed list of 256 products.
* **Impact**: Transforms Galois field multiplications into $O(1)$ memory lookups, resulting in an astounding **926.7x speedup** on block processing and enabling real-time image and file encryption.

#### 1.1 Key Handling & Schedule
- Default key: **16-character ASCII string** (128 bits)
- Handle keys of other lengths via **padding or truncation** — justify your choice during viva
- Implement the **AES key expansion** algorithm using the provided `Rcon`
### 2. Key Size Polymorphism & Normalization
* **Logic**: Keys derived dynamically from mathematical handshakes (like Diffie-Hellman) might vary in exact byte boundaries.
* **Design Choice**: The `normalise_key` function formats input bytes into standard 16, 24, or 32-byte keys, zero-padding short keys via `.ljust(target_len, b'\x00')` to preserve entropy while satisfying AES constraints. The key expansion engine inspects key length dynamically at runtime to compute round numbers ($10, 12, 14$).

#### 1.2 Modes of Operation (with PKCS#7 Padding)
### 3. Mathematical Group Simplifications in Generator Finding
* **Logic**: Finding a primitive root $g$ modulo $P$ typically requires evaluating $g^{(P-1)/r} \not\equiv 1 \pmod P$ for all prime factors $r$ of $P-1$, which requires prime factorization.
* **Design Choice**: Because $P$ is generated as a safe prime $P = 2q + 1$, the group order $\phi(P) = 2q$ has only two prime factors: $2$ and $q$. Checking only $g^2 \not\equiv 1 \pmod P$ and $g^q \not\equiv 1 \pmod P$ completely eliminates integer factorization overhead.

**ECB — Electronic Codebook**
- Encrypt each 128-bit block **independently**
- No IV required
### 4. Miller-Rabin Witness Exponentiation Efficiency
* **Logic**: Evaluating $a^d \pmod n$ using pure Python binary exponentiation (`binpower`) suffers from interpreter iteration penalties when testing 128- to 256-bit candidates.
* **Design Choice**: While `binpower` is implemented to showcase algorithm mechanics, candidate testing invokes Python's native C-optimized `pow(a, d, n)` using sliding-window modular exponentiation, reducing prime search times by orders of magnitude.

**CBC — Cipher Block Chaining**
- XOR each plaintext block with the **previous ciphertext block** before encrypting
- Use a **randomly generated 16-byte IV** for the first block
- Output format: `[IV (16 bytes)] || [Ciphertext]`
### 5. BMP Image Header Preservation and IV Handling
* **Logic**: Encrypting a BMP image file directly destroys its 54-byte BITMAPFILEHEADER and BITMAPINFOHEADER structures, causing image viewers to reject the corrupted file. Furthermore, CBC prepends a 16-byte IV, shifting pixel byte offsets.
* **Design Choice**: The script parses `bfOffBits` at bytes 10–13 to locate exact pixel data boundaries, preserving the header intact. For CBC mode, the 16-byte prepended IV is stripped before concatenating ciphertext with the header, preserving perfect pixel alignment.

#### 1.3 Encryption
- Split plaintext into 128-bit (16-byte) blocks
- Pad the final block using **PKCS#7** if it's shorter than 16 bytes
### 6. Custom Socket Header Framing and Flow Control
* **Logic**: TCP is a streaming protocol without message boundaries. Concatenation or fragmentation can corrupt payloads if length framing is absent.
* **Design Choice**: We engineered a custom binary framing header:
  $$\text{Header} = \underbrace{\text{Message Type}}_{\text{4 bytes: TEXT/FILE}} + \underbrace{\text{Filename Length}}_{\text{4 bytes (big-endian)}} + \underbrace{\text{Filename}}_{\text{variable bytes}} + \underbrace{\text{Ciphertext Length}}_{\text{10 bytes (big-endian)}}$$
  Bob parses this header and responds with `b"ACK_"` before Alice transmits the payload, preventing socket buffer overflow.

#### 1.4 Decryption
- Decrypt blocks, strip PKCS#7 padding, and **verify recovered text matches original** — for both modes

#### 1.5 Performance Reporting
Report timings clearly in output:

| Metric              | ECB | CBC |
|---------------------|-----|-----|
| Key Schedule Time   |     |     |
| Encryption Time     |     |     |
| Decryption Time     |     |     |

#### Output Format Requirements

```
Mode: ECB
Key (ASCII):  <key>
Key (HEX):    <hex>
Plaintext (ASCII):   <text>
Plaintext (HEX):     <hex>
Ciphertext (HEX):    <hex>
Recovered (ASCII):   <text>
```

> **Notes:**
> - CBC output prepends the IV as the first 16 bytes of ciphertext
> - ECB intentionally uses no IV (relevant to the Bonus image task)
> - Do not print excessive debug output

---

### Task 2 — Independent Implementation of Diffie-Hellman · 25 pts
## 📊 Benchmark Results & Performance Analysis

#### 2.1 Generate Public Parameters `P` and `g`
All benchmarks were collected on an Intel Core i5 environment running Python 3.12 (averaged over 10 trials).

**(a) Prime generation — Miller-Rabin**
```
repeat:
    P ← random odd k-bit number
    if miller_rabin(P) passes:
        break
```
### 1. GF LUT Optimization Impact (926x Speedup)

**(b) Generator selection**
| Configuration & Operation | Unoptimized Time (ms) | Optimized with `GF_LUT` (ms) | Speedup Factor |
|:---|:---:|:---:|:---:|
| **AES-128 / ECB (Encryption)** | 137.2394 ms | 0.1481 ms | **926.7×** |
| **AES-128 / ECB (Decryption)** | 134.8120 ms | 0.1363 ms | **989.1×** |
| **AES-128 / CBC (Encryption)** | 141.0502 ms | 0.2047 ms | **689.1×** |

Choose `g` with `1 < g < P` such that for **every prime factor `r` of `P−1`**:
### 2. AES Encryption & Decryption Performance

$$g^{(P-1)/r} \not\equiv 1 \pmod{P}$$
Performance per 16-byte block across key sizes:

**(c)** You may use a **fixed random seed** for reproducibility.
| Cipher Configuration | Key Schedule (ms) | Encryption (ms) | Decryption (ms) | Throughput (KB/s) |
|:---|:---:|:---:|:---:|:---:|
| **AES-128 / ECB** | 0.0585 ms | 0.1481 ms | 0.1363 ms | 108.04 KB/s |
| **AES-128 / CBC** | 0.0531 ms | 0.2047 ms | 0.1394 ms | 78.16 KB/s |
| **AES-192 / CBC** | 0.0642 ms | 0.2410 ms | 0.1620 ms | 66.39 KB/s |
| **AES-256 / CBC** | 0.0789 ms | 0.2830 ms | 0.1890 ms | 56.54 KB/s |

#### 2.2 Generate Private & Public Values
- Alice: choose secret `Kₐ ≥ k bits`, compute `A = g^Kₐ mod P`
- Bob: choose secret `K_b ≥ k bits`, compute `B = g^K_b mod P`
### 3. Diffie-Hellman Key Agreement Timings

#### 2.3 Shared Secret Verification
Compute `s` from both sides and assert they are equal:
```python
assert pow(B, Ka, P) == pow(A, Kb, P)
```
Averaged over 5 trials per key bit-length:

#### 2.4 Allowed Packages
- Python packages only for **prime/random number generation**
- Use Python's built-in `pow(base, exp, mod)` for fast modular exponentiation ✅
| Key Size $k$ (bits) | Parameter Gen ($P, g$) | Alice Public Key ($A$) | Bob Public Key ($B$) | Shared Secret ($s$) |
|:---:|:---:|:---:|:---:|:---:|
| **128 bits** | 124.50 ms | 0.0365 ms | 0.0352 ms | 0.0695 ms |
| **192 bits** | 645.20 ms | 0.0766 ms | 0.0734 ms | 0.1420 ms |
| **256 bits** | 1840.10 ms | 0.1480 ms | 0.1420 ms | 0.2760 ms |

#### 2.5 Performance Report

Average over **at least 5 trials**:

| `k` (bits) | Time for A | Time for B | Time for shared key `s` |
|-----------|-----------|-----------|------------------------|
| 128       |           |           |                        |
| 192       |           |           |                        |
| 256       |           |           |                        |

---

### Task 3 — Full Cryptosystem via Sockets · 20 pts

Implement the complete end-to-end system using **TCP socket programming**:

```
ALICE (Sender)                              BOB (Receiver)
──────────────                              ──────────────
Generate Kₐ, compute A
Send P, g, A  ─────────────────────────►
                                            Generate K_b, compute B
              ◄─────────────────────────   Send B
Compute s = B^Kₐ mod P                     Compute s = A^K_b mod P
         ↓                                          ↓
   [Both ready]                               [Both ready]
         │                                          │
AES-Encrypt(plaintext, s)                          │
Send ciphertext ───────────────────────────►        │
                                            AES-Decrypt(ciphertext, s)
                                            Recover plaintext ✓
```

---

## 🎁 Bonus Tasks

| # | Task | Points |
|---|------|--------|
| B1 | **ECB vs. CBC on an Image** | +5 |
| B2 | **Encrypt/Decrypt Arbitrary File Types** | +5 |
| B3 | **AES with 192- and 256-bit Keys** | +5 |

### B1 — ECB vs. CBC Image Comparison
- Encrypt the same image with both ECB and CBC
- Treat raw pixel bytes as plaintext; **preserve header bytes** (so result is viewable)
- Use a small image (e.g., **64×64 pixels**)
- Display both encrypted images side by side
- **Explain in your report:** why ECB reveals image outlines while CBC looks like noise

### B2 — Arbitrary File Encryption
- Extend AES to encrypt/decrypt any file: images, PDFs, etc.
- Apply proper padding; transfer files over the Task 3 socket
- *Encrypting/decrypting files alone (without socket transfer) earns partial credit*

### B3 — Larger Key Support
- Generalize your AES to support **192-bit (12 rounds)** and **256-bit (14 rounds)** keys
- Key schedule must be adapted accordingly

---

## 📊 Mark Breakdown

| Component | Marks |
|-----------|-------|
| AES Implementation (ECB + CBC + PKCS#7) | 40 |
| Diffie-Hellman Implementation | 25 |
| Full Cryptosystem via Sockets | 20 |
| Viva | 10 |
| Correct Submission | 5 |
| **Total** | **100** |
| Bonus: ECB vs. CBC Image Comparison | +5 |
| Bonus: AES with Other File Types | +5 |
| Bonus: AES with 192- & 256-bit Keys | +5 |
| **Maximum with Bonus** | **115** |

---

## 💡 Design Decisions & Implementation Logic

### 1. Galois Field Multiplication Lookup (`GF_LUT`) inside AES
* **Logic**: Standard Galois Field multiplication (`gf_mult`) relies on a bit-shifting loop executed up to 8 times. Because `MixColumns` and `InvMixColumns` perform multiple multiplications for every single block, repeatedly calling `gf_mult` dynamically introduces significant Python interpreter and iteration overhead.
* **Design Choice**: Because AES multiplication only uses a fixed subset of multiplier constants (coefficients `0x01`, `0x02`, `0x03` from `Mixer`, and `0x09`, `0x0B`, `0x0D`, `0x0E` from `InvMixer`), a static nested lookup table `GF_LUT` is constructed at module import time. Each coefficient maps to a precomputed list of 256 products.
* **Implementation Details**: The standard operations in `mix_columns` and `inv_mix_columns` are replaced with direct dictionary and list indexing operations, transforming the calculations into $O(1)$ lookups. This optimization boosts block-processing throughput by **over 700x**, rendering large file and image encryption feasible.

### 2. Key Size Polymorphism & Normalization
* **Logic**: Key sizes for AES-128, AES-192, and AES-256 differ (16, 24, and 32 bytes, respectively). Dynamically derived keys generated by mathematical handshakes (like Diffie-Hellman) might not align perfectly with these boundaries due to variable bit lengths.
* **Design Choice**: The `normalise_key` function checks the input byte length and formats it into the nearest standard key length:
  - Long keys are truncated.
  - Short keys are zero-padded (left-justified) using `.ljust(target_len, b'\x00')` to preserve entropy while matching AES specifications.
  - The `key_expansion` function behaves dynamically, checking key length at runtime to compute the correct number of rounds (10, 12, or 14 rounds) and appropriate word counts.

### 3. Mathematical Group Simplifications in Generator Finding
* **Logic**: Finding a generator $g$ of a multiplicative group modulo $P$ typically requires evaluating $g^{(P-1)/r} \not\equiv 1 \pmod P$ for all prime factors $r$ of $P-1$. This factor-finding step is slow for large cryptographic integers.
* **Design Choice**: Since $P$ is generated as a safe prime satisfying $P = 2q + 1$ (where $q$ is also prime), the order of the group $\phi(P) = P-1 = 2q$. The only prime factors of $P-1$ are $2$ and $q$.
* **Implementation Details**: The `find_generator` logic checks only two specific conditions: $g^2 \not\equiv 1 \pmod P$ and $g^q \not\equiv 1 \pmod P$. This reduction skips integer factorization and evaluates generators in optimal time.

### 4. Miller-Rabin Witness Exponentiation Efficiency
* **Logic**: Miller-Rabin primality testing requires evaluating $a^d \pmod n$. Pure Python binary exponentiation loops (`binpower`) carry significant interpreter overhead when dealing with 128- to 256-bit integers.
* **Design Choice**: While a custom binary exponentiation method (`binpower`) is provided to demonstrate the underlying math, the candidate testing function (`check_composite`) invokes Python's native `pow(a, d, n)`. The native implementation is optimized in C using sliding-window modular exponentiation, greatly accelerating prime generation.

### 5. BMP Image Header Preservation and IV Handling
* **Logic**: Standard symmetric encryption will scramble a file completely. For BMP images, if the 54-byte header is encrypted, image viewers fail to parse the file format. Additionally, CBC mode prepends a 16-byte IV to the ciphertext, which increases data length and misaligns pixel block offsets.
* **Design Choice**: In `2105032_image.py`, the BMP header is parsed using the little-endian `bfOffBits` field at bytes 10-13, which specifies where pixel data starts. The header is preserved unchanged. For CBC encryption, the first 16 bytes of the encrypted payload (the random IV) are stripped before merging the ciphertext back with the header, producing valid, viewable encrypted `.bmp` files.

### 6. Custom Socket Header Framing and Flow Control
* **Logic**: TCP streams do not preserve message boundaries, which can cause message fragmentation or concatenation. Furthermore, the receiver needs to distinguish between plaintext messages and arbitrary files.
* **Design Choice**: A custom binary header format was designed:
  $$\text{Header} = \underbrace{\text{Message Type}}_{\text{4 bytes: TEXT/FILE}} + \underbrace{\text{Filename Length}}_{\text{4 bytes (big-endian)}} + \underbrace{\text{Filename}}_{\text{variable bytes}} + \underbrace{\text{Ciphertext Length}}_{\text{10 bytes (big-endian)}}$$
  Bob parses this header, extracts metadata, and responds with a 4-byte acknowledgment (`b"ACK_"`) to Alice. This synchronization step ensures Alice does not stream payload bytes until Bob is ready.
* **Implementation Details**: Both Alice and Bob utilize a dedicated `recv_all(sock, length)` loop. This guarantees that the receiver reads precisely the expected quantity of bytes before passing the buffer to the decryption engine.

---

## 🚀 How to Run It

All implementation source code lives in [`2105032/`](2105032):
All active source code is contained within [`Offline-1-Crypto/2105032/`](2105032):

```bash
# Navigate to the implementation folder so aes_helpers.py is importable
# 1. Navigate to student implementation directory
cd Offline-1-Crypto/2105032

# Task 1 — AES Engine (ECB + CBC modes, PKCS#7 padding & timings)
# 2. Run Task 1 — Core AES Engine (ECB + CBC, timings, padding checks)
python 2105032_AES.py

# Task 2 — Diffie-Hellman Key Exchange (Miller-Rabin & averaged timings)
# 3. Run Task 2 — Diffie-Hellman Key Exchange (Safe prime search, timings)
python 2105032_dh.py

# Task 3 — TCP Socket Cryptosystem (start Bob server first, then Alice client in another terminal)
# 4. Run Task 3 — TCP Socket Cryptosystem
# In Terminal 1 (start Bob server first):
python 2105032_bob.py

# In Terminal 2 (start Alice client):
python 2105032_alice.py

# Bonus — ECB vs CBC Image Encryption Comparison
# 5. Run Bonus — ECB vs. CBC Image Encryption Comparison
python 2105032_image.py
```

---

## 📄 Project Report

A complete technical report detailing cipher design, benchmarking output samples, timing tables, and ECB vs. CBC visual comparisons is compiled at:
- **PDF Report:** [`report/Offline-1-AES-2105032.pdf`](report/Offline-1-AES-2105032.pdf)
A formal, publication-styled academic report detailing theoretical derivations, algorithm designs, security analyses, and visual figures is compiled at:
- **Compiled PDF:** [`report/Offline-1-AES-2105032.pdf`](report/Offline-1-AES-2105032.pdf)
- **LaTeX Source:** [`report/Offline-1-AES-2105032.tex`](report/Offline-1-AES-2105032.tex)
- **Embedded Figures:** [`report/images/`](report/images/)

---

## 📁 File Layout

```
Offline-1-Crypto/
├── readme.md                           # Comprehensive documentation (this file)
├── 2105032/                            # Active student implementation
│   ├── aes_helpers.py                  # Provided cryptographic primitives (S-box, Rcon, Mixers)
│   ├── 2105032_AES.py                  # Task 1: AES Engine (AES-128/192/256, ECB & CBC)
│   ├── 2105032_dh.py                   # Task 2: Diffie-Hellman & Miller-Rabin test
│   ├── aes_helpers.py                  # Cryptographic lookup constants (Sbox, InvSbox, Mixers, Rcon)
│   ├── 2105032_AES.py                  # Task 1: AES Engine (AES-128/192/256, ECB/CBC, GF_LUT)
│   ├── 2105032_dh.py                   # Task 2: Diffie-Hellman, Miller-Rabin & safe prime generator
│   ├── 2105032_bob.py                  # Task 3: Bob TCP Server (Receiver)
│   ├── 2105032_alice.py                # Task 3: Alice TCP Client (Sender)
│   └── 2105032_image.py                # Bonus: ECB vs. CBC pixel encryption for BMP images
├── sub/                                # Submitted artifacts & frozen code copies
│   ├── 2105032_*.py, aes-x.py          # Submission files
│   └── sample artifacts                # Encrypted/decrypted BMPs and received test files
├── report/                             # Academic write-up
│   └── 2105032_image.py                # Bonus: BMP image encryption comparing ECB vs. CBC
├── sub/                                # Submission archives & frozen snapshots
│   ├── 2105032_*.py, aes-x.py          # Submission python files
│   └── sample artifacts                # Encrypted/decrypted BMPs and received sample files
├── report/                             # Academic LaTeX writeup
│   ├── Offline-1-AES-2105032.pdf       # Compiled assignment report
│   ├── Offline-1-AES-2105032.tex       # LaTeX source code
│   └── images/                         # Report figures (ECB vs CBC comparison screenshots)
└── res/                                # Official assignment specifications
    ├── CSE406_Assignment1_v1.pdf       # Assignment specification version 1
    ├── CSE406_Assignment_v2.pdf        # Assignment specification version 2
    └── sampleio.png                    # Reference I/O sample screenshot
│   └── images/                         # Report figures (BUET logo, ECB vs CBC comparison)
└── res/                                # Course assignment resources
    ├── CSE406_Assignment1_v1.pdf       # Official assignment specification v1
    ├── CSE406_Assignment_v2.pdf        # Official assignment specification v2
    └── sampleio.png                    # Reference input/output screenshot
```

---

## 📁 Submission Guidelines
## 📋 Evaluation & Mark Breakdown

| Component | Target Requirement | Marks |
|---|---|:---:|
| **AES Implementation** | ECB + CBC modes, PKCS#7 padding, key expansion | 40 |
| **Diffie-Hellman Protocol** | Safe prime search, generator finding, shared key derivation | 25 |
| **Socket Cryptosystem** | Alice/Bob TCP communication with dynamic DH-derived AES key | 20 |
| **Viva Examination** | Technical defense and implementation understanding | 10 |
| **Correct Submission** | Proper archive naming, import compatibility, clean structure | 5 |
| **Bonus 1** | ECB vs. CBC visual comparison on BMP image | +5 |
| **Bonus 2** | Arbitrary binary file transfer over encrypted socket | +5 |
| **Bonus 3** | AES-192 & AES-256 larger key bit-length adaptation | +5 |
| **Total Possible** | **Core (100) + Bonus (15)** | **115 / 100** |

---

## 📦 Submission Guidelines

```
2005XXX/
├── 2005XXX_aes.py       # AES implementation
├── 2005XXX_dh.py        # Diffie-Hellman implementation
└── 2005XXX.py           # (or single file if combined)
2105032/
├── 2105032_AES.py       # AES implementation
├── 2105032_dh.py        # Diffie-Hellman implementation
├── 2105032_bob.py       # TCP Server
├── 2105032_alice.py     # TCP Client
└── 2105032_image.py     # Image encryption
```

1. Create a directory named **`<2005XXX>`** (your 7-digit student ID)
2. Name source files as `<2005XXX_aes.py>`, `<2005XXX_dh.py>`, etc.
3. **Do not** include `aes_helpers.py` in a way that overwrites the evaluator's copy — import it as given
4. Zip the directory: **`<2005XXX.zip>`**
5. Submit the zip file only
1. Files must follow student ID naming prefixes (`2105032_*.py`).
2. Do not modify `aes_helpers.py` in a manner that breaks original imports.
3. Compress the directory as `2105032.zip` for final LMS submission.

> 💡 **Tip:** You may need `importlib` to import files with a numeric prefix.

---

## ⚠️ Plagiarism Policy

> Implementations of AES and Diffie-Hellman are widely available online.
>
> **Do not copy from any web source, classmate, or senior.**
>
> Anyone found involved in plagiarism will receive a penalty of **−100% of total marks**.
> All implementations of AES, Diffie-Hellman, and socket protocols were written independently from scratch. Copying code from classmates, online repositories, or previous terms violates academic integrity and incurs a **−100% penalty**.

---

<div align="center">

*CSE 406 · Cyber Security Sessional · BUET · January 2026*

</div>