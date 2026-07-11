# 🔐 CSE 406 — Cyber Security Sessional
## Assignment 01: AES + Diffie-Hellman Cryptosystem

> **Course:** CSE 406 · Cyber Security Sessional · January 2026
> **Deadline:** 11:59 PM, 3 July 2026

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
- [Submission Guidelines](#-submission-guidelines)
- [Plagiarism Policy](#%EF%B8%8F-plagiarism-policy)

---

## 🌐 Overview

The goal of this assignment is to build a complete **symmetric-key cryptosystem** from scratch:

1. Two parties exchange a secret key securely using **Diffie-Hellman** over a finite field.
2. The sender encrypts plaintext using **AES-128** with the shared key.
3. The ciphertext travels over a channel (TCP socket); the receiver decrypts it.

> You are **not** required to implement Galois field arithmetic from scratch — finite-field building blocks are provided in `aes_helpers.py`. Focus on cipher structure and algorithmic correctness.

---

## 🏗 System Architecture

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

AES is a block cipher that operates on a **4×4 byte state matrix** (128 bits). It runs for:

| Key Size | Rounds |
|----------|--------|
| 128-bit  | 10     |
| 192-bit  | 12     |
| 256-bit  | 14     |

**This assignment targets AES-128 (10 rounds).** Each round (except the last) consists of four operations applied in sequence:

---

### Round Operations

#### 1. `subBytes` / `invSubBytes`
Replace every byte in the state using a fixed 256-entry S-box lookup table.

```
state[i][j] = Sbox[ state[i][j] ]          # encryption
state[i][j] = InvSbox[ state[i][j] ]       # decryption
```

Both `Sbox` and `InvSbox` are provided in `aes_helpers.py`.

---

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

```python
# You do NOT implement field arithmetic — use the provided helper:
from aes_helpers import gf_mult, Mixer, InvMixer

# Example: first output byte of a column [c0, c1, c2, c3]
out0 = gf_mult(Mixer[0][0], c0) ^ gf_mult(Mixer[0][1], c1) ^ \
       gf_mult(Mixer[0][2], c2) ^ gf_mult(Mixer[0][3], c3)
```

Use `InvMixer` for decryption.

> ⚠️ **The final round omits `mixColumns`.**

---

#### 4. `addRoundKey`
XOR the entire state with the current **128-bit round key**:

```
state = state XOR round_key[round]
```

Round keys are derived from the original key `K` via the **key schedule**, using the provided `Rcon` constants.

---

### AES Encryption Flow (10 Rounds)

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

Decryption applies **inverse steps in reverse order**.

---

### What's Provided To You

```python
from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult
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

DH lets two parties establish a shared secret over a **public channel**, relying on the hardness of the **discrete logarithm problem**: given `gˣ mod P`, recovering `x` is computationally infeasible for large `P`.

### Protocol Steps

```
1. Alice & Bob agree publicly on:
      P  — a large prime (≥ k bits)
      g  — a generator (1 < g < P)

2. Alice picks secret Kₐ  →  computes A = g^Kₐ mod P  →  sends A to Bob
3. Bob   picks secret K_b →  computes B = g^K_b mod P  →  sends B to Alice

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

### Task 1 — Independent Implementation of AES-128 (128-bit) · 40 pts

#### 1.1 Key Handling & Schedule
- Default key: **16-character ASCII string** (128 bits)
- Handle keys of other lengths via **padding or truncation** — justify your choice during viva
- Implement the **AES key expansion** algorithm using the provided `Rcon`

#### 1.2 Modes of Operation (with PKCS#7 Padding)

**ECB — Electronic Codebook**
- Encrypt each 128-bit block **independently**
- No IV required

**CBC — Cipher Block Chaining**
- XOR each plaintext block with the **previous ciphertext block** before encrypting
- Use a **randomly generated 16-byte IV** for the first block
- Output format: `[IV (16 bytes)] || [Ciphertext]`

#### 1.3 Encryption
- Split plaintext into 128-bit (16-byte) blocks
- Pad the final block using **PKCS#7** if it's shorter than 16 bytes

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

#### 2.1 Generate Public Parameters `P` and `g`

**(a) Prime generation — Miller-Rabin**
```
repeat:
    P ← random odd k-bit number
    if miller_rabin(P) passes:
        break
```

**(b) Generator selection**

Choose `g` with `1 < g < P` such that for **every prime factor `r` of `P−1`**:

$$g^{(P-1)/r} \not\equiv 1 \pmod{P}$$

**(c)** You may use a **fixed random seed** for reproducibility.

#### 2.2 Generate Private & Public Values
- Alice: choose secret `Kₐ ≥ k bits`, compute `A = g^Kₐ mod P`
- Bob: choose secret `K_b ≥ k bits`, compute `B = g^K_b mod P`

#### 2.3 Shared Secret Verification
Compute `s` from both sides and assert they are equal:
```python
assert pow(B, Ka, P) == pow(A, Kb, P)
```

#### 2.4 Allowed Packages
- Python packages only for **prime/random number generation**
- Use Python's built-in `pow(base, exp, mod)` for fast modular exponentiation ✅

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

## 📁 Submission Guidelines

```
2005XXX/
├── 2005XXX_aes.py       # AES implementation
├── 2005XXX_dh.py        # Diffie-Hellman implementation
└── 2005XXX.py           # (or single file if combined)
```

1. Create a directory named **`<2005XXX>`** (your 7-digit student ID)
2. Name source files as `<2005XXX_aes.py>`, `<2005XXX_dh.py>`, etc.
3. **Do not** include `aes_helpers.py` in a way that overwrites the evaluator's copy — import it as given
4. Zip the directory: **`<2005XXX.zip>`**
5. Submit the zip file only

> 💡 **Tip:** You may need `importlib` to import files with a numeric prefix.

---

## ⚠️ Plagiarism Policy

> Implementations of AES and Diffie-Hellman are widely available online.
>
> **Do not copy from any web source, classmate, or senior.**
>
> Anyone found involved in plagiarism will receive a penalty of **−100% of total marks**.

---

<div align="center">

*CSE 406 · Cyber Security Sessional · BUET · January 2026*

</div>