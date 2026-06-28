# CSE 406 — Cyber Security

Repo for the CSE 406 coursework assignments.

---

## Offline 1 — Cryptography (Diffie-Hellman + AES)

**Goal.** Implement a symmetric-key cryptosystem where the AES key is
securely agreed between sender and receiver using Diffie-Hellman key
exchange over a finite field, then used to encrypt and decrypt
plaintext transmitted over an arbitrary channel.

The full task statement is in [`CSE406_Assignment1_v1.pdf`](Offline-1-Crypto\res\CSE406_Assignment1_v1.pdf).

### Cryptosystem at a glance

```
Alice                              Bob
-----                              ---
choose Ka, send A = g^Ka mod P ──►
              ◄── send B = g^Kb mod P
s = B^Ka mod P                     s = A^Kb mod P      (same s on both sides)
derive AES key from s (low k bits)
encrypt PT with AES, send CT ───►
                                   decrypt CT with same AES key
```

### AES (Task 1 — 40 marks)

- AES-128 (10 rounds); implementation extended to AES-192 / AES-256 as
  a bonus.
- Four round transforms: `subBytes`, `shiftRows`, `mixColumns`,
  `addRoundKey`. Final round omits `mixColumns`.
- Two modes of operation:
  - **ECB** — each 16-byte block encrypted independently (no IV).
  - **CBC** — each plaintext block XORed with the previous ciphertext
    block before encryption; a random 16-byte IV is prepended.
- PKCS#7 padding so plaintexts of any length round-trip cleanly.
- Output format: key / plaintext / padded plaintext / ciphertext /
  deciphered (before & after unpadding) in both ASCII and HEX, plus
  timings for key schedule, encryption, and decryption.

### Diffie-Hellman (Task 2 — 25 marks)

- Random k-bit prime modulus `P`; generator `g` in `(1, P)`.
- Alice picks random `Ka ≥ k bits`, sends `A = g^Ka mod P`.
- Bob picks random `Kb ≥ k bits`, sends `B = g^Kb mod P`.
- Shared secret `s = B^Ka mod P = A^Kb mod P` (verified equal on both
  sides).
- AES key derived as the **low k bits** of `s`, big-endian, length
  k/8 bytes.
- Timings for k = 128, 192, 256 averaged over ≥ 5 trials.

### TCP socket cryptosystem (Task 3 — 20 marks)

- Bob listens, Alice connects.
- Wire protocol: each message is a 4-byte big-endian length followed
  by that many bytes. Integers are sent as ASCII decimal; the AES
  ciphertext is sent as raw bytes.
- Alice encrypts the plaintext with AES-CBC using the DH-derived key
  and sends it; Bob decrypts and prints the recovered plaintext.

### Bonus tasks (5 + 5 + 5 marks)

1. **ECB vs CBC on an image** — encrypt the pixel bytes of a 64×64 BMP
   with both modes (header preserved). ECB keeps the outline of the
   original (identical plaintext blocks → identical ciphertext
   blocks); CBC destroys the repetition and looks like random noise.
2. **Other file types** — the modes take arbitrary `bytes`, so any
   file (image, PDF, …) round-trips once padded. The same socket code
   can carry arbitrary-length ciphertext.
3. **Larger keys (192 / 256 bits)** — the key schedule, encrypt, and
   decrypt paths dispatch on key length, and the socket uses the
   matching DH size via `--k 192` / `--k 256`.

### Marks breakdown

| Task                                             | Marks |
| ------------------------------------------------ | ----- |
| AES (ECB + CBC, PKCS#7)                          | 40    |
| Diffie-Hellman key exchange                      | 25    |
| Whole cryptosystem over sockets                  | 20    |
| Viva                                             | 10    |
| Correct Submission                               | 5     |
| Bonus: ECB vs CBC on image                       | 5     |
| Bonus: AES with other file types                 | 5     |
| Bonus: AES with 192 / 256-bit keys               | 5     |

### How to run it

Everything lives in `Offline-1-Crypto/`. A virtual environment sits at
`Offline-1-Crypto/.venv` with `BitVector` and `sympy` pre-installed.

From a shell (PowerShell on Windows, or any POSIX shell):

```bash
# activate the venv (Windows PowerShell)
.\Offline-1-Crypto\.venv\Scripts\Activate.ps1
# (bash / zsh)
source Offline-1-Crypto/.venv/bin/activate

# move into the source folder so aes_helpers.py is importable
cd Offline-1-Crypto/raw

# Task 1 — AES (default: CBC, BUET key, "We need picnic")
python aes.py

# Task 2 — Diffie-Hellman (averaged timings + sample AES keys)
python dh.py

# Task 3 — sockets (run bob and alice in two terminals)
python socket_crypto.py bob
python socket_crypto.py alice --k 192

# Bonus — ECB vs CBC image
python image_bonus.py
```

If `python` isn't on `PATH`, replace it with the venv's interpreter,
e.g. `Offline-1-Crypto/.venv/Scripts/python.exe` on Windows or
`Offline-1-Crypto/.venv/bin/python` on macOS/Linux.

A step-by-step walkthrough with troubleshooting is in
[`Offline-1-Crypto/raw/walkthrough.md`](Offline-1-Crypto/raw/walkthrough.md).

### File layout

```
Offline-1-Crypto/
    .venv/                       # Python venv (BitVector, sympy)
    raw/
        aes_helpers.py           # provided — Sbox, InvSbox, Rcon, Mixer, gf_mult
        aes.py                   # Task 1
        dh.py                    # Task 2
        socket_crypto.py         # Task 3 (alice + bob in one file)
        image_bonus.py           # Bonus: ECB vs CBC on a 64x64 BMP
        README.md                # short overview
        walkthrough.md           # step-by-step test guide
        spec.md                  # assignment spec
        test.txt                 # sample expected output
```
