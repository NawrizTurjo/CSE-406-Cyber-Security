Edited 2105032_alice.py
Edited 2105032_bob.py
Edited 2105032_bob.py
Edited 2105032_image.py
Edited 2105032_AES.py
Edited he.txt
Viewed 2105032_alice.py:33-85

Here is how the file transmission and encryption/decryption workflow is handled on both the sender (Alice) and receiver (Bob) sides:

---

### 1. Sender Side (Alice)

1. **File Reading & Validation**:
   - Alice reads the file path provided by the user and checks if the file exists using `os.path.exists()`.
   - If it exists, the file is read in binary mode (`"rb"`) to obtain the raw payload bytes: 
     ```python
     with open(file_path, "rb") as f:
         payload = f.read()
     ```
   - The file name is extracted from the path using `os.path.basename()` and encoded to bytes.

2. **Encryption (CBC Mode)**:
   - Alice encrypts the payload bytes with the derived key using `aes_encrypt_cbc(payload, aes_key)`.
   - Under the hood, this function:
     - Applies **PKCS#7 padding** to the plaintext bytes to make the length a multiple of 16 bytes.
     - Generates a random 16-byte Initialization Vector (**IV**).
     - Encrypts the padded blocks sequentially in Cipher Block Chaining (CBC) mode.
     - Prepends the 16-byte IV to the encrypted blocks and returns the combined byte array.

3. **Local Encrypted Backup**:
   - Alice saves the encrypted ciphertext to a local file named `encrypted_<original_filename>` for local reference.

4. **Header Construction**:
   - To let Bob know what he is receiving, Alice builds a structured header containing metadata:
     $$\text{Header} = \underbrace{\text{msg\_type}}_{\text{4 bytes: "FILE"}} + \underbrace{\text{name\_len}}_{\text{4 bytes (big-endian length of filename)}} + \underbrace{\text{filename}}_{\text{raw bytes}} + \underbrace{\text{ct\_len}}_{\text{10 bytes (big-endian length of ciphertext)}}$$

5. **Transmission Protocol**:
   - Alice sends the structured header first.
   - She waits for a 4-byte acknowledgment (`ACK_`) from Bob.
   - Once received, she streams the entire ciphertext (IV + encrypted blocks) using `sendall()` and closes the connection.

---

### 2. Receiver Side (Bob)

1. **Metadata & Header Parsing**:
   - Bob reads the first 4 bytes to check the message type (`"FILE"`).
   - He reads the next 4 bytes to get the filename length, and then reads that many bytes to reconstruct the UTF-8 `filename`.
   - He reads the next 10 bytes to determine the exact total ciphertext length (`ct_len`).
   - Bob sends the 4-byte acknowledgment (`b"ACK_"`) back to Alice, signaling that he is ready for the encrypted payload.

2. **Ciphertext Buffering**:
   - Bob reads exactly `ct_len` bytes from the socket using a loop-based `recv_all(sock, length)` function. This ensures that the entire ciphertext payload is buffered into memory, handling any packet fragmentation.

3. **Decryption & Unpadding**:
   - Bob decrypts the buffered ciphertext using `aes_decrypt_cbc(ciphertext, aes_key)`.
   - Under the hood, this function:
     - Extracts the first 16 bytes as the **IV** and the rest as the actual ciphertext blocks.
     - Decrypts each block using the round keys and XORs it with the previous ciphertext block (or IV for the first block).
     - Runs `unpad_pkcs7()` to validate the padding scheme, strips off the padding bytes, and returns the original plaintext byte array.

4. **File Reconstruction**:
   - Bob saves the decrypted, unpadded bytes to disk in binary write mode (`"wb"`), prefixing the filename with `received_`:
     ```python
     out_name = "received_" + filename
     with open(out_name, "wb") as f:
         f.write(decrypted)
     ```
   - This cleanly restores the original file (e.g., `received_sampleio.png`) with the exact same bytes.

---

## Task-2: Miller-Rabin Primality Test Algorithm Analysis

The code in [2105032_dh.py](file:///e:/4-1%20Course%20Works/CSE-406-Cyber-Security/Offline-1-Crypto/2105032/2105032_dh.py) implements the **Miller-Rabin Primality Test**, which is a probabilistic algorithm used to determine if a given large integer $n$ is prime.

### 1. Mathematical Foundation
Every odd prime $p > 2$ satisfies a property derived from Fermat's Little Theorem. If we write $p - 1 = 2^s \cdot d$ (where $d$ is odd), then for any integer $a$ coprime to $p$, either:
1. $a^d \equiv 1 \pmod p$, or
2. $a^{2^r \cdot d} \equiv -1 \pmod p$ for some $0 \le r < s$.

If a candidate integer $n$ does not satisfy this property for a random base $a$ (witness), it is definitely composite. If it does satisfy it, $n$ is a *strong pseudoprime* to the base $a$.

---

### 2. Implementation Breakdown

#### A. Modular Exponentiation: `binpower(base, e, mod)`
* **Function**: Computes $\text{base}^e \pmod{\text{mod}}$ in $O(\log e)$ time.
* **Mechanism**: Uses the binary right-to-left exponentiation algorithm. It squares the base iteratively and multiplies the result whenever the current bit of the exponent $e$ is $1$ (checked via `e & 1`), shifting the exponent right (`e >>= 1`) at each step.
* *Note*: Inside `check_composite`, the built-in Python `pow(base, e, mod)` function is used instead because it is optimized in C and runs faster.

#### B. Composite Witness Check: `check_composite(n, a, d, s)`
* **Function**: Tests if the base $a$ proves that the number $n$ is composite.
* **Step 1**: It calculates $x = a^d \pmod n$. If $x == 1$ or $x == n - 1$, $n$ passes the test for this base (meaning it could be prime), so it returns `False` (not composite).
* **Step 2**: If the condition isn't met, it loops $s-1$ times, repeatedly squaring $x \pmod n$:
  - If $x$ becomes $n-1$, $n$ passes the test (returns `False`).
  - If $x$ becomes $1$ before reaching $n-1$, or if the loop completes without $x$ ever becoming $n-1$, then $n$ is mathematically proven to be composite. The function returns `True`.

#### C. Main Loop: `miller_rabin(n, iter=40)`
* **Step 1: Base & Even Checks**: 
  - If $n < 4$, it returns `True` for $n \in \{2, 3\}$ and `False` for $n \le 1$.
  - If $n$ is even, it returns `False`.
* **Step 2: Factorization of $n-1$**:
  - It repeatedly divides $n-1$ by 2 (via bit-shifts `d >>= 1`) to factor it into $2^s \cdot d$, where $d$ is odd.
* **Step 3: Probabilistic Testing Loop**:
  - It runs `iter` (default 40) independent trials.
  - In each trial, it picks a random base $a \in [2, n-2]$.
  - It runs `check_composite(n, a, d, s)`. If the candidate $n$ fails any trial (returns `True`), the function immediately returns `False` (composite).
* **Step 4: Output**: If $n$ passes all 40 trials, it is composite with a probability less than $4^{-40} \approx 8.27 \times 10^{-25}$. It returns `True` (highly likely prime).


Edited res_up.txt
Edited language.md
Edited skill.md
Edited 2105032_AES.py
Edited 2105032_AES.py
Viewed 2105032_dh.py:10-62
Viewed he.md:1-71
Edited he.md

We have successfully concatenated the analysis of the Miller-Rabin primality test algorithm to the end of your [he.md](file:///e:/4-1%20Course%20Works/CSE-406-Cyber-Security/Offline-1-Crypto/dmp/he.md) file.

Here is a summary of the algorithm's explanation:

### 1. Mathematical Foundation
The Miller-Rabin test checks if a candidate odd integer $n$ is prime by utilizing properties derived from Fermat's Little Theorem. If we write $n - 1 = 2^s \cdot d$ (where $d$ is odd), then for any random base $a \in [2, n-2]$, $n$ is highly likely a prime if:
1. $a^d \equiv 1 \pmod n$, or
2. $a^{2^r \cdot d} \equiv -1 \pmod n$ for some $0 \le r < s$.

If neither condition is met, $n$ is definitely a composite number.

### 2. Implementation Breakdown

* **Modular Exponentiation (`binpower`)**: 
  Calculates $base^e \pmod{mod}$ efficiently in $O(\log e)$ operations by utilizing binary right-to-left exponentiation. (Note: Inside the composite check, Python's built-in `pow(base, e, mod)` is used instead as it runs faster due to C-level optimizations).

* **Witness Evaluation (`check_composite`)**: 
  Computes the initial value $x = a^d \pmod n$. If $x = 1$ or $x = n-1$, the number passes this round. Otherwise, it iteratively squares $x$ up to $s-1$ times. If $x$ becomes $n-1$ during squaring, it passes. If it never reaches $n-1$ (or reaches $1$ too early), the function returns `True` (meaning it is composite).

* **Main Loop (`miller_rabin`)**: 
  Performs simple base-case checks (even numbers, values $< 4$), computes the $n-1 = 2^s \cdot d$ factorization, and runs `iter=40` independent trials with random bases. If the candidate fails any test, it is immediately declared composite (`False`). If it passes all 40 rounds, the probability of it being composite is less than $4^{-40} \approx 8.27 \times 10^{-25}$, and it is safely returned as prime (`True`).