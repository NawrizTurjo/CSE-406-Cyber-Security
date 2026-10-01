# ⏱️ CSE 406 — Cyber Security Sessional
## Offline 2: Side-Channel Timing Attack

> **Course:** CSE 406 · Cyber Security Sessional · January 2026  
> **Student ID:** 2105032  
> **Section:** A2  
> **Target Student ID (last 3 digits):** 032  
> **Recovered PIN:** 9892  

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Core Principles & Vulnerability Mechanics](#-core-principles--vulnerability-mechanics)
  - [1. Non-Constant-Time String Comparison](#1-non-constant-time-string-comparison)
  - [2. Information Leakage via Response Latency](#2-information-leakage-via-response-latency)
- [Attack Architecture & Execution Flow](#-attack-architecture--execution-flow)
  - [1. Prefix-Extension Search Algorithm](#1-prefix-extension-search-algorithm)
  - [2. Statistical Filtering & Noise Reduction](#2-statistical-filtering--noise-reduction)
- [Exploit Implementation Details](#-exploit-implementation-details)
  - [1. Script Architecture (`2105032.py`)](#1-script-architecture-2105032py)
  - [2. Candidate PIN Construction](#2-candidate-pin-construction)
  - [3. Robust State & Termination Tracking](#3-robust-state--termination-tracking)
- [Experimental Results & Latency Benchmarks](#-experimental-results--latency-benchmarks)
  - [Position 1 Analysis](#position-1-analysis)
  - [Position 2 Analysis](#position-2-analysis)
  - [Position 3 Analysis](#position-3-analysis)
  - [Position 4 Analysis](#position-4-analysis)
  - [Final Verification](#final-verification)
- [Timing Visualizations & Multi-Sample Analysis](#-timing-visualizations--multi-sample-analysis)
  - [1. Cumulative Latency Compounding](#1-cumulative-latency-compounding)
  - [2. Position 3 Narrow Margin Resolution](#2-position-3-narrow-margin-resolution)
  - [3. Sampling Depth vs. Signal-to-Noise Ratio](#3-sampling-depth-vs-signal-to-noise-ratio)
- [Edge Cases & Algorithmic Resilience](#-edge-cases--algorithmic-resilience)
  - [The Trailing-Zero Anomaly (Student ID 098 ➔ PIN `7300`)](#the-trailing-zero-anomaly-student-id-098--pin-7300)
  - [Two-Phase Handling: Fast Break vs. Complete Data Harvest](#two-phase-handling-fast-break-vs-complete-data-harvest)
- [Security Implications & Constant-Time Defenses](#-security-implications--constant-time-defenses)
- [How to Run It](#-how-to-run-it)
- [File Layout](#-file-layout)

---

## 🌐 Overview

This laboratory explores a **remote timing side-channel attack** conducted against a black-box HTTP authentication service. 

Traditional cryptanalysis often attempts to compromise mathematical hardness assumptions. In contrast, **side-channel analysis** exploits unintentional physical or temporal leakage stemming from implementation quirks. In this system:
- The target server validates a submitted 4-digit PIN against an internal secret character-by-character.
- The comparison logic is **non-constant-time**: it short-circuits and aborts immediately upon encountering the first mismatched character.
- A candidate PIN that shares a longer matching prefix with the secret executes deeper into the comparison loop, introducing a measurable delay.

By systematically measuring HTTP response latencies using high-resolution timers and filtering out network jitter across repeated trials, an attacker can extract the secret PIN digit-by-digit—**reducing the search space from $10^4 = 10,000$ combinations to just $4 \times 10 = 40$ candidate tests**.

The target authentication service deterministically generates a secret 4-digit PIN for each student derived from the last three digits of their Student ID. For student **`2105032`** (ID: `032`), the secret PIN is successfully recovered as **`9892`**.

---

## 🧠 Core Principles & Vulnerability Mechanics

### 1. Non-Constant-Time String Comparison

Consider standard string equality checks implemented in many high-level programming languages and C standard libraries (`strcmp`, `memcmp`, naive loops):

```
compare(guess, secret):
    for i from 0 to length - 1:
        if guess[i] != secret[i]:
            return False    <--- Early return leaks prefix length!
    return True
```

When comparing against secret PIN `"9892"`:
```
compare("9000", "9892") ➔ Checks '9'=='9' (✓), '0'!='8' (✗) ➔ Returns False after 2 checks
compare("9800", "9892") ➔ Checks '9'=='9' (✓), '8'=='8' (✓), '0'!='9' (✗) ➔ Returns False after 3 checks
compare("9892", "9892") ➔ Checks all 4 digits match (✓) ➔ Returns True (longest code path)
```

Each additional matched prefix digit incurs incremental execution overhead. To simulate observable network-level effects, the challenge server introduces an artificial delay for each successful character match.

### 2. Information Leakage via Response Latency

The observable round-trip time (RTT) for an HTTP request can be modeled as:
$$T_{\text{observed}} = T_{\text{network}} + T_{\text{OS\_jitter}} + T_{\text{base}} + k \cdot \Delta t$$
where:
* $k \in \{1, 2, 3, 4\}$ is the number of successfully matched characters before failure.
* $\Delta t$ is the artificial per-character processing latency (~10–20 ms).
* $T_{\text{network}} + T_{\text{OS\_jitter}}$ represents stochastic noise introduced by loopback sockets, thread scheduling, and HTTP parsing.

---

## 🏗 Attack Architecture & Execution Flow

```
                  ┌─────────────────────────────────────────┐
                  │ Target Server: POST /verify             │
                  │ Headers: X-Student-ID: 032              │
                  │ Payload: {"pin": "<candidate>"}         │
                  └────────────────────▲────────────────────┘
                                       │ HTTP POST (Latency Timed)
┌──────────────────────────────────────┴──────────────────────────────────────┐
│ Exploit Engine (2105032.py)                                                 │
│                                                                             │
│ Known Prefix = ""                                                           │
│ For position 1 to 4:                                                        │
│   For digit '0' to '9':                                                     │
│     candidate = Known Prefix + digit + '0'*(4 - position)                   │
│     Average latency = Sum(measure(candidate) for 1..N) / N                  │
│   winning_digit = argmax(Average latencies)                                 │
│   Known Prefix += winning_digit                                             │
│                                                                             │
│ If HTTP 200 OK received ➔ Terminate & Verify Full PIN                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1. Prefix-Extension Search Algorithm

The exploit proceeds greedily from left to right:
1. Initialize `known_prefix = ""`
2. To resolve position $i$ ($1 \le i \le 4$):
   * Generate 10 candidates by appending each digit `'0'` through `'9'` to `known_prefix` and padding remaining slots with `'0'`.
   * For each candidate, send `SAMPLES_PER_GUESS` requests to `http://127.0.0.1:5000/verify`.
   * Compute the arithmetic mean of response times.
   * Identify the candidate exhibiting the distinct **timing spike** (highest average latency).
   * Append the winning digit to `known_prefix`.
3. Terminate immediately once the server returns HTTP status `200 OK`.

### 2. Statistical Filtering & Noise Reduction

Because operating system context switching, TCP stack buffering, and interpreter delays induce jitter on individual requests, single-shot timing is vulnerable to false positives. 

The exploit employs multi-sample arithmetic averaging:

```python
def get_average_timing(candidate_pin: str, samples: int) -> tuple[float, bool]:
    total_time = 0.0
    success = False
    for _ in range(samples):
        elapsed, status = measure_response_time(candidate_pin=candidate_pin)
        total_time += elapsed
        if status == 200:
            success = True
    avg_time = total_time / samples
    return avg_time, success
```

Timings are captured using `time.perf_counter()`, providing nanosecond-precision CPU counters unaffected by system clock adjustments.

---

## ⚡ Exploit Implementation Details

### 1. Script Architecture (`2105032.py`)

| Function | Primary Role |
|---|---|
| `measure_response_time(candidate_pin)` | Transmits one JSON HTTP POST request to `/verify` with header `X-Student-ID: 032`; returns elapsed milliseconds and status code. |
| `get_average_timing(candidate_pin, samples)` | Dispatches `samples` repeated queries for a candidate, returning the mean latency and any `200 OK` detection flag. |
| `plot_timings(position, timings, known_prefix)` | Generates and saves a publication-quality horizontal bar chart using `matplotlib`, highlighting the winning candidate. |
| `recover_secret_pin()` | Master exploit loop coordinating the 4-phase prefix search, statistical selection, and final verification. |

### 2. Candidate PIN Construction

At position $i$ with prefix of length $i-1$:
$$\text{candidate\_pin} = \text{known\_prefix} + \text{curr\_digit} + \text{"0"} \times (\text{PIN\_LENGTH} - i)$$

* Example (testing digit `'8'` at position 2 after recovering `'9'`):
  $$\text{candidate} = \text{"9"} + \text{"8"} + \text{"00"} = \text{"9800"}$$

The trailing zeros act as neutral filler: if position 2 is wrong, the server aborts at position 2 and never evaluates the zeros.

### 3. Robust State & Termination Tracking

```python
if success:
    best_digit = curr_digit
    found_pin = True
    correct_candidate = candidate_pin

if not found_pin and avg_time > max_timing:
    max_timing = avg_time
    best_digit = curr_digit
```

The guard `if not found_pin` guarantees that if a candidate yields an authentic HTTP 200 OK, no subsequent candidate with noisy latency can overwrite the verified digit.

---

## 📊 Experimental Results & Latency Benchmarks

The benchmark attack run was executed with `SAMPLES_PER_GUESS = 5` against student ID `032`.

### Position 1 Analysis

Known Prefix: `""` · Testing Candidates: `0000`–`9000`

| Candidate | Average Latency | Status / Observation |
|:---:|:---:|:---|
| `0000` | 15.06 ms | Baseline mismatch at digit 1 |
| `1000` | 12.44 ms | Baseline mismatch |
| `2000` | 6.62 ms | Baseline mismatch |
| `3000` | 15.24 ms | Baseline mismatch |
| `4000` | 18.63 ms | Baseline mismatch |
| `5000` | 13.12 ms | Baseline mismatch |
| `6000` | 20.52 ms | Baseline mismatch |
| `7000` | 17.35 ms | Baseline mismatch |
| `8000` | 15.29 ms | Baseline mismatch |
| **`9000`** | **32.82 ms** | **Timing Spike! (+12.30 ms margin over runner-up)** |

* **Resolved Digit 1:** **`9`**

---

### Position 2 Analysis

Known Prefix: `"9"` · Testing Candidates: `9000`–`9900`

| Candidate | Average Latency | Status / Observation |
|:---:|:---:|:---|
| `9000` | 34.11 ms | Baseline prefix match (len 1) |
| `9100` | 33.27 ms | Baseline prefix match |
| `9200` | 31.42 ms | Baseline prefix match |
| `9300` | 35.97 ms | Baseline prefix match |
| `9400` | 33.06 ms | Baseline prefix match |
| `9500` | 29.30 ms | Baseline prefix match |
| `9600` | 33.03 ms | Baseline prefix match |
| `9700` | 33.10 ms | Baseline prefix match |
| **`9800`** | **53.70 ms** | **Timing Spike! (+17.73 ms margin over runner-up)** |
| `9900` | 33.01 ms | Baseline prefix match |

* **Resolved Digit 2:** **`8`**

---

### Position 3 Analysis

Known Prefix: `"98"` · Testing Candidates: `9800`–`9890`

| Candidate | Average Latency | Status / Observation |
|:---:|:---:|:---|
| `9800` | 46.24 ms | Baseline prefix match (len 2) |
| `9810` | 49.70 ms | Baseline prefix match |
| `9820` | 47.82 ms | Baseline prefix match |
| `9830` | 54.64 ms | Runner-up (elevated noise) |
| `9840` | 49.54 ms | Baseline prefix match |
| `9850` | 48.75 ms | Baseline prefix match |
| `9860` | 51.18 ms | Baseline prefix match |
| `9870` | 46.59 ms | Baseline prefix match |
| `9880` | 49.99 ms | Baseline prefix match |
| **`9890`** | **56.75 ms** | **Timing Spike! (+2.11 ms narrow margin over `9830`)** |

* **Resolved Digit 3:** **`9`**

---

### Position 4 Analysis

Known Prefix: `"989"` · Testing Candidates: `9890`–`9899`

| Candidate | Average Latency | Status / Observation |
|:---:|:---:|:---|
| `9890` | 66.43 ms | Baseline prefix match (len 3) |
| `9891` | 65.03 ms | Baseline prefix match |
| **`9892`** | **82.49 ms** | **Full Secret Matched! (HTTP 200 OK returned)** |
| `9893` | 63.08 ms | Baseline prefix match |
| `9894` | 59.87 ms | Baseline prefix match |
| `9895` | 65.16 ms | Baseline prefix match |
| `9896` | 71.95 ms | Baseline prefix match |
| `9897` | 60.19 ms | Baseline prefix match |
| `9898` | 68.24 ms | Baseline prefix match |
| `9899` | 61.35 ms | Baseline prefix match |

* **Resolved Digit 4:** **`2`**

---

### Final Verification

The exploit performs an independent confirmation query sending the recovered candidate `9892`:

```text
[*] Verifying recovered PIN with server...
[+] VERIFIED! Recovered PIN: 9892 (HTTP 200 OK)
```

The server acknowledged authentication success. The secret PIN for Student ID `032` is conclusively **`9892`**.

---

## 📈 Timing Visualizations & Multi-Sample Analysis

### 1. Cumulative Latency Compounding

The latency trajectory exhibits a strict, monotonically increasing stair-step pattern:

```
Latency (ms)
 100 │                                          ┌─────────┐ (82.49 ms - Full Match)
  80 │                              ┌───────────┘
  60 │                  ┌───────────┘ (56.75 ms - 3 digits)
  40 │      ┌───────────┘ (53.70 ms - 2 digits)
  20 │ ─────┘ (32.82 ms - 1 digit)
   0 └────────────────────────────────────────────────────────
       Pos 1        Pos 2        Pos 3        Pos 4
```

| Match Level | Mean Baseline Latency | Winning Digit Latency | Cumulative Increment |
|---|---|---|---|
| 0 Correct (Pos 1) | ~14 ms | 32.82 ms | +18.82 ms |
| 1 Correct (Pos 2) | ~33 ms | 53.70 ms | +20.88 ms |
| 2 Correct (Pos 3) | ~49 ms | 56.75 ms | +7.05 ms |
| 3 Correct (Pos 4) | ~65 ms | 82.49 ms | +17.46 ms |

### 2. Position 3 Narrow Margin Resolution

At Position 3, candidate `9890` (56.75 ms) surpassed `9830` (54.64 ms) by only **2.11 ms**. In high-jitter environments, a small sample size ($N=5$) carries a non-zero probability of false attribution.

To validate stability, multi-sample runs were conducted across $N \in \{1, 2, 3, 4, 5, 10, 32, 50, 100\}$:
* At $N = 10$, the margin widened to $> 6.5 \text{ ms}$.
* At $N = 50$, the margin stabilized above $11.0 \text{ ms}$.
* At $N = 100$, statistical noise was entirely suppressed, yielding clear gaps across all positions.

### 3. Sampling Depth vs. Signal-to-Noise Ratio

The directory [`2105032/results/`](2105032/results) contains 36 visualization charts and 9 text transcripts documenting the convergence behavior:
* `01_result.txt` through `100_result.txt`
* `<samples>_position_<pos>_timing_diagram.png`

Higher sample counts monotonically improve the signal-to-noise ratio ($\text{SNR} \propto \sqrt{N}$), confirming standard Central Limit Theorem behavior in network latency measurements.

---

## 🛡 Edge Cases & Algorithmic Resilience

### The Trailing-Zero Anomaly (Student ID 098 ➔ PIN `7300`)

Exhaustive offline simulation across all 181 university student PINs identified a structural boundary case: **Student ID 098 whose PIN is `7300`**.

Because candidate construction pads unsearched positions with `'0'`, testing digit `'3'` at Position 2 constructs:
$$\text{candidate} = \text{"7"} + \text{"3"} + \text{"00"} = \text{"7300"}$$

This candidate inadvertently matches the **complete 4-digit secret prematurely at Position 2**, prompting the server to return HTTP `200 OK` two positions early.

A naive exploit loop breaking at Position 2 would exit with an incomplete `known_prefix = "73"`, causing the final verification test (`"73"`) to fail.

### Two-Phase Handling: Fast Break vs. Complete Data Harvest

To handle this and similar boundary cases robustly, the implementation introduces the `COLLECT_ALL_DATA` configuration:

1. **`COLLECT_ALL_DATA = False` (Fast Mode)**:
   When HTTP 200 is detected, immediately assign `known_prefix = correct_candidate` (the full 4-digit string `"7300"`) and break out of the loop.
2. **`COLLECT_ALL_DATA = True` (Complete Harvest Mode)**:
   The loop continues through positions 3 and 4 to gather remaining timing chart data. At positions 3 and 4, candidate `"7300"` continues to trigger HTTP 200, guaranteeing that digit `'0'` wins legitimately without timing misclassification.

Both modes were verified and succeed across all student PIN profiles.

---

## 🔒 Security Implications & Constant-Time Defenses

The vulnerability demonstrated here is present in any authentication system where secret validation evaluates sequentially and short-circuits on mismatch.

### Remediation: Constant-Time Comparison

Authentication routines must execute in time invariant to secret contents or mismatch positions. 

In Python, the standard mitigation is `hmac.compare_digest()`:

```python
import hmac

# VULNERABLE:
# if submitted_pin == secret_pin:  # Early-exit leaks prefix length

# SECURE:
if hmac.compare_digest(submitted_pin, secret_pin):
    return 200
else:
    return 401
```

`hmac.compare_digest()` iterates over all characters regardless of mismatch, neutralizing the timing side-channel completely.

### Complementary Mitigations
1. **Exponential Backoff & Rate Limiting**: Restricting failed attempts per IP / Account dampens brute-force timing scans.
2. **Random Delay Injection (Jitter)**: Adding randomized artificial latency degrades the signal-to-noise ratio, requiring an impractically large sample size $N$.
3. **Cryptographic Hashing**: Comparing slow password hashes (Argon2id, bcrypt, PBKDF2) rather than raw PINs.

---

## 🚀 How to Run It

### Step 1: Launch the Target Server

Select the binary corresponding to your host operating system:

```bash
cd Offline-2-Side-Channel-Attack/res

# Linux:
./server_linux

# macOS:
./server_mac

# Windows:
.\server_windows.exe
```
The server will bind locally to `http://127.0.0.1:5000`.

### Step 2: Execute the Timing Attack Exploit

In a separate terminal window:

```bash
cd Offline-2-Side-Channel-Attack/2105032
python 2105032.py
```

The script will automatically probe the 4 positions, compute average latencies, render timing bar charts into `results/`, and print the verified recovered PIN.

---

## 📁 File Layout

```
Offline-2-Side-Channel-Attack/
├── readme.md                           # Comprehensive documentation (this file)
├── 2105032/                            # Active student implementation
│   ├── 2105032.py                      # Timing-attack exploit (averaging, digit recovery, plotting)
│   └── results/                        # Benchmarking artifacts across sample depths
│       ├── 01_result.txt ... 100_result.txt    # Execution transcripts
│       └── *_position_*_timing_diagram.png     # Matplotlib horizontal latency charts
├── all-test/                           # Test suite & comparative validation scripts
│   └── all_test.py                     # Automated testing harness across all student IDs
└── res/                                # Target binaries and assignment materials
    ├── Side_Channel_Timing_Attack_Assignment.docx.pdf  # Assignment specification
    ├── template.py                     # Provided starter template
    └── server_linux / server_mac / server_windows.exe   # Black-box target server binaries
```

---

<div align="center">

*CSE 406 · Cyber Security Sessional · BUET · January 2026*

</div>

