# CSE 406 — Side Channel Timing Attack
## Lab Assignment Writeup
**Student ID:** 2105032  
**Target Student ID (last 3 digits):** 032  
**Recovered PIN:** 9892  

---

## 1. Overview

This lab demonstrates a **remote timing side-channel attack** against a black-box HTTP authentication service. The target server compares a submitted PIN against a secret one character at a time, using a non-constant-time comparison. This means a PIN that shares more correct prefix characters with the secret takes slightly longer to reject — because the server performs more comparisons before detecting a mismatch.

By systematically measuring response latencies for all candidate digits at each position and identifying which one causes a consistent timing spike, the correct PIN can be recovered digit-by-digit without ever directly breaking the underlying cryptographic algorithm.

The server generates a unique, deterministic 4-digit PIN per student based on the last 3 digits of their Student ID.

---

## 2. Attack Methodology

### 2.1 Core Principle

A naive string comparison short-circuits on the first mismatch:

```
compare("9000", "9892")  →  checks '9'=='9' ✓, '0'≠'8' ✗  →  returns false early
compare("9800", "9892")  →  checks '9'=='9' ✓, '8'=='8' ✓, '0'≠'9' ✗  →  returns false later
compare("9892", "9892")  →  all 4 match  →  returns true (longest path)
```

Each additional correct prefix character adds a small but measurable delay. The server introduces artificial delays to amplify this signal, making it detectable over HTTP.

### 2.2 Attack Strategy

The attack builds the PIN one digit at a time using a **prefix-extension** approach:

1. Fix the known prefix (initially empty).
2. For each of the 10 candidate digits (`'0'`–`'9'`), construct a candidate PIN: `prefix + digit + '0' * (remaining positions)`.
3. Send the candidate PIN to the server `SAMPLES_PER_GUESS` times and average the response latencies.
4. The digit with the highest average latency is selected — it caused the deepest traversal into the comparison, meaning it matched the secret at this position.
5. Append this digit to the known prefix and repeat for the next position.
6. Terminate when the server returns HTTP 200 OK (full PIN match).

### 2.3 Noise Reduction

A single timing measurement is unreliable due to OS scheduling jitter, network stack variance, and system load. To mitigate this, multiple samples are collected per candidate and averaged:

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

`time.perf_counter()` is used for sub-millisecond resolution, and all samples are collected before the average is computed — no early-exit that would bias the result.

---

## 3. Implementation

### 3.1 Script Structure

| Function | Role |
|---|---|
| `measure_response_time(candidate_pin)` | Sends one HTTP POST to `/verify`, returns elapsed ms and HTTP status code |
| `get_average_timing(candidate_pin, samples)` | Collects `samples` measurements, returns average latency and success flag |
| `plot_timings(position, timings, known_prefix)` | Generates and saves the per-position timing bar chart |
| `recover_secret_pin()` | Main exploit loop — builds the PIN digit-by-digit |

### 3.2 Candidate PIN Construction

At each position `i` with `known_prefix` of length `i`, the candidate PIN is:

```
candidate_pin = known_prefix + curr_digit + '0' * (PIN_LENGTH - i - 1)
```

For example, at position 2 with prefix `'9'`, testing digit `'8'`:
```
candidate_pin = '9' + '8' + '00' = '9800'
```

The trailing zeros serve as filler — they are never reached by the comparison if position 2 is wrong, and they produce the shortest possible remaining-path if position 2 is correct.

### 3.3 Termination Logic

The exploit uses a `found_pin` flag to handle HTTP 200 detection correctly:

```python
if success:
    best_digit = curr_digit
    found_pin = True
    correct_candidate = candidate_pin

if not found_pin and avg_time > max_timing:
    max_timing = avg_time
    best_digit = curr_digit
```

The `if not found_pin` guard on the timing-spike tracker ensures that once a 200 is received, no later digit in the same position can overwrite `best_digit`. After the inner digit loop completes:

```python
if found_pin:
    if not COLLECT_ALL_DATA:
        known_prefix = correct_candidate
        break
```

The `COLLECT_ALL_DATA` flag controls whether the outer loop breaks immediately on 200 (fast mode) or continues through all remaining positions for complete chart data (data-collection mode).

---

## 4. Results

### 4.1 Recovered PIN

**Student ID 032 → PIN: `9892`**

The attack ran with `SAMPLES_PER_GUESS = 5` and successfully recovered all 4 digits.

### 4.2 Timing Data

#### Position 1

| Candidate | Avg Time | Notes |
|---|---|---|
| `0000` | 15.06 ms | |
| `1000` | 12.44 ms | |
| `2000` | 6.62 ms | |
| `3000` | 15.24 ms | |
| `4000` | 18.63 ms | |
| `5000` | 13.12 ms | |
| `6000` | 20.52 ms | |
| `7000` | 17.35 ms | |
| `8000` | 15.29 ms | |
| **`9000`** | **32.82 ms** | ← spike (+12.3ms over 2nd place) |

Correct digit: **9**

#### Position 2

| Candidate | Avg Time | Notes |
|---|---|---|
| `9000` | 34.11 ms | |
| `9100` | 33.27 ms | |
| `9200` | 31.42 ms | |
| `9300` | 35.97 ms | |
| `9400` | 33.06 ms | |
| `9500` | 29.30 ms | |
| `9600` | 33.03 ms | |
| `9700` | 33.10 ms | |
| **`9800`** | **53.70 ms** | ← spike (+17.7ms over 2nd place) |
| `9900` | 33.01 ms | |

Correct digit: **8**

#### Position 3

| Candidate | Avg Time | Notes |
|---|---|---|
| `9800` | 46.24 ms | |
| `9810` | 49.70 ms | |
| `9820` | 47.82 ms | |
| `9830` | 54.64 ms | 2nd place |
| `9840` | 49.54 ms | |
| `9850` | 48.75 ms | |
| `9860` | 51.18 ms | |
| `9870` | 46.59 ms | |
| `9880` | 49.99 ms | |
| **`9890`** | **56.75 ms** | ← spike (+2.1ms over 2nd place — narrowest gap) |

Correct digit: **9** *(narrow margin — see Section 6)*

#### Position 4

| Candidate | Avg Time | Notes |
|---|---|---|
| `9890` | 66.43 ms | |
| `9891` | 65.03 ms | |
| **`9892`** | **82.49 ms** | ← spike (+10.5ms over 2nd place) |
| `9893` | 63.08 ms | |
| `9894` | 59.87 ms | |
| `9895` | 65.16 ms | |
| `9896` | 71.95 ms | |
| `9897` | 60.19 ms | |
| `9898` | 68.24 ms | |
| `9899` | 61.35 ms | |

Correct digit: **2**

### 4.3 Verification

```
[*] Verifying recovered PIN with server...
[+] VERIFIED! Recovered PIN: 9892
```

HTTP 200 OK confirmed. Attack successful.

---

## 5. Visualization

A horizontal bar chart was generated for each position, comparing average response latency across all 10 candidate digits. Charts are saved to `results/{sample_str}_position_{N}_timing_diagram.png`.

The charts clearly show the timing spike at the correct digit for each position — the correct candidate's bar is visibly longer than all others, particularly at positions 1, 2, and 4. Position 3 shows a narrower gap (discussed in Section 6).

Multiple runs were collected at different sample counts (`SAMPLES_PER_GUESS` = 1, 2, 3, 4, 5, 10, 32, 50, 100) to demonstrate how signal clarity improves with averaging. The `results/` folder contains 36 PNG charts and 9 result text files covering all these runs.

---

## 6. Analysis & Observations

### 6.1 Cumulative Latency Pattern

The timing data shows a consistent pattern: average response latency increases with each correctly-guessed digit position. This is direct evidence of the server's sequential comparison:

| Position | Baseline (wrong digit) | Correct digit latency |
|---|---|---|
| 1 | ~14 ms | 32.82 ms |
| 2 | ~32 ms | 53.70 ms |
| 3 | ~49 ms | 56.75 ms |
| 4 | ~63 ms | 82.49 ms |

Each successfully matched prefix adds approximately 10–20ms to the baseline, compounding across positions.

### 6.2 Position 3 Narrow Margin

Position 3 produced the smallest spike gap in the run: only **2.1ms** between `9890` (56.75ms) and `9830` (54.64ms). With `SAMPLES_PER_GUESS = 5`, this is a noise-vulnerable result. On a different run, OS jitter could flip these two candidates and recover `9832` instead of `9892`.

Multi-sample runs at higher counts confirm the signal stabilizes. At `SAMPLES_PER_GUESS = 10`, the gap widens consistently. This illustrates the fundamental trade-off in timing attacks: **more samples → higher signal-to-noise ratio → more reliable digit recovery**, at the cost of more total HTTP requests.

### 6.3 Edge Case: Trailing-Zero PINs

During exploration, a pathological case was identified by brute-force comparing all 181 student PINs: **Student ID 098 → PIN `7300`**.

`7300` contains trailing zeros, meaning the full correct PIN can be accidentally triggered **before all 4 positions are processed**. Specifically:

- At position 2, candidate `7300` = `prefix '7'` + `digit '3'` + `padding '00'` = the complete correct PIN.
- The server returns HTTP 200 immediately.
- In the original implementation, the outer loop broke with `known_prefix = '73'` (only 2 digits), and the final verify call sent `'73'` → failure.

**The fix** uses a `COLLECT_ALL_DATA` flag to handle both use cases:

- **`COLLECT_ALL_DATA = True`** (default): the outer loop does not break on 200. Remaining positions continue to be processed. Since `7300` is still the correct PIN, it wins each subsequent position via the 200 flag (not timing). Final `known_prefix` = `'7300'`. ✅
- **`COLLECT_ALL_DATA = False`**: breaks immediately on 200, but first executes `known_prefix = correct_candidate` (the full 4-digit string that triggered 200) before breaking. Final `known_prefix` = `'7300'`. ✅

Both modes verified against `7300` and confirmed working.

This edge case class — **correct PIN discovered as a prefix-match artifact before the final position** — applies to any PIN where padding zeros happen to form the complete secret. Examples in the student PIN table: any PIN ending in one or more zeros where an intermediate candidate happens to equal the full PIN. The `found_pin` + `correct_candidate` pattern handles all such cases correctly.

---

## 7. Security Implications

This attack demonstrates a class of vulnerability present in any authentication system that:

1. Compares secrets character-by-character with early exit on mismatch (non-constant-time comparison).
2. Exposes timing information to the attacker — even over a network.
3. Uses secrets of fixed, known length.

The defense is straightforward: **constant-time comparison**. In Python, `hmac.compare_digest()` compares two strings in time proportional to their length regardless of where they differ, eliminating the timing signal entirely:

```python
import hmac
if hmac.compare_digest(submitted_pin, secret_pin):
    return 200
else:
    return 401
```

Additional mitigations include rate limiting, introducing random delays on authentication responses, and limiting the number of attempts before lockout — though none of these eliminate the fundamental vulnerability of non-constant-time comparison.

---

## 8. Conclusion

The timing side-channel attack successfully recovered the secret PIN `9892` for Student ID 032 through automated HTTP latency analysis. The exploit:

- Required no knowledge of the server's internal implementation
- Made no attempt to reverse-engineer or decompile the binary
- Relied entirely on observable response timing differences of 2–18ms per correct digit
- Completed in a single automated run with verification

The attack highlights that cryptographic strength alone is insufficient — implementation details like string comparison order and early-exit logic can leak secret information through observable side channels, even across a loopback network interface.

---

## 9. How to Run It

```bash
# 1. Start the provided black-box target server (matches your operating system)
cd Offline-2-Side-Channel-Attack/res
./server_linux        # on Linux
# or ./server_mac     # on macOS
# or .\server_windows.exe # on Windows

# 2. In another terminal, run the timing-attack exploit
cd Offline-2-Side-Channel-Attack/2105032
python 2105032.py
```

---

## 10. File Layout

```
Offline-2-Side-Channel-Attack/
├── readme.md                           # Comprehensive documentation (this file)
├── 2105032/                            # Active student implementation
│   ├── 2105032.py                      # Timing-attack exploit (averaging, digit recovery, plotting)
│   └── results/                        # Transcripts (<n>_result.txt) & bar charts (<n>_position_<k>_timing_diagram.png)
├── all-test/                           # Test suite & comparative validation scripts
│   └── all_test.py                     # Automated testing harness
└── res/                                # Target binaries and assignment materials
    ├── Side_Channel_Timing_Attack_Assignment.docx.pdf  # Assignment specification
    ├── template.py                     # Provided starter template
    └── server_linux / server_mac / server_windows.exe   # Black-box target server binaries
```

---

<div align="center">

*CSE 406 · Cyber Security Sessional · BUET · January 2026*

</div>

