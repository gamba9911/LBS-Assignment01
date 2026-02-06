from loguru import logger

from app import check_payload_true, build_sql_payload, KNOWN_USER, THRESHOLD_SECONDS

FILE_PATH = "ket.txt"


def verify_key():
    key = ""
    with open('key.txt', 'r') as file:
        key = file.read().rstrip()

    # check the validity of the whole key
    prefix_payload = build_sql_payload(f"key=='{key}'")
    if (check_payload_true(KNOWN_USER, prefix_payload, THRESHOLD_SECONDS)):
        logger.info("✅ Key is correct")
    else:
        logger.warning("❌ Key is incorrect.")


if __name__ == '__main__':
    verify_key()
