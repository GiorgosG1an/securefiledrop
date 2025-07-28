import os
import hmac
import hashlib
import base64
from datetime import datetime
import datetime

LOG_KEY_PATH = "keys/logkey.bin"
LOG_FILE = "logs/access.log"

def load_log_key() -> bytes:
    """
    Loads a cryptographic key from the specified log key path.

    Returns:
        bytes: The loaded or newly generated cryptographic key.
    """

    if not os.path.exists(LOG_KEY_PATH):
        key = os.urandom(32)
        os.makedirs(os.path.dirname(LOG_KEY_PATH), exist_ok=True)

        with open(LOG_KEY_PATH, 'wb') as f:
            f.write(key)

    else:
        with open(LOG_KEY_PATH, 'rb') as f:
            key = f.read()

    return key

def log_event(action: str, filename:str) -> None:
    """
    Logs an event with an HMAC signature for integrity.

    Args:
        action (str): The action performed (e.g., "upload", "download").
        filename (str): The name of the file involved in the event.

    Returns:
        None

    The log entry includes a UTC timestamp, the action, the filename, and a base64-encoded HMAC-SHA256 signature.
    """
    key = load_log_key()
    timestamp = datetime.datetime.now(datetime.timezone.utc)
    message = f"{timestamp} {action} {filename}"

    signature = hmac.new(key, message.encode(), hashlib.sha256).digest()
    signature_b64 = base64.b64encode(signature).decode()

    log_line = f"{message} {signature_b64} \n"

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    with open(LOG_FILE, "a") as log:
        log.write(log_line)

def verify_log_file() -> bool:

    key = load_log_key()
    if not os.path.exists(LOG_FILE):
        print("Log file does not exist.")
        return False
    
    all_ok = True
    with open(LOG_FILE, 'r') as f:
        for i, line in enumerate(f, start=1):
            parts = line.strip().split()
            if len(parts) < 5:
                print(f"Line {i} is malformed!")
                all_ok = False
                continue

            timestamp = f"{parts[0]} {parts[1]}"
            action = parts[2]
            filename = parts[3]
            hmac_b64 = parts[4]

            message = f"{timestamp} {action} {filename}"

            expected_sig = hmac.new(key, message.encode(), hashlib.sha256).digest()

            try:
                given_sig = base64.b64decode(hmac_b64)
            except Exception:
                print(f"Line {i}: Invalid base64 HMAC")
                all_ok = False
                continue

            if not hmac.compare_digest(expected_sig, given_sig):
                print(f"Line {i}: HMAC verification failed.")
                all_ok = False

    if all_ok:
        print(f"All log entries verified. No tampering detected.")
    return all_ok

