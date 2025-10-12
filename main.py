import argparse, os, json, base64
from pathlib import Path
from datetime import datetime

import requests

from dotenv import load_dotenv
load_dotenv()


from lib.encryption import (
    PRIVATE_KEY_FILENAME,
    create_account_with_mnemonic,
    extract_sk,
)

METADATA_FILENAME = os.path.expanduser("~/.cryptochat/metadata.json")


def save_uid(uid: str):
    dirname = os.path.dirname(METADATA_FILENAME)
    os.makedirs(dirname, mode=0o700, exist_ok=True)
    with open(METADATA_FILENAME, "w") as f:
        data = {
            "uid": uid,
            "crated_at": datetime.now().isoformat()
        }
        json.dump(data, f, indent=2)
    os.chmod(METADATA_FILENAME, 0o600)


def update_uid(uid: str):
    pass


def read_uid():
    if not os.path.exists(METADATA_FILENAME):
        return
    data = json.load(open(METADATA_FILENAME))
    return data['uid']


def command_start(args = None):
    api_address = 'http://127.0.0.1:8080'

    if os.path.exists(PRIVATE_KEY_FILENAME + ".blob"):
        """
        if session token exists and not expired use it
        else extract sk -> authenticate -> save new session token
        """
        uid = read_uid()
        sk = extract_sk()

        url = api_address + f"/api/v1/auth/challenge?uid={uid}"
        res = requests.get(url)
        if res.status_code != 200:
            raise RuntimeError(f"Failed to reach {api_address}. Server responded with {res.status_code}")
        data = res.json()
        
        nonce_bytes = base64.b64decode(data['nonce'])
        sig_bytes = sk.sign(nonce_bytes)
        
        url = api_address + f"/api/v1/auth/verify?uid={uid}"
        payload = {"sig": base64.b64encode(sig_bytes).decode("utf-8")}
        res = requests.post(url, json=payload)
        print(res.status_code)
        data = res.json()

        print(data)
        # session_token = res.text

    else:
        mnemonic, pk_str = create_account_with_mnemonic()

        payload = {"pk": pk_str}
        res = requests.post(api_address + "/api/v1/auth/register", json=payload)
        if res.status_code != 201:
            raise RuntimeError(f"Registration failed. Server responded with {res.status_code}")
        
        data = res.json()
        my_uid = data['uid']
        save_uid(my_uid)
        print("\nAccount successfully created.")
        print("UID:", my_uid)

        print("\nPlease back up your 12 words recovery seed phrase it won't be displayed again:")
        print("---")
        print(mnemonic.upper())
        print("---")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure chat in CLI")

    subparsers = parser.add_subparsers(dest="command")
    
    start_parser = subparsers.add_parser("start", help="Start chat")
    start_parser.set_defaults(handler=command_start)

    args = parser.parse_args()


    if hasattr(args, 'handler'):
        args.handler(args)
    else:
        command_start()

