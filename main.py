import argparse, os, json, base64
from pathlib import Path
from datetime import datetime

import requests

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dotenv import load_dotenv
load_dotenv()

from lib.encryption import (
    PRIVATE_KEY_FILENAME,
    create_account_with_mnemonic,
    read_privkey,
    import_account_from_mnemonic
)
from lib.utils import read_uid, save_uid



class Session:
    def __init__(self, session_token: str, expires_at: datetime):
        self.session_token = session_token
        self.expires_at = expires_at

    def is_valid(self):
        return datetime.now() < self.expires_at


class Client:
    def __init__(self):
        self.base_url: str = "http://127.0.0.1:8080"
        self._session: Session | None = None
        self._privkey: Ed25519PrivateKey | None = None
        self._uid: str = ""

    @property
    def privkey(self) -> Ed25519PrivateKey:
        if not self._privkey:
            raise ValueError("Private key not initialized")
        return self._privkey
    
    @privkey.setter
    def privkey(self, value: Ed25519PrivateKey):
        self._privkey = value

    @property
    def session(self) -> Session:
        if not self._session:
            raise ValueError("Session not initialized")
        return self._session
    
    @session.setter
    def session(self, value: Session):
        self._session = value

    @property
    def uid(self) -> str:
        if not self._uid:
            raise ValueError("UID not initialized")
        return self._uid
    
    @uid.setter
    def uid(self, value: str):
        self._uid = value

    def authenticate(self):
        res = requests.get(f"{self.base_url}/api/v1/auth/challenge?uid={self.uid}")
        if res.status_code != 200:
            raise RuntimeError(f"Failed to obtain the challenge. Server responded with {res.status_code}")
        
        nonce_bytes = base64.b64decode(res.json()['nonce'])
        sig_bytes = self.privkey.sign(nonce_bytes)
        
        payload = {"uid": self.uid, "sig": base64.b64encode(sig_bytes).decode("utf-8")}
        res = requests.post(f"{self.base_url}/api/v1/auth/verify", json=payload)
        if res.status_code != 200:
            raise RuntimeError(f"Failed to authenticate current user. Server responded with {res.status_code}")
        
        self.session = Session(res.json()["access_token"], res.json()["expires_at"])

    def api_request(self, method: str, endpoint: str, **kwargs):
        if not self.session or not self.session.is_valid():
            self.authenticate()
        return requests.request(method, self.base_url + endpoint, **kwargs)

def login(client: Client):
    client.uid = read_uid()
    client.privkey = read_privkey()
    client.authenticate()

def register(client: Client):
    mnemonic, pk_str = create_account_with_mnemonic()

    res = requests.post(f"{client.base_url}/api/v1/auth/register", json={"pk": pk_str})
    if res.status_code != 201:
        raise RuntimeError(f"Registration failed. Server responded with {res.status_code}")
    
    uid = res.json()['uid']
    save_uid(uid)

    print("\nAccount successfully created.")
    print("UID:", uid)

    print("\nPlease back up your 12 words recovery seed phrase it won't be displayed again:")
    print("---")
    print(mnemonic.upper())
    print("---")

def command_start(args = None):
    client = Client()
    if not os.path.exists(PRIVATE_KEY_FILENAME + ".blob"):
        input_mnemonic = input("First time login on this device.\nEnter your seed phrase to login to an existing account or press Enter with no input to register a new one:")
        if not input_mnemonic:
            register(client)
        else:
            import_account_from_mnemonic(input_mnemonic)
    login(client)

    print(client.session.session_token)
    # display_UI(client)


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
