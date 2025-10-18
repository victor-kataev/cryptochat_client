import os
import requests

from crypto.constants import PRIVATE_KEY_FILENAME
from crypto.keystore import create_account_with_mnemonic, read_privkey
from crypto.keys import import_account_from_mnemonic
from storage.metadata import read_uid, save_uid

from .api import Client


def login(client: Client):
    """
    Login to an existing account.

    Args:
        client: Client instance to configure

    Raises:
        ValueError: If UID file doesn't exist
        RuntimeError: If authentication fails
    """
    client.uid = read_uid()
    client.privkey = read_privkey()
    client.authenticate()


def register(client: Client):
    """
    Register a new account.

    Args:
        client: Client instance to configure

    Raises:
        RuntimeError: If registration fails
    """
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


def command_start(args=None):
    """
    Start command handler - registers or logs in user.

    Args:
        args: Command line arguments (unused)
    """
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
