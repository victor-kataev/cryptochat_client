import os
import requests
import asyncio
import websockets
import time

from crypto.constants import PRIVATE_KEY_FILENAME
from crypto.keystore import create_account_with_mnemonic, import_keypair_from_mnemonic, read_privkey
from storage.metadata import read_uid, save_uid
from front.tui import TextualUI

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


def import_account_from_mnemonic(mnemonic: str, client: Client):
    pk_str = import_keypair_from_mnemonic(mnemonic.lower())
    res = requests.post(f"{client.base_url}/api/v1/auth/fetch_uid", json={"pk": pk_str})
    if res.status_code != 200:
        raise RuntimeError(f"Failed to fetch UID. Server responded with {res.status_code}")
    uid = res.json()['uid']
    save_uid(uid)
    print("\nWelcome back!")
    print(f"UID: {uid}\n")


sender_queue = asyncio.Queue()





async def command_start(args=None):
    """
    Start command handler - registers or logs in user.

    Args:
        args: Command line arguments (unused)
    """
    client = Client()
    if not os.path.exists(PRIVATE_KEY_FILENAME + ".blob"):
        input_mnemonic = input("First time login on this device.\nEnter your seed phrase to login to an existing account or press Enter with no input to register a new one:\n")
        if input_mnemonic:
            import_account_from_mnemonic(input_mnemonic, client)
        else:
            register(client)
    login(client)

    ui = TextualUI(client)

    async def websocket_handler():
        async with websockets.connect(f"ws://localhost:8080/ws?token={client.session.session_token}") as ws:
            async def receiver():
                async for msg in ws:
                    await ui.receiver_queue.put(msg)

            async def sender():
                while True:
                    msg = await ui.sender_queue.get()
                    await ws.send(msg)

            await asyncio.gather(receiver(), sender())

    await asyncio.gather(websocket_handler(), ui.run_async())
