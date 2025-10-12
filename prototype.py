#!/usr/bin/env python3
import os, sys, json, base64, secrets, getpass
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

# Path to store local keyfile
HOME = Path.home()
KEYDIR = HOME / ".cli_chat"
KEYFILE = KEYDIR / "private.key.json"


# --- Simulated server state ---
SERVER_DB = {}

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "===")

def mnemonic_from_seed(seed: bytes) -> str:
    # crude mnemonic: split into 12 words of base32
    import base64
    b32 = base64.b32encode(seed).decode("utf8").lower().strip("=")
    return " ".join([b32[i:i+4] for i in range(0, len(b32), 4)])

def mnemonic_to_seed(mn: str) -> bytes:
    import base64
    b32 = mn.replace(" ", "").upper()
    return base64.b32decode(b32 + "===")


# --- Key management ---
def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(passphrase.encode())

def encrypt_private_key(private_bytes: bytes, passphrase: str | None):
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    if passphrase:
        key = derive_key(passphrase, salt)
    else:
        key = secrets.token_bytes(32)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, private_bytes, None)
    return {"salt": b64u(salt), "nonce": b64u(nonce), "ct": b64u(ct)}

def decrypt_private_key(enc: dict, passphrase: str | None):
    salt = b64u_decode(enc["salt"])
    nonce = b64u_decode(enc["nonce"])
    ct = b64u_decode(enc["ct"])
    if passphrase:
        key = derive_key(passphrase, salt)
    else:
        raise ValueError("Passphrase required")
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None)


# --- Client commands ---
def cmd_init():
    if KEYFILE.exists():
        print("Key already exists at", KEYFILE)
        return
    KEYDIR.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption()
    )
    pub_bytes = pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )
    # ask for passphrase
    passphrase = getpass.getpass("Choose a passphrase (blank for none): ")
    enc = encrypt_private_key(priv_bytes, passphrase if passphrase else None)

    # simulate server registration
    uid = secrets.token_urlsafe(6)
    SERVER_DB[uid] = {"pubkey": pub_bytes}
    seed = secrets.token_bytes(16)
    mnemonic = mnemonic_from_seed(seed)

    with open(KEYFILE, "w") as f:
        json.dump({"uid": uid, "pubkey": b64u(pub_bytes), "enc": enc}, f)

    print("Account created.")
    print("UID:", uid)
    print("\nRecovery mnemonic (store this safely):")
    print(mnemonic)

def load_keyfile():
    if not KEYFILE.exists():
        print("No keyfile, run init first.")
        sys.exit(1)
    return json.load(open(KEYFILE))

def cmd_whoami():
    meta = load_keyfile()
    uid = meta["uid"]
    pub = b64u_decode(meta["pubkey"])
    fp = hashes.Hash(hashes.SHA256())
    fp.update(pub)
    fingerprint = fp.finalize().hex()[:12]
    print("UID:", uid)
    print("Public key fingerprint (short):", fingerprint)
    print("Public key (base64url):", meta["pubkey"])

def cmd_login():
    meta = load_keyfile()
    uid = meta["uid"]
    pub = b64u_decode(meta["pubkey"])
    passphrase = getpass.getpass("Passphrase: ")
    priv_bytes = decrypt_private_key(meta["enc"], passphrase if passphrase else None)
    priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)

    # simulate server challenge
    challenge = secrets.token_bytes(32)
    sig = priv.sign(challenge)
    # server verifies
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pubkey = Ed25519PublicKey.from_public_bytes(pub)
    try:
        pubkey.verify(sig, challenge)
        print("Login successful. Server verified signature.")
    except InvalidSignature:
        print("Login failed. Signature mismatch.")

def cmd_export_mnemonic():
    meta = load_keyfile()
    print("Export not implemented fully in demo.")
    print("Just back up the keyfile and mnemonic printed at init.")

def cmd_import_mnemonic(mn: str):
    seed = mnemonic_to_seed(mn)
    print("Imported seed:", seed.hex())
    print("This demo does not regenerate the same keypair yet.")

def main():
    if len(sys.argv) < 2:
        print("Usage: cli_chat_client.py [init|whoami|login|export-mnemonic|import-mnemonic]")
        return
    cmd = sys.argv[1]
    if cmd == "init": cmd_init()
    elif cmd == "whoami": cmd_whoami()
    elif cmd == "login": cmd_login()
    elif cmd == "export-mnemonic": cmd_export_mnemonic()
    elif cmd == "import-mnemonic":
        if len(sys.argv) < 3:
            print("Usage: import-mnemonic <mnemonic>")
        else:
            cmd_import_mnemonic(" ".join(sys.argv[2:]))
    else:
        print("Unknown command", cmd)

if __name__ == "__main__":
    main()
