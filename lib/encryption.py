from mnemonic import Mnemonic
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, BestAvailableEncryption,
    load_pem_private_key, load_der_private_key
)
# from cryptography.hazmat.primitives.serialization.pkcs8 import (
#     load_pem_private_key as load_pkcs8_pem
# )
from argon2 import PasswordHasher
import keyring
import os, base64


ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 1 << 16  # 65536 KiB = 64 MiB, tune per platform
ARGON2_PARALLELISM = 1
HKDF_INFO = b"crpytochat v1 ed25519 seed"   # domain separation
PRIVATE_KEY_FILENAME = os.path.expanduser("~/.cryptochat/id_ed25519.pem")


def generate_mnemonic(strength: int = 128) -> str:
    """
    strength: 128 bits -> 12 words, 256 -> 24 words
    """
    mn = Mnemonic("english")
    return mn.generate(strength=strength)


def mnemonic_to_bip39_seed(mnemonic: str, passphrase: str = "") -> bytes:
    mn = Mnemonic("english")
    return mn.to_seed(mnemonic, passphrase=passphrase)  # returns bytes (512-bit derived seed)


def derive_ed25519_seed_from_bip39_seed(bip39_seed: bytes) -> bytes:
    """
    Derive 32 bytes deterministically from bip39 seed using HKDF-SHA512
    (Alternative: use SLIP-0010 if you need HD derivation)
    """
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    )
    return hkdf.derive(bip39_seed)


def ed25519_keypair_from_seed(seed32: bytes) -> Ed25519PrivateKey:
    """
    seed32 must be 32 bytes. Ed25519 private key is the 32-byte seed in most libs.
    """
    if len(seed32) != 32:
        raise ValueError("seed32 must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed32)


def serialize_private_key_pkcs8_encrypted(private_key: Ed25519PrivateKey, passphrase: bytes) -> bytes:
    pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(passphrase)
    )
    return pem


# ph = PasswordHasher(time_cost=ARGON2_TIME_COST, memory_cost=ARGON2_MEMORY_COST, parallelism=ARGON2_PARALLELISM)

# from argon2.low_level import hash_secret_raw, Type

# def derive_key_argon2id(passphrase: str, salt: bytes, length: int = 32) -> bytes:
#     """
#     Derive symmetric key from passphrase using argon2
#     """
#     return hash_secret_raw(
#         secret=passphrase.encode(),
#         salt=salt,
#         time_cost=ARGON2_TIME_COST,
#         memory_cost=ARGON2_MEMORY_COST,
#         parallelism=ARGON2_PARALLELISM,
#         hash_len=length,
#         type=Type.ID
#     )


KEYRING_SERVICE = "cryptochat"
KEYRING_KEY_NAME = "local_sym_key"


def store_key_in_keyring(key_bytes: bytes):
    import base64
    key_b64 = base64.b64encode(key_bytes).decode()
    keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_NAME, key_b64)


def retrieve_key_from_keyring() -> bytes:
    import base64
    key_b64 = keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_NAME)
    if not key_b64:
        # return None
        raise RuntimeError("Sym key not found in keyring")
    return base64.b64decode(key_b64)


def write_private_pem_file(pem_bytes: bytes, path: str = PRIVATE_KEY_FILENAME):
    dirname = os.path.dirname(path)
    os.makedirs(dirname, mode=0o700, exist_ok=True)
    with open(path, "wb") as f:
        f.write(pem_bytes)
    os.chmod(path, 0o600)


def load_ed25519_from_blob(blob_path: str, sym_key: bytes) -> Ed25519PrivateKey:
    with open(blob_path, "rb") as f:
        data = f.read()

    if len(data) < 12 + 16:
        raise ValueError("Blob too small or corrupted")

    nonce = data[:12]
    ct = data[12:]
    aes = AESGCM(sym_key)
    raw_priv = aes.decrypt(nonce, ct, None)
    if len(raw_priv) != 32:
        raise ValueError("Unexpected private key size: %d" % len(raw_priv))

    return Ed25519PrivateKey.from_private_bytes(raw_priv)


def load_private_key_from_pkcs8_pem(path: str, passphrase: bytes) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        data = f.read()
    return load_pem_private_key(data, password=passphrase)


def create_account_with_mnemonic(passphrase_for_storage: str | None = None, auto_store_in_keyring: bool = True) -> tuple[str, str]: 
    mnemonic = generate_mnemonic(128)  # 12 words
    bip39_seed = mnemonic_to_bip39_seed(mnemonic, passphrase="")  # allow empty BIP39 passphrase
    seed32 = derive_ed25519_seed_from_bip39_seed(bip39_seed)
    privkey = ed25519_keypair_from_seed(seed32)
    
    # store encrypted private key
    if passphrase_for_storage:
        pem = serialize_private_key_pkcs8_encrypted(privkey, passphrase_for_storage.encode())
        write_private_pem_file(pem)
    else:
        sym_key = os.urandom(32)
        if auto_store_in_keyring:
            store_key_in_keyring(sym_key)

        raw_priv = privkey.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

        aes = AESGCM(sym_key)
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, raw_priv, None)

        blob_path = PRIVATE_KEY_FILENAME + ".blob"
        write_private_pem_file(nonce + ct, blob_path)

    public_bytes = privkey.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )
    pk_str = base64.b64encode(public_bytes).decode('utf-8')
    
    return mnemonic, pk_str


def read_privkey() -> Ed25519PrivateKey:
    sym_key = retrieve_key_from_keyring()
    return load_ed25519_from_blob(PRIVATE_KEY_FILENAME + ".blob", sym_key)


def import_account_from_mnemonic(mnemonic: str):
    ...
