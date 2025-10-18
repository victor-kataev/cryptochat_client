import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, BestAvailableEncryption
)
import keyring

from .constants import PRIVATE_KEY_FILENAME, KEYRING_SERVICE, KEYRING_KEY_NAME
from .keys import (
    generate_mnemonic,
    mnemonic_to_bip39_seed,
    derive_ed25519_seed_from_bip39_seed,
    ed25519_keypair_from_seed
)


def serialize_private_key_pkcs8_encrypted(private_key: Ed25519PrivateKey, passphrase: bytes) -> bytes:
    """
    Serialize private key to PKCS8 format with encryption.

    Args:
        private_key: Ed25519 private key
        passphrase: Passphrase for encryption

    Returns:
        PEM-encoded encrypted private key
    """
    pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(passphrase)
    )
    return pem


def store_key_in_keyring(key_bytes: bytes):
    """
    Store symmetric key in system keyring.

    Args:
        key_bytes: Key bytes to store
    """
    key_b64 = base64.b64encode(key_bytes).decode()
    keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_NAME, key_b64)


def retrieve_key_from_keyring() -> bytes:
    """
    Retrieve symmetric key from system keyring.

    Returns:
        Key bytes

    Raises:
        RuntimeError: If key not found in keyring
    """
    key_b64 = keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_NAME)
    if not key_b64:
        raise RuntimeError("Sym key not found in keyring")
    return base64.b64decode(key_b64)


def write_private_pem_file(pem_bytes: bytes, path: str = PRIVATE_KEY_FILENAME):
    """
    Write private key file with secure permissions.

    Args:
        pem_bytes: Key bytes to write
        path: File path (defaults to PRIVATE_KEY_FILENAME)
    """
    dirname = os.path.dirname(path)
    os.makedirs(dirname, mode=0o700, exist_ok=True)
    with open(path, "wb") as f:
        f.write(pem_bytes)
    os.chmod(path, 0o600)


def load_ed25519_from_blob(blob_path: str, sym_key: bytes) -> Ed25519PrivateKey:
    """
    Load Ed25519 private key from encrypted blob file.

    Args:
        blob_path: Path to encrypted blob file
        sym_key: Symmetric key for decryption

    Returns:
        Ed25519PrivateKey instance

    Raises:
        ValueError: If blob is corrupted or invalid
    """
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


def create_account_with_mnemonic(passphrase_for_storage: str | None = None, auto_store_in_keyring: bool = True) -> tuple[str, str]:
    """
    Create a new account with mnemonic and store the private key.

    Args:
        passphrase_for_storage: Optional passphrase for encrypting stored key
        auto_store_in_keyring: If True and no passphrase, store encryption key in keyring

    Returns:
        Tuple of (mnemonic phrase, base64-encoded public key)
    """
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
    """
    Read private key from encrypted blob file using keyring.

    Returns:
        Ed25519PrivateKey instance

    Raises:
        RuntimeError: If key not found in keyring
        ValueError: If blob file is corrupted
    """
    sym_key = retrieve_key_from_keyring()
    return load_ed25519_from_blob(PRIVATE_KEY_FILENAME + ".blob", sym_key)
