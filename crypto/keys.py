from mnemonic import Mnemonic
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .constants import HKDF_INFO


def generate_mnemonic(strength: int = 128) -> str:
    """
    Generate a BIP39 mnemonic phrase.

    Args:
        strength: 128 bits -> 12 words, 256 -> 24 words

    Returns:
        Mnemonic phrase as a string
    """
    mn = Mnemonic("english")
    return mn.generate(strength=strength)


def mnemonic_to_bip39_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Convert mnemonic to BIP39 seed.

    Args:
        mnemonic: BIP39 mnemonic phrase
        passphrase: Optional passphrase for additional security

    Returns:
        512-bit derived seed as bytes
    """
    mn = Mnemonic("english")
    return mn.to_seed(mnemonic, passphrase=passphrase)


def derive_ed25519_seed_from_bip39_seed(bip39_seed: bytes) -> bytes:
    """
    Derive 32 bytes deterministically from bip39 seed using HKDF-SHA512.
    (Alternative: use SLIP-0010 if you need HD derivation)

    Args:
        bip39_seed: 512-bit BIP39 seed

    Returns:
        32-byte seed suitable for Ed25519
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
    Generate Ed25519 keypair from 32-byte seed.

    Args:
        seed32: 32-byte seed

    Returns:
        Ed25519PrivateKey instance

    Raises:
        ValueError: If seed is not exactly 32 bytes
    """
    if len(seed32) != 32:
        raise ValueError("seed32 must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed32)

