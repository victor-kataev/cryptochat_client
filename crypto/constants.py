import os

# Argon2 parameters
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 1 << 16  # 65536 KiB = 64 MiB, tune per platform
ARGON2_PARALLELISM = 1

# HKDF domain separation
HKDF_INFO = b"crpytochat v1 ed25519 seed"

# File paths
PRIVATE_KEY_FILENAME = os.path.expanduser("~/.cryptochat/id_ed25519.pem")

# Keyring configuration
KEYRING_SERVICE = "cryptochat"
KEYRING_KEY_NAME = "local_sym_key"
