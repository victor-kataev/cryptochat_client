import os
import json
from datetime import datetime

METADATA_FILENAME = os.path.expanduser("~/.cryptochat/metadata.json")


def save_uid(uid: str):
    """
    Save user ID to metadata file.

    Args:
        uid: User ID to save
    """
    dirname = os.path.dirname(METADATA_FILENAME)
    os.makedirs(dirname, mode=0o700, exist_ok=True)
    with open(METADATA_FILENAME, "w") as f:
        data = {
            "uid": uid,
            "created_at": datetime.now().isoformat()
        }
        json.dump(data, f, indent=2)
    os.chmod(METADATA_FILENAME, 0o600)


def read_uid() -> str:
    """
    Read user ID from metadata file.

    Returns:
        User ID

    Raises:
        ValueError: If metadata file doesn't exist
    """
    if not os.path.exists(METADATA_FILENAME):
        raise ValueError(f"File {METADATA_FILENAME} doesn't exist")
    with open(METADATA_FILENAME) as f:
        data = json.load(f)
    return data['uid']
