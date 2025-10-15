import os, json
from datetime import datetime

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


def read_uid() -> str:
    if not os.path.exists(METADATA_FILENAME):
        raise ValueError(f"File {METADATA_FILENAME} doesn't exist")
    data = json.load(open(METADATA_FILENAME))
    return data['uid']
