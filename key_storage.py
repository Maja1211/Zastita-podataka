import json
import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

PUBLIC_RING_FILE = os.path.join(DATA_DIR, "public_key_ring.json")
PRIVATE_RING_FILE = os.path.join(DATA_DIR, "private_key_ring.json")


def prepare_storage():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    if not os.path.exists(PUBLIC_RING_FILE):
        save_public_keys([])
    if not os.path.exists(PRIVATE_RING_FILE):
        save_private_keys([])


def load_keys(file_path):
    prepare_storage()
    with open(file_path, "r", encoding="utf-8") as file:
        text = file.read().strip()
    if text == "":
        return []
    return json.loads(text)


def save_keys(file_path, keys):
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(keys, file, indent=4, ensure_ascii=False)


def load_public_keys():
    return load_keys(PUBLIC_RING_FILE)


def load_private_keys():
    return load_keys(PRIVATE_RING_FILE)


def save_public_keys(keys):
    save_keys(PUBLIC_RING_FILE, keys)


def save_private_keys(keys):
    save_keys(PRIVATE_RING_FILE, keys)