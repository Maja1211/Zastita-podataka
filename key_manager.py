from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from key_storage import (
    load_public_keys,
    load_private_keys,
    save_public_keys,
    save_private_keys
)


def make_key_id(public_key):
    numbers = public_key.public_numbers()
    n = numbers.n
    last_64_bits = n & ((1 << 64) - 1)
    key_id = format(last_64_bits, "016X")
    return key_id

def make_user_id(name, email):
    user_id = name + " <" + email + ">"
    return user_id


def get_current_time():
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return current_time


def generate_private_key(key_size):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    return private_key


def convert_public_key_to_pem(public_key):
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pem_text = pem_bytes.decode("utf-8")
    return pem_text


def convert_private_key_to_encrypted_pem(private_key, password):
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        )
    )
    pem_text = pem_bytes.decode("utf-8")
    return pem_text


def create_public_key_record(key_id, name, email, key_size, created_at, public_key_pem):
    record = {
        "key_id": key_id,
        "name": name,
        "email": email,
        "user_id": make_user_id(name, email),
        "key_size": key_size,
        "created_at": created_at,
        "public_key": public_key_pem
    }
    return record


def create_private_key_record(key_id, name, email, key_size, created_at, public_key_pem, encrypted_private_key_pem):
    record = {
        "key_id": key_id,
        "name": name,
        "email": email,
        "user_id": make_user_id(name, email),
        "key_size": key_size,
        "created_at": created_at,
        "public_key": public_key_pem,
        "encrypted_private_key": encrypted_private_key_pem
    }
    return record


def generate_rsa_key_pair(name, email, key_size, password):
    if key_size != 1024 and key_size != 2048:
        raise ValueError("Key size must be 1024 or 2048.")
    if name == "":
        raise ValueError("Name cannot be empty.")
    if email == "":
        raise ValueError("Email cannot be empty.")
    if password == "":
        raise ValueError("Password cannot be empty.")
    private_key = generate_private_key(key_size)
    public_key = private_key.public_key()
    key_id = make_key_id(public_key)
    created_at = get_current_time()
    public_key_pem = convert_public_key_to_pem(public_key)
    encrypted_private_key_pem = convert_private_key_to_encrypted_pem(private_key, password)
    public_record = create_public_key_record(
        key_id,
        name,
        email,
        key_size,
        created_at,
        public_key_pem
    )
    private_record = create_private_key_record(
        key_id,
        name,
        email,
        key_size,
        created_at,
        public_key_pem,
        encrypted_private_key_pem
    )
    public_keys = load_public_keys()
    private_keys = load_private_keys()
    public_keys.append(public_record)
    private_keys.append(private_record)
    save_public_keys(public_keys)
    save_private_keys(private_keys)
    return key_id


def get_public_keys():
    public_keys = load_public_keys()
    return public_keys


def get_private_keys():
    private_keys = load_private_keys()
    return private_keys

def delete_public_key(key_id):
    public_keys = load_public_keys()
    updated_keys = []
    for key in public_keys:
        if key["key_id"] != key_id:
            updated_keys.append(key)
    save_public_keys(updated_keys)


def delete_private_key(key_id):
    private_keys = load_private_keys()
    updated_keys = []
    for key in private_keys:
        if key["key_id"] != key_id:
            updated_keys.append(key)
    save_private_keys(updated_keys)

def get_private_key_for_use(key_id, password):
    private_keys = load_private_keys()
    for record in private_keys:
        if record["key_id"] == key_id:
            encrypted_pem = record["encrypted_private_key"].encode("utf-8")
            private_key = serialization.load_pem_private_key(
                encrypted_pem,
                password=password.encode("utf-8")
            )
            return private_key
    raise ValueError("Private key was not found.")


def get_public_key_for_use(key_id):
    public_keys = load_public_keys()
    for record in public_keys:
        if record["key_id"] == key_id:
            public_pem = record["public_key"].encode("utf-8")
            public_key = serialization.load_pem_public_key(public_pem)
            return public_key
    raise ValueError("Public key was not found.")


def check_private_key_password(key_id, password):
    try:
        get_private_key_for_use(key_id, password)
        return True
    except Exception:
        return False


def export_public_key(key_id, file_path):
    public_keys = load_public_keys()
    for record in public_keys:
        if record["key_id"] == key_id:
            file = open(file_path, "w", encoding="utf-8")
            file.write(record["public_key"])
            file.close()
            return
    raise ValueError("Public key was not found.")

def export_key_pair(key_id, password, file_path):
    private_keys = load_private_keys()
    for record in private_keys:
        if record["key_id"] == key_id:
            if check_private_key_password(key_id, password) == False:
                raise ValueError("Wrong password.")
            file = open(file_path, "w", encoding="utf-8")
            file.write("-----PGP PROJECT KEY PAIR-----\n")
            file.write("key_id: " + record["key_id"] + "\n")
            file.write("name: " + record["name"] + "\n")
            file.write("email: " + record["email"] + "\n")
            file.write("key_size: " + str(record["key_size"]) + "\n")
            file.write("created_at: " + record["created_at"] + "\n")
            file.write("\n")
            file.write(record["public_key"])
            file.write("\n")
            file.write(record["encrypted_private_key"])
            file.close()
            return
    raise ValueError("Private key was not found.")

def import_public_key(file_path, name, email):
    file = open(file_path, "r", encoding="utf-8")
    public_key_pem = file.read()
    file.close()
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode("utf-8")
    )
    key_id = make_key_id(public_key)
    if key_exists_in_public_ring(key_id):
        raise ValueError("Public key already exists in the public key ring.")
    created_at = get_current_time()
    public_record = create_public_key_record(
        key_id,
        name,
        email,
        public_key.key_size,
        created_at,
        public_key_pem
    )
    public_keys = load_public_keys()
    public_keys.append(public_record)
    save_public_keys(public_keys)
    return key_id

def key_exists_in_public_ring(key_id):
    public_keys = load_public_keys()
    for key in public_keys:
        if key["key_id"] == key_id:
            return True
    return False

def key_exists_in_private_ring(key_id):
    private_keys = load_private_keys()
    for key in private_keys:
        if key["key_id"] == key_id:
            return True
    return False

def extract_block(text, begin_text, end_text):
    begin_index = text.find(begin_text)
    end_index = text.find(end_text)
    if begin_index == -1 or end_index == -1:
        raise ValueError("Required PEM block was not found.")
    end_index = end_index + len(end_text)
    block = text[begin_index:end_index]
    return block

def import_key_pair(file_path, password):
    file = open(file_path, "r", encoding="utf-8")
    text = file.read()
    file.close()
    public_key_pem = extract_block(
        text,
        "-----BEGIN PUBLIC KEY-----",
        "-----END PUBLIC KEY-----"
    )
    encrypted_private_key_pem = extract_block(
        text,
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----END ENCRYPTED PRIVATE KEY-----"
    )
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode("utf-8")
    )
    serialization.load_pem_private_key(
        encrypted_private_key_pem.encode("utf-8"),
        password=password.encode("utf-8")
    )
    key_id = make_key_id(public_key)
    if key_exists_in_private_ring(key_id):
        raise ValueError("Private key already exists in the private key ring.")
    created_at = read_value_from_exported_file(text, "created_at")
    name = read_value_from_exported_file(text, "name")
    email = read_value_from_exported_file(text, "email")
    public_record = create_public_key_record(
        key_id,
        name,
        email,
        public_key.key_size,
        created_at,
        public_key_pem
    )
    private_record = create_private_key_record(
        key_id,
        name,
        email,
        public_key.key_size,
        created_at,
        public_key_pem,
        encrypted_private_key_pem
    )
    public_keys = load_public_keys()
    private_keys = load_private_keys()
    if not key_exists_in_public_ring(key_id):
        public_keys.append(public_record)
    private_keys.append(private_record)
    save_public_keys(public_keys)
    save_private_keys(private_keys)
    return key_id

def read_value_from_exported_file(text, field_name):
    lines = text.splitlines()
    for line in lines:
        prefix = field_name + ": "
        if line.startswith(prefix):
            value = line.replace(prefix, "")
            return value
    return "Unknown"

def delete_key_pair(key_id):
    delete_public_key(key_id)
    delete_private_key(key_id)

def get_public_key_table_data():
    public_keys = load_public_keys()
    table_data = []
    for key in public_keys:
        row = {
            "key_id": key["key_id"],
            "name": key["name"],
            "email": key["email"],
            "key_size": key["key_size"],
            "created_at": key["created_at"]
        }
        table_data.append(row)
    return table_data


def get_private_key_table_data():
    private_keys = load_private_keys()
    table_data = []
    for key in private_keys:
        row = {
            "key_id": key["key_id"],
            "name": key["name"],
            "email": key["email"],
            "key_size": key["key_size"],
            "created_at": key["created_at"]
        }
        table_data.append(row)
    return table_data


def describe_public_key(key_id):
    # Umesto sirovog Key ID-a, vraca citljiv opis vlasnika kljuca (ime i mejl),
    # da bi se autor potpisa lakse prepoznao pri prijemu poruke.
    for record in get_public_keys():
        if record["key_id"] == key_id:
            short_id = record["key_id"][-8:]
            return f"{record['name']} <{record['email']}> (Key ID ...{short_id})"
    return f"Key ID {key_id} (unknown - not in your public key ring)"