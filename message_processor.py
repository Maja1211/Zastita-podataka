import base64
import hashlib
import zlib
import json
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

from key_manager import get_private_key_for_use, get_public_key_for_use, get_current_time, describe_public_key


# ==========================================================
# Radix-64 (OpenPGP ASCII armor) helpers
# ==========================================================

CRC24_INIT = 0xB704CE
CRC24_POLY = 0x1864CFB


def crc24(data):
    crc = CRC24_INIT
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= CRC24_POLY
    return crc & 0xFFFFFF


def radix64_encode(raw_bytes):
    body_b64 = base64.b64encode(raw_bytes).decode('ascii')
    crc_value = crc24(raw_bytes)
    crc_bytes = crc_value.to_bytes(3, 'big')
    crc_b64 = base64.b64encode(crc_bytes).decode('ascii')
    # format: telo poruke u base64, pa na kraju posebna linija sa CRC-om,
    # bas kao u PGP ASCII armor formatu (npr. "=njUN").
    return (body_b64 + "\n=" + crc_b64).encode('ascii')


def radix64_decode(armored_bytes):
    text = armored_bytes.decode('ascii')
    if "\n=" not in text:
        raise ValueError("Radix-64 format is invalid: CRC line not found.")
    body_b64, crc_b64 = text.rsplit("\n=", 1)
    body_bytes = base64.b64decode(body_b64)
    declared_crc = base64.b64decode(crc_b64.strip())
    computed_crc = crc24(body_bytes).to_bytes(3, 'big')
    if declared_crc != computed_crc:
        raise ValueError("CRC check failed: the message was corrupted during transfer.")
    return body_bytes


def apply_padding(data, block_size):
    padder = sym_padding.PKCS7(block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data


def remove_padding(padded_data, block_size):
    unpadder = sym_padding.PKCS7(block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data


def sign_data(data, private_key):
    signature = private_key.sign(
        data,
        asym_padding.PKCS1v15(),
        hashes.SHA1()
    )
    return signature


def verify_signature(data, signature, public_key):
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PKCS1v15(),
            hashes.SHA1()
        )
        return True
    except Exception:
        return False


def process_and_send_message(
        original_text, output_path,
        filename="message.txt",
        do_sign=False, sender_key_id=None, sender_password=None,
        do_encrypt=False, receiver_key_id=None, sym_algo="AES128",
        do_compress=False, do_radix64=False
):
    data = original_text.encode('utf-8')

    message_structure = {
        "is_signed": do_sign,
        "is_encrypted": do_encrypt,
        "is_compressed": do_compress,
        "is_radix64": do_radix64,
        "sender_key_id": sender_key_id,
        "receiver_key_id": receiver_key_id,
        "sym_algo": sym_algo,
        "filename": filename,
        "message_timestamp": get_current_time()
    }

    # 1. Signing
    if do_sign:
        private_key = get_private_key_for_use(sender_key_id, sender_password)

        # hes se racuna nad podacima i vremenom nastajanja potpisa, da bi se
        # sprecio replay napad (isti potpis ponovo iskoriscen uz drugu poruku).
        signature_timestamp = get_current_time()
        sign_input = data + signature_timestamp.encode('utf-8')

        digest = hashlib.sha1(sign_input).digest()
        signature = sign_data(sign_input, private_key)

        message_structure["signature"] = base64.b64encode(signature).decode('utf-8')
        message_structure["signature_timestamp"] = signature_timestamp
        # vodeca dva okteta hes vrednosti - primalac njima brzo proverava da li
        # koristi ispravan javni kljuc, pre nego što uradi punu RSA verifikaciju.
        message_structure["signature_leading_octets"] = base64.b64encode(digest[:2]).decode('utf-8')

    # 2. Compression
    if do_compress:
        data = zlib.compress(data)

    # 3. Encryption
    if do_encrypt:
        public_key = get_public_key_for_use(receiver_key_id)

        if sym_algo == "AES128":
            session_key = os.urandom(16)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
            block_size = 128
        elif sym_algo == "TripleDES":
            session_key = os.urandom(24)
            iv = os.urandom(8)
            cipher = Cipher(algorithms.TripleDES(session_key), modes.CBC(iv), backend=default_backend())
            block_size = 64
        else:
            raise ValueError("Unsupported algorithm. Choose AES128 or TripleDES.")

        encryptor = cipher.encryptor()
        padded_data = apply_padding(data, block_size)
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        encrypted_session_key = public_key.encrypt(
            session_key,
            asym_padding.PKCS1v15()
        )

        message_structure["iv"] = base64.b64encode(iv).decode('utf-8')
        message_structure["encrypted_session_key"] = base64.b64encode(encrypted_session_key).decode('utf-8')
        data = ciphertext

    # final packing
    message_structure["data"] = base64.b64encode(data).decode('utf-8')
    final_payload = json.dumps(message_structure).encode('utf-8')

    # radix-64 (sa CRC-24 za detekciju gresaka u prenosu)
    if do_radix64:
        final_payload = radix64_encode(final_payload)

    with open(output_path, 'wb') as f:
        f.write(final_payload)


def _parse_message_file(file_path):
    """
    Ucitava fajl i prepoznaje o kakvom paketu se radi (radix-64 armor sa CRC-om,
    ili cist JSON), ne dirajuci nijedan kljuc. Ovo omogucava da se pre trazenja
    lozinke/kljuca prvo utvrdi da li je poruka uopste enkriptovana, i ako jeste,
    kojim je tacno kljucem enkriptovana (receiver_key_id je vec sadrzan u fajlu).
    """
    with open(file_path, 'rb') as f:
        raw_payload = f.read()

    message_structure = None
    try:
        message_structure = json.loads(radix64_decode(raw_payload).decode('utf-8'))
    except ValueError as crc_error:
        # fajl je prepoznat kao radix-64, ali je CRC provera pukla - to je
        # jasna greska u prenosu/ostecenju fajla, ne treba je progutati.
        if "CRC check failed" in str(crc_error):
            raise
    except Exception:
        message_structure = None

    if message_structure is None:
        try:
            message_structure = json.loads(raw_payload.decode('utf-8'))
        except Exception:
            raise ValueError("Invalid file format. Package not recognized.")

    return message_structure


def get_message_requirements(file_path):
    """
    Ono sto GUI treba da zna PRE nego sto zatrazi lozinku: da li je poruka
    enkriptovana i, ako jeste, ID privatnog kljuca koji je potreban za
    dekripciju (taj ID dolazi iz same poruke, korisnik ga ne bira rucno -
    tacno kao sto je opisano u PGP.pdf, slajd 28).
    """
    message_structure = _parse_message_file(file_path)
    return {
        "is_signed": message_structure.get("is_signed", False),
        "is_encrypted": message_structure.get("is_encrypted", False),
        "sender_key_id": message_structure.get("sender_key_id"),
        "receiver_key_id": message_structure.get("receiver_key_id"),
    }


def receive_and_process_message(file_path, password=None):
    message_structure = _parse_message_file(file_path)

    data = base64.b64decode(message_structure["data"])

    # 1. Decryption
    if message_structure["is_encrypted"]:
        # ID privatnog kljuca se cita iz same poruke (receiver_key_id), ne
        # bira ga korisnik rucno - poruka vec zna kojim kljucem treba da se
        # otvori, isto kao sto realan PGP klijent radi.
        key_id = message_structure["receiver_key_id"]
        private_key = get_private_key_for_use(key_id, password)
        encrypted_session_key = base64.b64decode(message_structure["encrypted_session_key"])

        session_key = private_key.decrypt(
            encrypted_session_key,
            asym_padding.PKCS1v15()
        )

        iv = base64.b64decode(message_structure["iv"])
        sym_algo = message_structure["sym_algo"]
        cipher = None
        block_size = None
        if sym_algo == "AES128":
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
            block_size = 128
        elif sym_algo == "TripleDES":
            cipher = Cipher(algorithms.TripleDES(session_key), modes.CBC(iv), backend=default_backend())
            block_size = 64

        decryptor = cipher.decryptor()
        padded_data = decryptor.update(data) + decryptor.finalize()
        data = remove_padding(padded_data, block_size)

    # 2. Decompression
    if message_structure["is_compressed"]:
        data = zlib.decompress(data)

    # 3. Verification
    verification_info = "Message is not signed."
    if message_structure["is_signed"]:
        public_key = get_public_key_for_use(message_structure["sender_key_id"])
        signature = base64.b64decode(message_structure["signature"])
        signature_timestamp = message_structure["signature_timestamp"]

        # isti sign_input kao na strani pošiljaoca: podaci + vreme potpisa
        sign_input = data + signature_timestamp.encode('utf-8')

        digest = hashlib.sha1(sign_input).digest()
        declared_leading_octets = base64.b64decode(message_structure["signature_leading_octets"])

        if digest[:2] != declared_leading_octets:
            # brza provera (vodeca dva okteta heša) je pukla - ili je iskoriscen
            # pogrešan javni kljuc, ili je poruka izmenjena
            verification_info = "WARNING: Key check failed - wrong public key or corrupted message."
        else:
            is_valid = verify_signature(sign_input, signature, public_key)
            author_label = describe_public_key(message_structure["sender_key_id"])
            if is_valid:
                verification_info = (
                    f"Signature is VALID. Author: {author_label}, signed at {signature_timestamp}"
                )
            else:
                verification_info = (
                    f"WARNING: Signature is NOT valid or the message has been compromised! "
                    f"(claimed author: {author_label})"
                )

    message_info = {
        "filename": message_structure.get("filename", "unknown"),
        "message_timestamp": message_structure.get("message_timestamp", "unknown"),
        "signature_timestamp": message_structure.get("signature_timestamp")
    }

    return data.decode('utf-8'), verification_info, message_info
