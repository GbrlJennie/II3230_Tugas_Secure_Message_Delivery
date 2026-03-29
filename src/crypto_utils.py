"""
crypto_utils.py
Modul utilitas kriptografi untuk End-to-End Secure Message Delivery.
Menggunakan: AES-256-CBC (symmetric), RSA-2048 (asymmetric), SHA-256 (hash), RSA-PSS (signature)
"""

import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


# ─────────────────────────────────────────────
# 1. RSA Key Generation
# ─────────────────────────────────────────────

def generate_rsa_keypair(key_size: int = 2048):
    """Generate RSA private/public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_private_key(pem_bytes: bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None, backend=default_backend())


def load_public_key(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes, backend=default_backend())


# ─────────────────────────────────────────────
# 2. Symmetric Encryption (AES-256-CBC)
# ─────────────────────────────────────────────

def generate_aes_key() -> bytes:
    """Generate random 256-bit AES key."""
    return os.urandom(32)  # 32 bytes = 256 bit


def aes_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-CBC. Returns (iv, ciphertext)."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # PKCS7 padding
    pad_len = 16 - (len(plaintext) % 16)
    plaintext_padded = plaintext + bytes([pad_len] * pad_len)

    ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()
    return iv, ciphertext


def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-CBC ciphertext. Returns plaintext."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    pad_len = plaintext_padded[-1]
    return plaintext_padded[:-pad_len]


# ─────────────────────────────────────────────
# 3. Asymmetric Encryption (RSA-OAEP)
# ─────────────────────────────────────────────

def rsa_encrypt(public_key, data: bytes) -> bytes:
    """Encrypt data using RSA public key (OAEP padding)."""
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(private_key, encrypted_data: bytes) -> bytes:
    """Decrypt data using RSA private key (OAEP padding)."""
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ─────────────────────────────────────────────
# 4. Hash Function (SHA-256)
# ─────────────────────────────────────────────

def sha256_hash(data: bytes) -> bytes:
    """Compute SHA-256 hash of data."""
    return hashlib.sha256(data).digest()


def sha256_hash_hex(data: bytes) -> str:
    """Compute SHA-256 hash of data, return as hex string."""
    return hashlib.sha256(data).hexdigest()


# ─────────────────────────────────────────────
# 5. Digital Signature (RSA-PSS)
# ─────────────────────────────────────────────

def sign(private_key, data_hash: bytes) -> bytes:
    """Sign hash with RSA private key using PSS padding."""
    return private_key.sign(
        data_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature(public_key, data_hash: bytes, signature: bytes) -> bool:
    """Verify RSA-PSS signature. Returns True if valid."""
    try:
        public_key.verify(
            signature,
            data_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────
# 6. Payload Builder & Parser
# ─────────────────────────────────────────────

def build_payload(
    source_ip: str,
    dest_ip: str,
    iv: bytes,
    ciphertext: bytes,
    encrypted_key: bytes,
    data_hash: bytes,
    signature: bytes
) -> dict:
    """Build JSON-serializable payload dict."""
    return {
        "source_ip": source_ip,
        "destination_ip": dest_ip,
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iv": base64.b64encode(iv).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "hash": base64.b64encode(data_hash).decode(),
        "signature": base64.b64encode(signature).decode(),
        "hash_algorithm": "SHA-256",
        "symmetric_algorithm": "AES-256-CBC",
        "asymmetric_algorithm": "RSA-2048-OAEP",
        "signature_algorithm": "RSA-PSS"
    }


def payload_to_json(payload: dict) -> str:
    return json.dumps(payload, indent=2)


def payload_from_json(json_str: str) -> dict:
    return json.loads(json_str)


def decode_payload_fields(payload: dict) -> dict:
    """Decode base64 fields from payload for processing."""
    return {
        "source_ip": payload["source_ip"],
        "destination_ip": payload["destination_ip"],
        "ciphertext": base64.b64decode(payload["ciphertext"]),
        "iv": base64.b64decode(payload["iv"]),
        "encrypted_key": base64.b64decode(payload["encrypted_key"]),
        "hash": base64.b64decode(payload["hash"]),
        "signature": base64.b64decode(payload["signature"]),
    }
