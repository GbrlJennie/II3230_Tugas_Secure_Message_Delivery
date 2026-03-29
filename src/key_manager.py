"""
key_manager.py
Modul manajemen kunci RSA: generate, simpan, dan muat dari file.
"""

import os
from pathlib import Path
from crypto_utils import (
    generate_rsa_keypair,
    serialize_private_key,
    serialize_public_key,
    load_private_key,
    load_public_key,
)

KEYS_DIR = Path(__file__).parent / "keys"


def ensure_keys_dir():
    KEYS_DIR.mkdir(exist_ok=True)


def generate_and_save_keys(identity: str):
    """
    Generate RSA keypair untuk identity (alice / bob) dan simpan ke folder keys/.
    Returns: (private_key_obj, public_key_obj)
    """
    ensure_keys_dir()
    private_key, public_key = generate_rsa_keypair()

    priv_path = KEYS_DIR / f"{identity}_private.pem"
    pub_path = KEYS_DIR / f"{identity}_public.pem"

    priv_path.write_bytes(serialize_private_key(private_key))
    pub_path.write_bytes(serialize_public_key(public_key))

    print(f"[KeyManager] Keys generated for '{identity}': {priv_path}, {pub_path}")
    return private_key, public_key


def load_keys(identity: str):
    """
    Muat RSA keypair dari file untuk identity.
    Returns: (private_key_obj, public_key_obj)
    """
    priv_path = KEYS_DIR / f"{identity}_private.pem"
    pub_path = KEYS_DIR / f"{identity}_public.pem"

    if not priv_path.exists() or not pub_path.exists():
        raise FileNotFoundError(f"Keys not found for '{identity}'. Run generate_and_save_keys() first.")

    private_key = load_private_key(priv_path.read_bytes())
    public_key = load_public_key(pub_path.read_bytes())
    return private_key, public_key


def load_public_key_only(identity: str):
    """Muat hanya public key dari file."""
    pub_path = KEYS_DIR / f"{identity}_public.pem"
    if not pub_path.exists():
        raise FileNotFoundError(f"Public key not found for '{identity}'.")
    return load_public_key(pub_path.read_bytes())


def keys_exist(identity: str) -> bool:
    priv_path = KEYS_DIR / f"{identity}_private.pem"
    pub_path = KEYS_DIR / f"{identity}_public.pem"
    return priv_path.exists() and pub_path.exists()


def setup_all_keys(force: bool = False):
    """
    Setup kunci untuk Alice dan Bob.
    Jika sudah ada dan force=False, kunci lama digunakan.
    Returns: dict dengan semua key objects.
    """
    for identity in ["alice", "bob"]:
        if force or not keys_exist(identity):
            print(f"[KeyManager] Generating keys for {identity}...")
            generate_and_save_keys(identity)
        else:
            print(f"[KeyManager] Keys for {identity} already exist, loading...")

    alice_priv, alice_pub = load_keys("alice")
    bob_priv, bob_pub = load_keys("bob")

    return {
        "alice_private": alice_priv,
        "alice_public": alice_pub,
        "bob_private": bob_priv,
        "bob_public": bob_pub,
    }
