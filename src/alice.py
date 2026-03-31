"""
alice.py
Modul sisi pengirim (Alice) untuk End-to-End Secure Message Delivery.
"""

import json
import socket
from crypto_utils import (
    generate_aes_key,
    aes_encrypt,
    rsa_encrypt,
    sha256_hash,
    sign,
    build_payload,
    payload_to_json,
    serialize_public_key,
    serialize_private_key,
)


class Alice:
    def __init__(self, private_key, public_key, bob_public_key,
                 alice_ip: str = "127.0.0.1", bob_ip: str = "127.0.0.1"):
        self.private_key = private_key
        self.public_key = public_key
        self.bob_public_key = bob_public_key
        self.last_source_port: int | None = None
        self.alice_ip = alice_ip
        self.bob_ip = bob_ip

        # State untuk logging / GUI
        self.log: list[str] = []
        self.last_payload: dict | None = None
        self.last_aes_key: bytes | None = None
        self.last_hash_hex: str | None = None

    def _log(self, msg: str):
        self.log.append(msg)
        print(f"[Alice] {msg}")

    def prepare_secure_message(self, plaintext: str) -> dict:
        """
        Lakukan seluruh proses sisi Alice:
        1. Generate AES key
        2. Encrypt plaintext (AES-256-CBC)
        3. Encrypt AES key dengan public key Bob (RSA-OAEP)
        4. Hash plaintext (SHA-256)
        5. Sign hash dengan private key Alice (RSA-PSS)
        6. Build payload
        Mengembalikan payload dict.
        """
        self.log.clear()
        plaintext_bytes = plaintext.encode("utf-8")

        # Step 1: Generate AES key
        self._log("Membuat AES-256 symmetric key secara acak...")
        aes_key = generate_aes_key()
        self.last_aes_key = aes_key
        self._log(f"AES Key (hex): {aes_key.hex()}")

        # Step 2: Encrypt plaintext
        self._log("Mengenkripsi plaintext dengan AES-256-CBC...")
        iv, ciphertext = aes_encrypt(plaintext_bytes, aes_key)
        self._log(f"IV (hex): {iv.hex()}")
        self._log(f"Ciphertext (hex): {ciphertext.hex()}")

        # Step 3: Encrypt AES key with Bob's public key
        self._log("Mengenkripsi AES key menggunakan public key Bob (RSA-OAEP)...")
        encrypted_key = rsa_encrypt(self.bob_public_key, aes_key)
        self._log(f"Encrypted AES Key (hex): {encrypted_key.hex()[:64]}...")

        # Step 4: Hash plaintext
        self._log("Menghitung hash SHA-256 dari plaintext...")
        data_hash = sha256_hash(plaintext_bytes)
        self.last_hash_hex = data_hash.hex()
        self._log(f"SHA-256 Hash: {data_hash.hex()}")

        # Step 5: Sign hash
        self._log("Membuat digital signature menggunakan private key Alice (RSA-PSS)...")
        signature = sign(self.private_key, data_hash)
        self._log(f"Signature (hex): {signature.hex()[:64]}...")

        # Step 6: Build payload
        self._log("Membangun payload...")
        payload = build_payload(
            source_ip=self.alice_ip,
            dest_ip=self.bob_ip,
            iv=iv,
            ciphertext=ciphertext,
            encrypted_key=encrypted_key,
            data_hash=data_hash,
            signature=signature
        )
        self.last_payload = payload
        self._log("Payload siap dikirim.")
        return payload

    def send_payload(self, payload: dict, bob_port: int = 9999, alice_port: int | None = None) -> bool:
        try:
            payload_json = payload_to_json(payload).encode("utf-8")
            self._log(f"Menghubungkan ke {self.bob_ip}:{bob_port}...")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.bob_ip, bob_port))
                local_ip, local_port = s.getsockname()
                self.last_source_port = local_port
                self._log(f"Source port yang dipakai: {local_port}")
                length = len(payload_json)
                s.sendall(length.to_bytes(4, "big") + payload_json)
            self._log(f"Payload berhasil dikirim ke {self.bob_ip}:{bob_port} ({length} bytes).")
            return True
        except Exception as e:
            self._log(f"ERROR saat pengiriman: {e}")
            return False

    def prepare_and_send(
        self,
        plaintext: str,
        bob_port: int = 9999,
        alice_port: int | None = None,
    ) -> tuple[dict, bool]:
        """Helper: prepare + send dalam satu langkah."""
        payload = self.prepare_secure_message(plaintext)
        success = self.send_payload(payload, bob_port=bob_port, alice_port=alice_port)
        return payload, success
