"""
bob.py
Modul sisi penerima (Bob) untuk End-to-End Secure Message Delivery.
"""

import socket
import threading
from crypto_utils import (
    rsa_decrypt,
    aes_decrypt,
    sha256_hash,
    verify_signature,
    payload_from_json,
    decode_payload_fields,
)


class BobVerificationResult:
    """Hasil verifikasi pesan di sisi Bob."""

    def __init__(self):
        self.plaintext: str = ""
        self.aes_key_hex: str = ""
        self.hash_match: bool = False
        self.signature_valid: bool = False
        self.computed_hash_hex: str = ""
        self.received_hash_hex: str = ""
        self.success: bool = False
        self.error: str = ""
        self.log: list[str] = []

    def summary(self) -> str:
        lines = [
            f"Plaintext    : {self.plaintext}",
            f"Hash Match   : {'✓ Valid' if self.hash_match else '✗ Invalid'}",
            f"Signature    : {'✓ Valid' if self.signature_valid else '✗ Invalid'}",
            f"Overall      : {'✓ PESAN SAH' if self.success else '✗ PESAN TIDAK SAH'}",
        ]
        return "\n".join(lines)


class Bob:
    """
    Representasi penerima (Bob) dalam skenario secure message delivery.
    """

    def __init__(self, private_key, alice_public_key,
                 listen_ip: str = "0.0.0.0", port: int = 9999):
        self.private_key = private_key
        self.alice_public_key = alice_public_key
        self.listen_ip = listen_ip
        self.port = port

        self._server_thread: threading.Thread | None = None
        self._server_socket: socket.socket | None = None
        self._running = False

        # Callback dipanggil saat pesan diterima: fn(result: BobVerificationResult)
        self.on_message_received = None

        self.log: list[str] = []

    def _log(self, msg: str):
        self.log.append(msg)
        print(f"[Bob] {msg}")

    def process_payload(self, payload_json: str) -> BobVerificationResult:
        """
        Proses payload JSON yang diterima dari Alice:
        1. Dekripsi AES key dengan private key Bob
        2. Dekripsi ciphertext dengan AES key
        3. Hitung hash plaintext dan bandingkan
        4. Verifikasi digital signature
        """
        result = BobVerificationResult()
        self.log.clear()

        try:
            payload = payload_from_json(payload_json)
            fields = decode_payload_fields(payload)

            # Step 1: Decrypt AES key
            self._log("Mendekripsi AES key menggunakan private key Bob (RSA-OAEP)...")
            aes_key = rsa_decrypt(self.private_key, fields["encrypted_key"])
            result.aes_key_hex = aes_key.hex()
            self._log(f"AES Key berhasil didekripsi: {aes_key.hex()}")

            # Step 2: Decrypt ciphertext
            self._log("Mendekripsi ciphertext menggunakan AES-256-CBC...")
            plaintext_bytes = aes_decrypt(fields["iv"], fields["ciphertext"], aes_key)
            result.plaintext = plaintext_bytes.decode("utf-8")
            self._log(f"Plaintext: {result.plaintext}")

            # Step 3: Verify hash
            self._log("Menghitung ulang SHA-256 hash dari plaintext...")
            computed_hash = sha256_hash(plaintext_bytes)
            result.computed_hash_hex = computed_hash.hex()
            result.received_hash_hex = fields["hash"].hex()
            result.hash_match = (computed_hash == fields["hash"])
            self._log(f"Hash dihitung : {result.computed_hash_hex}")
            self._log(f"Hash diterima : {result.received_hash_hex}")
            self._log(f"Hash match    : {'✓ Ya' if result.hash_match else '✗ Tidak'}")

            # Step 4: Verify signature
            self._log("Memverifikasi digital signature menggunakan public key Alice (RSA-PSS)...")
            result.signature_valid = verify_signature(
                self.alice_public_key,
                fields["hash"],
                fields["signature"]
            )
            self._log(f"Signature valid: {'✓ Ya' if result.signature_valid else '✗ Tidak'}")

            result.success = result.hash_match and result.signature_valid
            result.log = list(self.log)

            if result.success:
                self._log("✓ Pesan valid: berhasil didekripsi, integritas terjaga, pengirim terverifikasi.")
            else:
                self._log("✗ Pesan TIDAK valid!")

        except Exception as e:
            result.error = str(e)
            result.log = list(self.log)
            self._log(f"ERROR: {e}")

        return result

    def _handle_client(self, conn: socket.socket, addr):
        """Handle satu koneksi masuk dari Alice."""
        try:
            self._log(f"Koneksi diterima dari {addr[0]}:{addr[1]}")
            # Baca 4 byte panjang, lalu baca isi
            raw_len = conn.recv(4)
            if len(raw_len) < 4:
                return
            msg_len = int.from_bytes(raw_len, "big")
            data = b""
            while len(data) < msg_len:
                chunk = conn.recv(min(4096, msg_len - len(data)))
                if not chunk:
                    break
                data += chunk
            payload_json = data.decode("utf-8")
            self._log(f"Payload diterima ({len(data)} bytes).")
            result = self.process_payload(payload_json)
            if self.on_message_received:
                self.on_message_received(result)
        except Exception as e:
            self._log(f"ERROR handle client: {e}")
        finally:
            conn.close()

    def start_listening(self, callback=None):
        """Mulai server listener di thread terpisah."""
        if callback:
            self.on_message_received = callback
        self._running = True
        self._server_thread = threading.Thread(target=self._serve, daemon=True)
        self._server_thread.start()
        self._log(f"Mendengarkan di {self.listen_ip}:{self.port}...")

    def _serve(self):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.listen_ip, self.port))
        self._server_socket.listen(5)
        while self._running:
            try:
                self._server_socket.settimeout(1.0)
                conn, addr = self._server_socket.accept()
                t = threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop_listening(self):
        """Hentikan server listener."""
        self._running = False
        if self._server_socket:
            self._server_socket.close()
        self._log("Server dihentikan.")
