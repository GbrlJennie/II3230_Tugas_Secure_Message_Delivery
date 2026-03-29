"""
demo.py
Demo CLI lengkap End-to-End Secure Message Delivery.
Menunjukkan seluruh alur dari Alice ke Bob dalam satu proses (simulasi lokal).
"""

import time
import json
from key_manager import setup_all_keys
from alice import Alice
from bob import Bob
from crypto_utils import payload_to_json


SEPARATOR = "=" * 70


def print_section(title: str):
    print(f"\n{SEPARATOR}")
    print(f"  {title}")
    print(SEPARATOR)


def run_demo(plaintext: str = None, alice_ip: str = "127.0.0.1", bob_ip: str = "127.0.0.1", port: int = 9999):
    if plaintext is None:
        plaintext = "Bob, transfer dana penelitian sebesar 10 juta ke rekening Lab Keamanan."

    print_section("SETUP: Generate / Load RSA Keys")
    keys = setup_all_keys()

    # ─── Inisialisasi Alice & Bob ───
    alice = Alice(
        private_key=keys["alice_private"],
        public_key=keys["alice_public"],
        bob_public_key=keys["bob_public"],
        alice_ip=alice_ip,
        bob_ip=bob_ip,
    )

    received_results = []

    def on_received(result):
        received_results.append(result)

    bob_receiver = Bob(
        private_key=keys["bob_private"],
        alice_public_key=keys["alice_public"],
        listen_ip="0.0.0.0",
        port=port,
    )

    # ─── Bob mulai mendengarkan ───
    print_section("BOB: Mulai Mendengarkan")
    bob_receiver.start_listening(callback=on_received)
    time.sleep(0.3)  # beri waktu server socket bind

    # ─── Alice menyiapkan dan mengirim pesan ───
    print_section("ALICE: Menyiapkan Pesan")
    print(f"  Plaintext: {plaintext}")
    payload = alice.prepare_secure_message(plaintext)

    print_section("ALICE: Payload yang Akan Dikirim")
    payload_str = payload_to_json(payload)
    print(payload_str)

    print_section("ALICE: Mengirim Payload ke Bob")
    success = alice.send_payload(payload, port=port)
    if not success:
        print("  ✗ Gagal mengirim payload!")
        bob_receiver.stop_listening()
        return

    # Tunggu Bob memproses
    time.sleep(0.5)

    # ─── Tampilkan hasil verifikasi Bob ───
    print_section("BOB: Hasil Verifikasi")
    if received_results:
        result = received_results[0]
        print(f"  Plaintext yang diterima : {result.plaintext}")
        print(f"  AES Key (dekripsi)      : {result.aes_key_hex[:32]}...")
        print(f"  Hash dihitung ulang     : {result.computed_hash_hex}")
        print(f"  Hash dari payload       : {result.received_hash_hex}")
        print(f"  Hash Match              : {'✓ VALID' if result.hash_match else '✗ INVALID'}")
        print(f"  Signature Valid         : {'✓ VALID' if result.signature_valid else '✗ INVALID'}")
        print(f"\n  {'✓ PESAN SAH: Berhasil didekripsi, integritas terjaga, pengirim terverifikasi.' if result.success else '✗ PESAN TIDAK SAH!'}")
    else:
        print("  Tidak ada pesan yang diterima.")

    bob_receiver.stop_listening()

    print_section("DEMO SELESAI")
    print("  Semua komponen kriptografi berjalan dengan baik.")
    print(SEPARATOR)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Demo End-to-End Secure Message Delivery")
    parser.add_argument("--message", "-m", type=str, default=None,
                        help="Pesan plaintext yang akan dikirim")
    parser.add_argument("--alice-ip", type=str, default="127.0.0.1")
    parser.add_argument("--bob-ip", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    args = parser.parse_args()

    run_demo(
        plaintext=args.message,
        alice_ip=args.alice_ip,
        bob_ip=args.bob_ip,
        port=args.port,
    )
