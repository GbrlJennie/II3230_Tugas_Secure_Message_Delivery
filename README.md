# End-to-End Secure Message Delivery
## II3230 Keamanan Informasi — Latihan Praktikum

---
## Kontributor
| Nama | NIM |
|---|---|
| Naila Selvira Budiana | 18223018 |
| Gabriela Jennifer Sandy | 18223092 |

---

## Struktur Folder

```
secure_delivery/
├── crypto_utils.py      # Utilitas kriptografi (AES, RSA, SHA-256, Signature)
├── alice.py             # Modul sisi pengirim (Alice)
├── bob.py               # Modul sisi penerima (Bob)
├── key_manager.py       # Manajemen RSA keypair (generate & load)
├── demo.py              # Demo CLI lengkap (terminal)
├── GUI.py               # Antarmuka grafis (Tkinter)
├── requirements.txt     # Dependensi Python
├── keys/                # Folder kunci RSA (auto-generated)
│   ├── alice_private.pem
│   ├── alice_public.pem
│   ├── bob_private.pem
│   └── bob_public.pem
└── README.md
```

---

## Instalasi

```bash
pip install -r requirements.txt
```

---

## Cara Menjalankan

### 1. Demo CLI (Terminal)
```bash
python demo.py
```
Dengan pesan custom:
```bash
python demo.py --message "Pesan rahasia saya"
```

### 2. GUI (Antarmuka Grafis)
```bash
python GUI.py
```

---

## Alur Sistem

### Sisi Alice (Pengirim)
1. Menentukan **plaintext** yang akan dikirim
2. Membuat **AES-256 key** secara acak
3. Mengenkripsi plaintext dengan **AES-256-CBC**
4. Mengenkripsi AES key dengan **public key Bob** (RSA-2048-OAEP)
5. Menghitung **SHA-256 hash** dari plaintext
6. Membuat **digital signature** dari hash menggunakan **private key Alice** (RSA-PSS)
7. Membangun **payload JSON** dan mengirimnya ke IP Bob via socket TCP

### Sisi Bob (Penerima)
1. Menerima payload dari IP Alice
2. Mendekripsi AES key menggunakan **private key Bob** (RSA-OAEP)
3. Mendekripsi ciphertext menggunakan **AES key** (AES-256-CBC)
4. Menghitung ulang **SHA-256 hash** dan membandingkan dengan hash di payload
5. Memverifikasi **digital signature** menggunakan **public key Alice** (RSA-PSS)
6. Menyimpulkan validitas pesan

---

## Format Payload

```json
{
  "source_ip": "127.0.0.2",
  "destination_ip": "127.0.0.1",
  "ciphertext": "<base64>",
  "iv": "<base64>",
  "encrypted_key": "<base64>",
  "hash": "<base64>",
  "signature": "<base64>",
  "hash_algorithm": "SHA-256",
  "symmetric_algorithm": "AES-256-CBC",
  "asymmetric_algorithm": "RSA-2048-OAEP",
  "signature_algorithm": "RSA-PSS"
}
```
---

## Algoritma yang Digunakan

| Komponen | Algoritma | Alasan |
|---|---|---|
| Symmetric Encryption | AES-256-CBC | Standar industri, cepat, aman |
| Asymmetric Encryption | RSA-2048-OAEP | Standar untuk key exchange |
| Hash | SHA-256 | Standar, collision-resistant |
| Digital Signature | RSA-PSS | Lebih aman dari PKCS#1 v1.5 |
| Library | `cryptography` (PyCA) | Mature, well-maintained |

---

## Topologi

```
Alice (127.0.0.2) ──── TCP Socket ────► Bob (127.0.0.1:9999)
```

Untuk dua perangkat berbeda, ganti IP sesuai jaringan lokal.

