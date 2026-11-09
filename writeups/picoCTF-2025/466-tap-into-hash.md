# 466 - Tap into Hash (Reverse Engineering, picoCTF 2025, Medium)

## Challenge Metadata
- ID: 466 | Event: picoCTF 2025
- Category: Reverse Engineering | Difficulty: Medium (2)
- Author: Taylor McCampbell
- Points: 200 Pts (CyLab) / 50 Pts (picoCTF)
- Flag: `academy{block_3SRhViRbT1qcX_XUjM0r49cH_qCzmJZzBK_3a847c57}`
- Standard Reference: NIST SP 800-115 §4.2, FIPS 180-4, RFC 8018, RFC 5652, CWE-312, CWE-321, CWE-327

## Problem Statement & Scope
Tantangan menyediakan berkas sumber Python `block_chain.py` dan berkas keluaran artefak terenkripsi `enc_flag`.
Deskripsi tantangan:
*"Can you make sense of this source code file and write a function that will decode the given encrypted file content? Find the encrypted file enc_flag and source file block_chain.py."*
Petunjuk:
- Hint 1: `Do you know what blockchains are? If so, you know that hashing is used in blockchains.`
- Hint 2: `Download the encrypted flag file and the source file and reverse engineer the source file.`

Objektif pengujian (NIST SP 800-115 Section 4.2 Cryptographic Security Testing & Software Flaw Analysis):
Menganalisis arsitektur internal simulasi blockchain, mengidentifikasi kelemahan mendasar dalam skema pembangkitan kunci dan mode enkripsi, merekonstruksi algoritma pembalik (*decryption oracle*), dan memulihkan string bendera rahasia yang disisipkan di dalam rantai blok terenkripsi.

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Cleartext Key Storage & Distribution Disclose (CWE-312 / CWE-321):**
   Program `block_chain.py` membangkitkan kunci acak 32-byte (`key = bytes.fromhex(random_string)`), namun mencetak representasi byte mentah kunci tersebut secara langsung ke `stdout` bersamaan dengan ciphertext:
   ```python
   print("Key:", key)
   ...
   print("Encrypted Blockchain:", encrypted_blockchain)
   ```
   Keluaran ini disimpan utuh ke dalam berkas `enc_flag`. Akibatnya, material kunci kriptografi terdistribusi secara terbuka bersama dengan ciphertext (*dual artifact disclosure*), meniadakan seluruh premis kerahasiaan (*confidentiality*).
2. **Kelemahan Skema Enkripsi Keystream Berulang (CWE-327):**
   Fungsi `encrypt()` dalam `block_chain.py` mengimplementasikan logika enkripsi blok berulang tanpa initialization vector (IV) maupun mode operasi aman (seperti AES-GCM / CBC):
   ```python
   key_hash = hashlib.sha256(key).digest()  # 32 bytes
   ...
   for i in range(0, len(plaintext), block_size):
       block = plaintext[i:i + block_size]
       cipher_block = xor_bytes(block, key_hash)
       ciphertext += cipher_block
   ```
   Fungsi pembantu `xor_bytes(a, b)` didefinisikan sebagai:
   ```python
   def xor_bytes(a, b):
       return bytes(x ^ y for x, y in zip(a, b))
   ```
   Karena ukuran blok (`block_size`) adalah 16 byte, `zip(block, key_hash)` secara inheren hanya memproses 16 byte pertama dari `key_hash` (`key_hash[:16]`). Seluruh blok sepanjang berkas di-XOR dengan 16 byte statis yang identik. Operasi XOR bersifat involutif ($C \oplus K = P \iff P \oplus K = C$), sehingga proses dekripsi dapat dilakukan dengan operasi yang identik.
3. **Penyisipan Token & Padding PKCS #7 (RFC 5652):**
   Plaintext dibentuk dari rantai blok yang dihubungkan dengan karakter minus (`-`), disisipi token flag di titik tengah (`midpoint`), lalu ditambahkan padding PKCS #7 agar kelipatan 16 byte. Setelah operasi XOR dibalik, padding PKCS #7 dapat dilepaskan dengan memeriksa byte terakhir (`pad_len = pt[-1]`).

## Rekonstruksi Eksploitasi Step-by-Step
1. Tahap 1 — Analisis Artefak `enc_flag`:
   Berkas `enc_flag` berisi dua baris terstruktur:
   - `Key: b'\xdar\xbd%x\x05\x979\xca\xb9\xa0\xb3\x92\xa6W\x06\xa0\xa7\xc0\xb8\xb7\x02\xa3\x93\x80\xa1>\xba\xc9\x0e^('`
   - `Encrypted Blockchain: b'\xe9p\x9a\x1f...'` (total 384 bytes, 24 blok @ 16 byte).
2. Tahap 2 — Rekonstruksi Keystream:
   Menghitung SHA-256 dari kunci mentah dan mengambil 16 byte awal:
   ```python
   k16 = hashlib.sha256(key).digest()[:16]
   ```
3. Tahap 3 — Inversi XOR Blok & Depadding PKCS #7:
   Melakukan iterasi blok per 16 byte pada ciphertext, melakukan XOR dengan `k16`, menggabungkan seluruh blok, dan melepaskan padding:
   ```python
   pt = b"".join(bytes(c ^ k for c, k in zip(enc[i:i+16], k16)) for i in range(0, len(enc), 16))
   pad_len = pt[-1]
   cleartext = pt[:-pad_len].decode('utf-8')
   ```
4. Tahap 4 — Ekstraksi Flag:
   String terdekripsi memperlihatkan struktur blockchain:
   `000632cb...-00d927ab...-0097f5ac...academy{block_3SRhViRbT1qcX_XUjM0r49cH_qCzmJZzBK_3a847c57}00e19...`
   Ekstraksi regex menghasilkan token flag utuh: `academy{block_3SRhViRbT1qcX_XUjM0r49cH_qCzmJZzBK_3a847c57}`.
5. Tahap 5 — Validasi REST API Platform:
   Mengirimkan flag melalui `POST /api/submissions/` dengan payload `{"challenge": 466, "flag": "..."}`.
   Platform mengembalikan status `HTTP 201 Created` (`correct: true`).

## Flag & Bukti Verifikasi
- Flag Resmi: `academy{block_3SRhViRbT1qcX_XUjM0r49cH_qCzmJZzBK_3a847c57}`
- Bukti Validasi: REST API CyLab `POST /api/submissions/` mengembalikan `HTTP 201 Created` (`correct: true`, user 1072359).
- Reproduktifitas Solver: Terverifikasi 100% via `scripts/solve_466_tap_into_hash.py` (eksekusi instan deterministik).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pemisahan Kunci Kriptografi & Data (Separation of Keys & Data):** Jangan pernah mencetak atau mendistribusikan material kunci kriptografi di kanal atau berkas yang sama dengan data terenkripsi. Terapkan arsitektur Key Management Service (KMS) atau Hardware Security Module (HSM).
- **Penggunaan Cipher Standar Industri (FIPS-Approved Ciphers):** Jangan mengarang skema enkripsi buatan sendiri (*Never Roll Your Own Crypto*). Gunakan cipher simetris teruji seperti AES-256-GCM atau ChaCha20-Poly1305 yang menyediakan kerahasiaan sekaligus integritas autentikasi (AEAD).
- **Penanganan IV/Nonce yang Benar:** Jika menggunakan mode stream cipher atau CBC/CTR, wajib gunakan Nonce/IV acak kriptografis yang unik untuk setiap sesi enkripsi, mencegah serangan keystream reuse (*two-time pad*).
- **Pembersihan Log & Output Sanitization:** Pastikan pipeline aplikasi memfilter dan menyensor variabel sensitif sebelum dicetak ke log aplikasi atau terminal pengguna untuk memitigasi CWE-312.
