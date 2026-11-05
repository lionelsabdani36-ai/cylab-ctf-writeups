# Writeup: Python Wrangling (Challenge ID: 166)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Python Execution & Fernet Symmetric Decryption
- **Difficulty:** Medium (diff=2)
- **Author:** syreal
- **Event:** picoCTF 2021
- **Points:** 10
- **Flag:** `academy{4p0110_1n_7h3_h0us3_d6af8f37}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman eksekusi skrip CLI Python dan penanganan enkripsi/dekripsi simetris:
> *"Python scripts are invoked kind of like programs in the Terminal... Can you run ende.py using password.txt to get flag.txt.en?"*
> Artefak: `ende.py`, `password.txt`, `flag.txt.en`

Peserta diberikan utilitas Python `ende.py`, sebuah berkas kunci/kata sandi `password.txt` berisi string teks 32-karakter, dan sebuah berkas terenkripsi `flag.txt.en`. Peserta diminta mengeksekusi skrip dengan parameter dekripsi yang tepat untuk mengembalikan teks asli bendera.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Format Enkripsi Terotentikasi Fernet (Symmetric Encryption):**
   - Modul `cryptography.fernet` mengimplementasikan enkripsi simetris yang aman (*authenticated symmetric encryption*) menggunakan algoritma AES dalam mode CBC dengan ukuran kunci 128 bit, dipadukan dengan HMAC-SHA256 untuk verifikasi integritas/otentisitas pesan, serta penanda waktu (*timestamp*).
   - Format token Fernet yang dihasilkan dienkode dengan URL-safe base64:
     - Header: 1 bita versi (`0x80`) + 8 bita timestamp.
     - IV: 16 bita initialization vector acak.
     - Ciphertext: kelipatan 16 bita (AES-CBC ter-padding PKCS#7).
     - HMAC: 32 bita tanda tangan otentikasi SHA-256.

2. **Kelemahan Manajemen Kunci / Kredensial Berdampingan (CWE-321):**
   - Dalam studi kasus ini, algoritma enkripsi yang digunakan (Fernet) secara matematis kuat. Namun, kelemahan mendasar terletak pada arsitektur penyimpanan kunci (*key distribution & storage*).
   - Berkas kata sandi (`password.txt`) didistribusikan berdampingan langsung dengan berkas ciphertext (`flag.txt.en`).
   - Logika derivasi kunci pada `ende.py` hanya melakukan operasi *Base64 encoding* terhadap string password tanpa fungsi *key stretching* atau *slow hashing* (seperti PBKDF2/Argon2/bcrypt), sehingga siapapun yang memperoleh berkas kata sandi dapat mendiversifikasi kunci dekripsi secara instan.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Artefak Berkas:**
   Unduh ketiga komponen berkas dari server CDN CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/1f8bb290392a5ab6795ba98cf621ec507bd52be282f62f32e35c43e0d7fc2415/ende.py
   wget https://challenge-files.cylabacademy.net/library/1f8bb290392a5ab6795ba98cf621ec507bd52be282f62f32e35c43e0d7fc2415/password.txt
   wget https://challenge-files.cylabacademy.net/library/1f8bb290392a5ab6795ba98cf621ec507bd52be282f62f32e35c43e0d7fc2415/flag.txt.en
   ```

2. **Analisis Isi Kunci dan Kode Sumber:**
   Periksa isi berkas kata sandi:
   ```bash
   cat password.txt
   # 563e47ddeaf84eca8b2a31201381a898
   ```

3. **Eksekusi Dekripsi melalui CLI:**
   Jalankan `ende.py` dengan flag `-d` untuk mendekripsi berkas `flag.txt.en`, lalu masukkan kata sandi yang telah ditemukan:
   ```bash
   python3 ende.py -d flag.txt.en
   ```
   Prompt meminta:
   ```text
   Please enter the password: 563e47ddeaf84eca8b2a31201381a898
   ```
   Keluaran:
   ```text
   academy{4p0110_1n_7h3_h0us3_d6af8f37}
   ```

4. **Eksekusi Dekripsi Programatik (Otomasi Headless):**
   Proses dekripsi juga dapat dipanggil secara mandiri melalui pustaka Python `cryptography.fernet`:
   ```python
   import base64
   from cryptography.fernet import Fernet

   pw = open("password.txt").read().strip()
   enc = open("flag.txt.en", "rb").read().strip()
   key = base64.b64encode(pw.encode())
   plain = Fernet(key).decrypt(enc)
   print(plain.decode())
   # academy{4p0110_1n_7h3_h0us3_d6af8f37}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{4p0110_1n_7h3_h0us3_d6af8f37}`
- **Verifikasi API Platform:** Validasi token melalui endpoint `POST /api/submissions/` menghasilkan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 166, "flag": "academy{4p0110_1n_7h3_h0us3_d6af8f37}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi Inti LKS Cyber Security:** Peserta LKS Cyber Security dituntut memiliki kefasihan penuh dalam lingkungan baris perintah Linux (CLI) serta scripting Python dasar untuk interaksi utilitas otomatisasi dan parsing kriptografi.
- **Mitigasi Defensif (Manajemen Kunci Kriptografi & Secret Zero):**
  1. *Pemisahan Media Penyimpanan Kunci (Hardware Security Module / KMS):* Kunci dekripsi dan data terenkripsi tidak boleh disimpan di repositori berkas atau direktori yang sama (*separation of duties*). Kunci harus disimpan dalam vault terkelola seperti AWS KMS, HashiCorp Vault, atau modul perangkat keras TPM/HSM.
  2. *Key Derivation Function (KDF) yang Aman:* Jangan pernah membuat kunci simetris secara langsung dari password string biasa hanya dengan Base64. Selalu gunakan algoritma KDF terstandar NIST seperti PBKDF2 (minimal 600.000 iterasi SHA-256) atau Argon2id dengan salt acak yang unik per data.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_166_python_wrangling.py`.
