# Writeup: Timestamped Secrets (Challenge ID: 722)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Low-Entropy KDF & Timestamp Brute-Force
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** picoCTF
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{sa3S_sEc9t_3b464909}`
- **Flag Komunitas:** `CTF{sa3S_sEc9t_3b464909}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), CWE-330 (Use of Insufficiently Random Values), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-326 (Inadequate Encryption Strength), & NIST SP 800-38A (Recommendation for Block Cipher Modes of Operation).

---

## Problem Statement & Scope

Pada modul bimbingan teknis `Timestamped Secrets`, peserta diuji dalam audit implementasi kriptografi simetris dan analisis kerentanan penurunan kunci (*Key Derivation Function / KDF*):
- Skenario lingkungan: Disediakan berkas terenkripsi `message.txt` dan skrip contoh implementasi enkripsi `encryption.py`.
- Pernyataan tantangan:
  > *"Someone encrypted a message using AES in ECB mode but they weren’t very careful with their key. Turns out it’s derived from something as simple as the current time! Can you uncover the key and decrypt the flag?"*
- Artefak yang disediakan:
  1. `message.txt`:
     ```text
     Hint: The encryption was done around 1790147519 UTC
     Ciphertext (hex): 44e98ac8b821d1b561b49f38c114c89405c1895b1f9425b6adc8e0911b68731a
     ```
  2. `encryption.py`: Implementasi AES-128 dalam mode Electronic Codebook (ECB) di mana kunci diturunkan dari `sha256(str(timestamp).encode()).digest()[:16]`.
- Sasaran pengujian: Mengevaluasi keruntuhan entropi kunci (*key-space collapse*), merekonstruksi brute-force pencarian kunci pada jendela waktu sempit di sekitar hint timestamp, memulihkan plaintext ber-padding PKCS#7, serta memvalidasi token resmi pada endpoint REST API CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Keruntuhan Ruang Kunci / Low-Entropy KDF (CWE-330 & CWE-326):**
   Algoritma AES-128 secara teoritis memiliki ruang kunci sebesar $2^{128} \approx 3.4 \times 10^{38}$ kemungkinan kunci, yang menjamin keamanan komputasi dari serangan brute-force. Namun, pada implementasi `encryption.py`:
   ```python
   timestamp = int(time.time())
   key = sha256(str(timestamp).encode()).digest()[:16]
   ```
   Kunci tidak dibangkitkan dari generator acak terstandar (*Cryptographically Secure Pseudo-Random Number Generator / CSPRNG*), melainkan diturunkan dari bilangan bulat waktu POSIX epoch (`int(time.time())`).
   Dengan adanya petunjuk waktu enkripsi di sekitar `1790147519 UTC`, ruang pencarian penyerang (*search space*) menyusut secara drastis:
   - Jendela ±60 detik: hanya 121 kandidat kunci.
   - Jendela ±1 jam: hanya 7.201 kandidat kunci.
   - Jendela ±24 jam: hanya 172.801 kandidat kunci.
   Pada prosesor modern, 172.801 iterasi SHA-256 dan dekripsi AES-128 dapat diselesaikan dalam waktu kurang dari 0.5 detik pada satu core CPU.

2. **Kelemahan Mode Electronic Codebook / ECB (CWE-327):**
   Penggunaan mode ECB (`AES.MODE_ECB`) menghilangkan vektor inisialisasi (*Initialization Vector / IV*). Mode ini bersifat deterministik murni: blok teks jelas (*plaintext*) yang identik akan selalu menghasilkan blok teks sandi (*ciphertext*) yang identik pada kunci yang sama. Selain itu, ECB tidak menyediakan integritas data (*integrity*) maupun autentikasi pesan (*authentication*), melanggar rekomendasi NIST SP 800-38A.

3. **Insecure Password/Key Derivation vs KDF Standar (RFC 5869 / HKDF):**
   Memotong digest hash kriptografis (`sha256(...)[:16]`) dari representasi string bilangan bulat pendek tidak memenuhi kaidah *entropy extraction* atau *key expansion*. Tanpa adanya cryptographic salt dan fungsi perlambatan berbasis memori/komputasi (seperti PBKDF2, Argon2, atau scrypt), setiap tebakan timestamp dapat diuji secara instan.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Ekstraksi Parameter dari Berkas Lab:**
   Membaca berkas `message.txt` dan mengekstrak nilai basis waktu (`ts0 = 1790147519`) serta string ciphertext heksadesimal 32-byte (64 karakter hex):
   `ct = bytes.fromhex("44e98ac8b821d1b561b49f38c114c89405c1895b1f9425b6adc8e0911b68731a")`.

2. **Penyusunan Algoritma Brute-Force Jendela Waktu:**
   Mengiterasi nilai offset $\Delta t$ di sekitar `ts0`:
   ```python
   for offset in range(-1000, 1001):
       ts_cand = ts0 + offset
       cand_key = sha256(str(ts_cand).encode("utf-8")).digest()[:16]
       cipher = AES.new(cand_key, AES.MODE_ECB)
       try:
           decrypted = cipher.decrypt(ct)
           plaintext = unpad(decrypted, AES.block_size)
           if b"academy{" in plaintext:
               print(f"[+] Key found at timestamp: {ts_cand}")
               return plaintext.decode()
       except ValueError:
           # Padding PKCS#7 tidak valid, lanjutkan iterasi
           continue
   ```

3. **Eksekusi Dekripsi & Pemulihan Flag:**
   Pada iterasi offset $\Delta t = 0$ (`ts = 1790147519`), kunci kandidat menghasilkan padding PKCS#7 yang valid dan membuka string teks:
   `academy{sa3S_sEc9t_3b464909}`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{sa3S_sEc9t_3b464909}`
- **Flag Komunitas:** `CTF{sa3S_sEc9t_3b464909}`
- **Log Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 722,
    "flag": "academy{sa3S_sEc9t_3b464909}",
    "correct": true,
    "historical": false
  }
  ```
  Status respons HTTP: `201 Created` mengonfirmasi token valid dan tercatat secara definitif.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Rekomendasi Remediasi & Hardening (Defensive Perspective):**
   - **Pembangkitan Kunci Aman Kriptografis (CSPRNG):** Kunci enkripsi wajib dibangkitkan menggunakan generator bilangan acak ber-entropi tinggi dari kernel OS (seperti modul `secrets` pada Python atau fungsi `getrandom(2)` pada POSIX):
     ```python
     import secrets
     key = secrets.token_bytes(16)  # 128-bit full entropy
     ```
   - **Penggunaan Mode Terautentikasi (AEAD):** Gantikan mode ECB usang dengan Galois/Counter Mode (AES-GCM) yang menyertakan IV unik per sesi dan autentikasi integritas (*MAC tag*):
     ```python
     cipher = AES.new(key, AES.MODE_GCM)
     ciphertext, tag = cipher.encrypt_and_digest(plaintext)
     ```
   - **Key Derivation yang Tepat (HKDF):** Bila kunci memang harus diturunkan dari sumber data eksternal, gunakan RFC 5869 HKDF atau Argon2id yang menyertakan cryptographic salt acak serta konfigurasi *work factor* yang memadai.

2. **Relevansi Modul LKS Cyber Security:**
   - **Cryptographic Audit:** Kemampuan menganalisis alur KDF dan mengidentifikasi reduksi ruang kunci adalah kompetensi inti dalam penilaian kepatuhan keamanan perangkat lunak (*Secure Coding & Crypto Review*).
   - **Forensic Incident Decryption:** Dalam investigasi insiden (*digital forensics*), artefak malware ransomware atau file terenkripsi seringkali menggunakan timestamp log sistem untuk seed pembangkitan kunci; analis forensik memanfaatkan prinsip ini untuk memulihkan data korban tanpa membayar tebusan.
