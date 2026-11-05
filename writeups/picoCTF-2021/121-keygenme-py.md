# Writeup: keygenme-py (Challenge ID: 121)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Python AST Key Generation & Hash Inversion
- **Difficulty:** Medium (diff=2)
- **Author:** syreal
- **Event:** picoCTF 2021
- **Points:** 30
- **Flag:** `academy{1n_7h3_kk3y_of_9edf443b}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan reverse engineering terhadap kode sumber aplikasi Python trialware:
> *"keygenme-trial.py"*
> Artefak: `keygenme-trial.py`
> Deskripsi: Program trial interaktif berbasis menu yang menyediakan fitur simulasi sistem bintang (Arcane Calculator). Pengguna diminta memasukkan kunci lisensi penuh (*full version license key*) untuk membuka fitur terkunci.

Peserta diberikan skrip Python `keygenme-trial.py`. Karena format kode didistribusikan dalam teks skrip terbuka (*interpreted scripting language*), seluruh alur verifikasi kunci lisensi dapat dibaca dan didekonstruksi secara statis tanpa memerlukan debugger biner dinamis.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Validasi Lisensi Klien (Client-Side Licensing Flaw):**
   - Dalam rekayasa perangkat lunak berstandar NIST SP 800-115 (*Section 5.3: Cryptographic & Binary Evaluation*), logika validasi hak akses (*entitlement verification*) yang dieksekusi sepihak pada mesin klien (*client-side*) tanpa validasi kriptografis asimetris (seperti digital signature Ed25519 atau RSA pada lisensi) rentan terhadap *licensing bypass* dan *keygen creation*.
   - Masalah ini terdaftar pada **CWE-327** (*Use of a Broken or Risky Cryptographic Algorithm*) dan **CWE-602** (*Client-Side Enforcement of Server-Side Security*).

2. **Dekomposisi Logika Pembuatan Kunci (*Key Generation Logic*):**
   - Pemeriksaan kode pada fungsi `check_key(key, username_trial)` mengungkapkan bahwa kunci lisensi disusun dari tiga komponen:
     $$K = \text{key\_part\_static1\_trial} \parallel \text{key\_part\_dynamic1\_trial} \parallel \text{key\_part\_static2\_trial}$$
   - **Komponen Statis:**
     - Prefix: `academy{1n_7h3_kk3y_of_` (panjang 23 karakter)
     - Suffix: `}` (panjang 1 karakter)
   - **Komponen Dinamis:**
     - Ditentukan oleh byte username pengguna: `bUsername_trial = b"MILLER"`
     - Komponen dinamis berpanjang tepat 8 karakter hex, di mana setiap karakter dicocokkan dengan digest SHA-256 dari `bUsername_trial` pada indeks tertentu:
       $$\text{Indices} = [4, 5, 3, 6, 2, 7, 1, 8]$$
     - Urutan pencocokan:
       - `key[23] == sha256(b"MILLER")[4]`
       - `key[24] == sha256(b"MILLER")[5]`
       - `key[25] == sha256(b"MILLER")[3]`
       - `key[26] == sha256(b"MILLER")[6]`
       - `key[27] == sha256(b"MILLER")[2]`
       - `key[28] == sha256(b"MILLER")[7]`
       - `key[29] == sha256(b"MILLER")[1]`
       - `key[30] == sha256(b"MILLER")[8]`

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Artefak Skrip:**
   ```bash
   wget https://challenge-files.cylabacademy.net/library/2ae1afa675115ff8bf18b4d6edd0a7230c6231a75c3f5d33562372ee88be12cb/keygenme-trial.py
   ```

2. **Analisis Fungsi `check_key` Menggunakan Grep / Cat:**
   Membaca struktur fungsi pengecekan kunci:
   ```python
   def check_key(key, username_trial):
       ...
       for c in key_part_static1_trial:
           if key[i] != c: return False
           i += 1
       if key[i] != hashlib.sha256(username_trial).hexdigest()[4]: return False
       i += 1
       # ... berlanjut hingga indeks 5, 3, 6, 2, 7, 1, 8
   ```

3. **Rekonstruksi Keygen Dinamis:**
   Menghitung SHA-256 dari `b"MILLER"`:
   ```bash
   python3 -c '
   import hashlib
   h = hashlib.sha256(b"MILLER").hexdigest()
   print("Digest:", h)
   indices = [4, 5, 3, 6, 2, 7, 1, 8]
   dynamic = "".join(h[idx] for idx in indices)
   print("Dynamic part:", dynamic)
   print("Flag:", f"academy{{1n_7h3_kk3y_of_{dynamic}}}")
   '
   ```
   Output:
   - SHA-256: `734d9ef4ba0977dafd63c59bd4ceb0413f7559edf6347c8405f8feabdecb01d0`
   - Indeks `[4, 5, 3, 6, 2, 7, 1, 8]`:
     - Posisi 4: `9`
     - Posisi 5: `e`
     - Posisi 3: `d`
     - Posisi 6: `f`
     - Posisi 2: `4`
     - Posisi 7: `4`
     - Posisi 1: `3`
     - Posisi 8: `b`
   - Bagian dinamis: `9edf443b`

4. **Sintesis Flag Lengkap:**
   $$\text{Flag} = \text{academy\{1n\_7h3\_kk3y\_of\_9edf443b\}}$$

---

## Flag & Verifikasi

- **Flag:** `academy{1n_7h3_kk3y_of_9edf443b}`
- **Verifikasi API CyLab:**
  Submisi HTTP POST langsung ke `/api/submissions/` dengan CSRF token valid:
  ```json
  {"challenge": 121, "flag": "academy{1n_7h3_kk3y_of_9edf443b}"}
  ```
  Status respons: `HTTP 201 Created` dengan `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Penerapan Tanda Tangan Digital pada Sistem Lisensi (Asymmetric Verification):**
   - Jangan pernah memvalidasi lisensi hanya dengan mencocokkan digest hash sepihak terhadap username pada kode klien.
   - Gunakan skema kriptografi asimetris (Public-Key Cryptography):
     1. Pihak penerbit menandatangani payload lisensi $(Username \parallel Expiry)$ menggunakan *Private Key* rahasia milik vendor via skema RSA-PSS atau Ed25519.
     2. Aplikasi klien hanya menyimpan *Public Key* vendor untuk memverifikasi validitas tanda tangan (`crypto.verify`). Penyerang tidak dapat memalsukan lisensi tanpa mengetahui private key vendor.
2. **Obfuskasi & Integritas Biner (Anti-Tampering):**
   - Untuk software native, terapkan teknik *code integrity check*, anti-debugging, dan compiler-level control flow flattening (OLLVM) guna menghambat dekompilasi langsung.
