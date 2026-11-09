# Writeup: Guess My Cheese (Part 2) (Challenge ID: 474)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Low-Entropy Salt Exhaustion & SHA-256 Precomputed Rainbow Table Analysis
- **Difficulty:** Medium (2)
- **Points:** 300
- **Author:** aditin
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{cHeEsYdaa8c59e}`
- **Flag Platform Asli:** `picoCTF{cHeEsYdaa8c59e}`
- **Flag Komunitas:** `CTF{cHeEsYdaa8c59e}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Cryptographic Assessment & Credential Auditing), FIPS 180-4 (Secure Hash Standard), RFC 6234 (US Secure Hash Algorithms), CWE-328 (Use of Weak Hash / Broken Cryptographic Scheme), CWE-330 (Use of Insufficiently Random Values), & CWE-760 (Use of a One-Way Hash with a Predictable Salt).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Applied Cryptography & Password Security Analysis*:
- **Skenario Tantangan:** Setelah skema substitusi Affine pada bagian pertama berhasil dipecahkan, pengembang sistem memperkuat mekanisme verifikasi dengan mengimplementasikan fungsi hash kriptografis standar industri SHA-256 serta menambahkan garam (*salt*). Peserta diberikan daftar 599 nama keju resmi (`cheese_list.txt`) dan disajikan nilai intisari hash target berukuran 256-bit (64 karakter heksadesimal). Peserta ditantang membalikkan hash untuk menemukan nama keju dan nilai salt yang tepat.
- **Deskripsi Soal:** *"The imposter was able to fool us last time, so we've strengthened our defenses! Here's our list of cheeses. Hints: 1. I heard that *SHA-256* is the best hash function out there!, 2. Remember Squeexy, we enjoy our cheese with exactly *2 nibbles* of *hexadecimal-character salt*!, 3. Ever heard of *rainbow tables*?"*
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis konstruksi masukan hash: penggabungan nama keju huruf kecil (*lowercase*) dengan salt mentah 1-byte (`bytes([salt])`).
  2. Evaluasi entropi salt kriptografis: 2 nibble heksadesimal merepresentasikan 1 byte (8-bit) dengan rentang nilai $0 \le s \le 255$ ($0x00$ hingga $0xff$).
  3. Perhitungan total ruang pencarian kandidat: $N = 599 \text{ keju} \times 256 \text{ salt} = 153.344 \text{ pasangan}$.
  4. Perancangan dan pembuatan tabel prainisialisasi (*rainbow lookup table*) berbasis memori dalam waktu eksekusi kurang dari 150 ms.
  5. Otomasi parsing prompt soket TCP netcat, pencarian instan pada tabel $O(1)$, dan transmisi jawaban interaktif.
  6. Verifikasi token resmi melalui REST API CyLab `POST /api/submissions/` (HTTP Status 201).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Ilusi Proteksi Salt Berentropi Rendah (CWE-330 / CWE-760):**
   Tujuan kriptografis dari penambahan salt adalah memperbesar ruang pencarian secara eksponensial sehingga pembuatan tabel prainisialisasi (*precomputed rainbow table*) menjadi tidak layak secara komputasi (*computationally infeasible*). Standar industri (seperti NIST SP 800-63B) mensyaratkan salt berukuran minimal 128 bit (16 byte), yang menghasilkan $2^{128} \approx 3,4 \times 10^{38}$ kemungkinan nilai per kata sandi.
   Namun pada sistem ini, salt dibatasi hanya 2 nibble (1 byte = 8 bit):
   $$\text{Entropi Salt} = \log_2(256) = 8 \text{ bit}$$
   Ukuran ruang kunci 8-bit merupakan kerentanan fatal yang memungkinkan seluruh kombinasi salt dipetakan secara tuntas (*exhaustive enumeration*) dalam sepersekian detik.

2. **Dekomposisi Konstruksi Digest SHA-256:**
   Proses pembuatan hash oleh server mengikuti algoritma deterministik berikut:
   $$\text{Digest} = \text{SHA256}(\text{lowercase}(\text{cheese}) \parallel \text{bytes}([s]))$$
   di mana:
   - $\text{cheese} \in \{c_1, c_2, \dots, c_{599}\}$ diambil dari `cheese_list.txt`.
   - $s \in [0, 255]$ adalah integer biner 8-bit.
   Karena masukan tidak melibatkan fungsi peregang waktu (*time cost/memory cost parameter*), kalkulasi $153.344$ digest SHA-256 dapat diselesaikan dalam $100\text{--}120$ milidetik menggunakan implementasi standar pustaka C/Python.

3. **Inversi Deterministik Berbasis Tabel Hash:**
   Dengan mengompilasi kamus pemetaan terbalik:
   $$\text{LookupTable}: \text{hex\_digest} \longrightarrow (\text{cheese}, \text{salt\_hex})$$
   pencarian setiap nilai hash yang disajikan server dapat diselesaikan dalam kompleksitas waktu $O(1)$ tanpa perlu melakukan komputasi berulang saat sesi koneksi TCP aktif.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Kamus Kata Sandi / Cheese List:**
   Mengunduh daftar keju resmi dari CDN CyLab Academy:
   ```bash
   curl -s https://challenge-files.cylabacademy.net/library/0511a1f12af19a4da2afb8e1bb046ed7cf57d0f621cc3d706d4013274845d109/cheese_list.txt -o cheese_list.txt
   ```

2. **Kompilasi Tabel Pelangi Lokal (Precomputed Rainbow Table):**
   Membuat pemetaan kamus SHA-256 secara lokal:
   ```python
   import hashlib

   with open("cheese_list.txt", "r") as f:
       cheeses = [line.strip().lower() for line in f if line.strip()]

   rainbow = {}
   for c in cheeses:
       cb = c.encode("utf-8")
       for s in range(256):
           h = hashlib.sha256(cb + bytes([s])).hexdigest()
           rainbow[h] = (c, f"{s:02x}")
   print(f"[+] Total entri tabel pelangi: {len(rainbow)}")
   ```

3. **Interaksi Soket TCP & Pencocokan Hash Target:**
   - Menghubungkan soket ke port container: `nc chatelaine.cylabacademy.net 19360`
   - Server memberikan tantangan: `guess it: 4358a37d7a1c8ff4acc094eff27056fea3b95e45970bdf684823794dcf666cdb`
   - Melakukan lookup pada tabel:
     ```python
     matched_cheese, salt_hex = rainbow["4358a37d7a1c8ff4acc094eff27056fea3b95e45970bdf684823794dcf666cdb"]
     # matched_cheese = "greuilh"
     # salt_hex = "3e"
     ```

4. **Pengiriman Respons ke Server:**
   - Kirim `g` untuk memilih opsi tebak.
   - Kirim `greuilh` sebagai nama keju.
   - Kirim `3e` sebagai nilai salt dalam format 2 karakter hex.
   - Server memverifikasi kecocokan dan mencetak token rahasia:
     ```text
     YUM! MMMMmmmmMMMMmmmMMM!!! Yes...yesssss! That's my cheese!
     Here's the password to the cloning room: academy{cHeEsYdaa8c59e}
     ```

5. **Eksekusi Solver Mandiri:**
   ```bash
   python3 scripts/solve_474_guess_my_cheese_part_2.py chatelaine.cylabacademy.net:19360
   ```
   Output eksekusi:
   ```text
   [+] Invarian tabel pelangi salt 8-bit & SHA-256 terverifikasi matematis (100% roundtrip)
   [*] Menghubungi target netcat: chatelaine.cylabacademy.net:19360...
   [+] Flag berhasil diekstraksi dari soket TCP: academy{cHeEsYdaa8c59e}
   [SUCCESS] Challenge 474 (Guess My Cheese (Part 2)) verified: academy{cHeEsYdaa8c59e}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{cHeEsYdaa8c59e}`
- **Flag Platform Asli:** `picoCTF{cHeEsYdaa8c59e}`
- **Flag Komunitas:** `CTF{cHeEsYdaa8c59e}`
- **Verifikasi Submisi REST API:** POST `/api/submissions/` dengan payload `{"challenge": 474, "flag": "academy{cHeEsYdaa8c59e}"}` menghasilkan status HTTP 201 dengan atribut `correct: true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Penegakan Entropi Minimum pada Parameter Salt (NIST SP 800-63B §5.1.1.2):**
   Ukuran salt tidak boleh ditentukan secara sembarang atau bernilai kecil. Standar NIST mensyaratkan:
   - Panjang salt minimal **128 bit (16 byte)** atau **256 bit (32 byte)**.
   - Salt harus dihasilkan menggunakan generator acak kriptografis sejati (*Cryptographically Secure Pseudorandom Number Generator* / CSPRNG) seperti `secrets.token_bytes(32)`.
   - Salt harus unik untuk setiap kredensial dan disimpan bersama nilai hash.

2. **Penggunaan Algoritma Key Derivation Function (KDF) yang Tahan GPU:**
   Meskipun menggunakan salt yang panjang, fungsi hash cepat (*fast hash*) seperti SHA-256 masih rentan terhadap serangan penelusuran kamus terdistribusi menggunakan akselerasi GPU. Sistem otentikasi wajib menggunakan fungsi peregang kunci (*memory-hard / compute-hard KDF*):
   - **Argon2id (RFC 9106):** Konfigurasi memori minimal 64 MB, 3 iterasi, 4 thread.
   - **scrypt (RFC 7914):** Parameter $N=32768, r=8, p=1$.
   - **PBKDF2-HMAC-SHA256 (RFC 8018):** Minimal 600.000 iterasi.

3. **Perlindungan Terhadap Enumerasi Kamus Terbatas:**
   Ketika ruang masukan teks asli diketahui terbatas (seperti daftar nama keju, nomor identitas kependudukan, atau nomor telepon), enkripsi kunci simetris terautentikasi (misalnya AES-256-GCM) dengan kunci server rahasia yang disimpan di Hardware Security Module (HSM) atau Key Vault harus digunakan sebagai pengganti fungsi hash publik.
