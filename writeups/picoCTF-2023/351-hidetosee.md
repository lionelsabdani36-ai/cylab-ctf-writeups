# Writeup: HideToSee (Challenge ID: 351)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Steghide Extraction & Classical Atbash Cipher (CWE-327 / CWE-319)
- **Difficulty:** Medium (diff=2)
- **Event:** picoCTF 2023
- **Points:** 100
- **Author:** Sunday Jacob Nwanya
- **Flag Resmi:** `academy{atbash_crack_6167bd8e}`
- **Standar Audit:** NIST SP 800-115 § 4.2 (Vulnerability Analysis) & § 4.3 (Verification)

---

## Problem Statement & Scope

Tantangan `HideToSee` menyajikan sebuah berkas citra JPEG bernama `atbash.jpg`. Skenario investigasi menantang peserta untuk menemukan saluran data tersembunyi yang disisipkan ke dalam media grafis, mengekstrak pesan terenkripsi, serta memecahkan skema sandi kriptografi klasik yang digunakan untuk merekonstruksi token bendera resmi CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Steganografi Berbasis Koefisien Frekuensi DCT (Discrete Cosine Transform):**
   Utilitas steganografi `steghide` menyematkan muatan biner (*payload*) ke dalam koefisien domain frekuensi DCT citra JPEG. Algoritma ini menggantikan bit-bit frekuensi rendah dan menengah tanpa menimbulkan degradasi visual yang tampak pada mata manusia.
   
   Kelemahan operasional mendasar muncul ketika proses penyematan tidak diamankan dengan frasa sandi kriptografis yang kuat, atau dibiarkan menggunakan kata sandi kosong (*null passphrase* `""`). Analis keamanan dapat mengekstrak data tersembunyi secara instan tanpa memerlukan serangan kamus atau brute force.

2. **Kelemahan Sandi Substitusi Monoalfabetik Atbash (CWE-327):**
   Artefak teks yang diekstrak dari citra menghasilkan teks tersandi:
   `zxzwvnb{zgyzhs_xizxp_6167yw8v}`.
   
   Nama berkas `atbash.jpg` secara langsung merujuk pada sandi substitusi Atbash, yaitu sandi monoalfabetik kuno yang membalikkan urutan 26 karakter alfabet secara simetris:
   $$c \equiv (25 - p) \pmod{26}$$
   Karakter $a \leftrightarrow z$, $b \leftrightarrow y$, $c \leftrightarrow x$, dan seterusnya. Karena pemetaan ini bersifat deterministik satu-ke-satu tanpa konfusi Shannon maupun kunci rahasia dinamis, teks terbuka dapat dipulihkan secara instan melalui penerapan transformasi pembalikan yang sama.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi dan Ekstraksi Steghide:**
   Ekstrak berkas rahasia dari artefak `atbash.jpg` menggunakan kata sandi kosong:
   ```bash
   steghide extract -sf atbash.jpg -p "" -xf -
   # Output: zxzwvnb{zgyzhs_xizxp_6167yw8v}
   ```

2. **Analisis Pemetaan Teks Sandi (Atbash Mapping):**
   - Prefiks `zxzwvnb` terdiri atas 7 karakter:
     $z \rightarrow a$, $x \rightarrow c$, $z \rightarrow a$, $w \rightarrow d$, $v \rightarrow e$, $n \rightarrow m$, $b \rightarrow y$ (membentuk kata `academy`).
   - Bagian tengah `zgyzhs` dipetakan menjadi:
     $z \rightarrow a$, $g \rightarrow t$, $y \rightarrow b$, $z \rightarrow a$, $h \rightarrow s$, $s \rightarrow h$ (membentuk kata `atbash`).
   - Bagian kata kerja `xizxp`:
     $x \rightarrow c$, $i \rightarrow r$, $z \rightarrow a$, $x \rightarrow c$, $p \rightarrow k$ (membentuk kata `crack`).
   - Bagian leetspeak dan angka `6167yw8v`:
     Digit numerik tetap dipertahankan, sedangkan karakter alfabet dibalik:
     $y \rightarrow b$, $w \rightarrow d$, $v \rightarrow e$ (membentuk string `6167bd8e`).

3. **Rekonstruksi Token Final:**
   Penggabungan seluruh segmen menghasilkan token valid:
   `academy{atbash_crack_6167bd8e}`.

4. **Verifikasi Token Live REST API:**
   Kirim token ke endpoint penyerahan resmi:
   ```bash
   curl -X POST https://learn.cylabacademy.org/api/submissions/ \
     -H "Content-Type: application/json" \
     -H "X-CSRFToken: <CSRF_TOKEN>" \
     -H "Cookie: sessionid=<SESSION_ID>; csrftoken=<CSRF_TOKEN>" \
     -d '{"challenge": 351, "flag": "academy{atbash_crack_6167bd8e}"}'
   ```
   Platform mengembalikan status respons HTTP 201 Created dengan atribut `correct: true`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{atbash_crack_6167bd8e}`
- **Status Submisi REST API:** HTTP 201 Created (`correct: true`, `historical: false`).
- **Skrip Reproduktif:** `scripts/solve_351_hidetosee.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Relevansi Silabus LKS Cyber Security:**
   - Modul Cryptography: Pemahaman prinsip dasar analisis kriptografi klasik vs modern, teknik analisis frekuensi substitusi monoalfabetik, dan kelemahan arsitektur kriptosistem tanpa kunci rahasia dinamis.
   - Modul Steganography & Incident Response: Prosedur ekstraksi muatan tersembunyi pada artefak JPEG dan identifikasi vektor saluran terselubung (*covert channels*).

2. **Mitigasi Defensif (Hardening & Media Sanitization):**
   - **Penerapan Standar Enkripsi Modern:** Dilarang keras mengandalkan keamanan berbasis pengaburan (*security through obscurity*) atau sandi substitusi statis. Terapkan algoritma kriptografi terotentikasi standar industri (seperti AES-256-GCM atau ChaCha20-Poly1305).
   - **Pemrosesan Ulang Media Publik:** Seluruh aset media yang diunggah atau didistribusikan ke ranah publik wajib melewati tahap rekompresi dan requantization koefisien DCT untuk menghancurkan data steganografis yang mungkin disusupkan oleh penyerang.
