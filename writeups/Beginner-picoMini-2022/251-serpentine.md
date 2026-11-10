# Writeup: Serpentine (Challenge ID: 251)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Python Execution & Static Source Reversing
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** Beginner picoMini 2022
- **Points:** 50
- **Flag:** `academy{7h3_r04d_l355_7r4v3l3d_825b10ae}`

---

## Problem Statement & Scope

Diberikan sebuah skrip Python interaktif `serpentine.py` yang dapat diunduh melalui repositori berkas CyLab Security Academy:
`https://challenge-files.cylabacademy.net/library/6f4ff467e583437bc55c9d44497b3c0751e233197567e46d19e87f2887bba4e3/serpentine.py`

Skrip menyediakan menu CLI interaktif berbasis loop konsol:
- Pilihan `a`: Mencetak kata-kata penyemangat acak (`print_encouragement()`).
- Pilihan `b`: Opsi yang secara deskriptif dimaksudkan untuk mencetak bendera (`Print flag`). Namun, saat dieksekusi, program hanya mencetak pesan pengecoh:
  `Oops! I must have misplaced the print_flag function! Check my source code!`
- Pilihan `c`: Keluar dari program (`sys.exit(0)`).

Peserta ditantang untuk menginspeksi kode sumber skrip, memahami aliran kendali eksekusi (*control flow*), dan memulihkan teks terang bendera yang terlindungi oleh transformasi XOR sederhana.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Dead Code & Logic Branch Misdirection (CWE-670 / NIST SP 800-115 § 4.2):**
   - Panduan pengujian penetrasi teknis NIST SP 800-115 § 4.2 (*Source Code Review & Static Analysis*) menggarisbawahi bahwa logika kontrol alur (*control flow*) aplikasi yang tidak konsisten sering kali menyembunyikan fungsi sensitif yang tidak pernah dijangkau oleh alur normal (*dead code / unreachable routines*).
   - Pada `serpentine.py`, fungsi `print_flag()` telah didefinisikan secara lengkap di awal skrip:
     ```python
     def print_flag():
         flag = str_xor(flag_enc, 'enkidu')
         print(flag)
     ```
   - Namun, percabangan logika `elif choice == 'b':` sengaja tidak memanggil fungsi `print_flag()`.

2. **Penyematan Rahasia Sisi Klien & Obfuskasi XOR Lemah (CWE-798 / CWE-327):**
   - Kredensial bendera disematkan secara langsung di sisi klien (*hardcoded client-side secret*) dalam bentuk array karakter biner `flag_enc` sepanjang 40 bita:
     ```python
     flag_enc = chr(0x04) + chr(0x0d) + chr(0x0a) + ... + chr(0x14)
     ```
   - Kunci enkripsi simetris juga disematkan secara terbuka berupa string statis `"enkidu"`.
   - Operasi `str_xor` menggunakan metode repeating-key stream XOR sederhana tanpa *diffusion*, *confusion*, maupun *message integrity check* (HMAC).

3. **Inversi Dekripsi Deterministik:**
   - Karena operasi XOR bersifat involutif ($A \oplus B \oplus B = A$), mendekripsi ciphertext identik dengan mengenkripsi kembali teks terang dengan kunci yang sama.
   - Tanpa perlu menjalankan loop menu interaktif, memanggil `str_xor(flag_enc, 'enkidu')` secara langsung di Python menghasilkan token resmi secara deterministik.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh artefak skrip dari pustaka berkas CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/6f4ff467e583437bc55c9d44497b3c0751e233197567e46d19e87f2887bba4e3/serpentine.py
   ```
2. Lakukan inspeksi statis pada kode sumber menggunakan editor atau CLI:
   ```bash
   head -n 25 serpentine.py
   ```
   Ditemukan fungsi `str_xor(secret, key)`, variabel `flag_enc`, dan fungsi `print_flag()`.
3. Telusuri percabangan menu utama pada fungsi `main()`:
   ```python
   elif choice == 'b':
       print('\nOops! I must have misplaced the print_flag function! Check my source code!\n\n')
   ```
   Percabangan ini membuktikan bahwa fungsi `print_flag()` sengaja diabaikan.
4. Lakukan patch langsung pada skrip atau panggil fungsinya melalui one-liner Python:
   ```bash
   python3 -c "import serpentine; serpentine.print_flag()"
   ```
   Output:
   ```text
   academy{7h3_r04d_l355_7r4v3l3d_825b10ae}
   ```
5. Eksekusi skrip solver mandiri `scripts/solve_251_serpentine.py`:
   ```bash
   python3 scripts/solve_251_serpentine.py
   ```
   Output mengonfirmasi token valid:
   `[+] Recovered Flag: academy{7h3_r04d_l355_7r4v3l3d_825b10ae}`

---

## Flag & Verifikasi

- **Flag:** `academy{7h3_r04d_l355_7r4v3l3d_825b10ae}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status verifikasi valid:
  ```json
  {"challenge": 251, "flag": "academy{7h3_r04d_l355_7r4v3l3d_825b10ae}", "correct": true}
  ```
- **Matriks Pengujian Wrapper:**
  - `academy{7h3_r04d_l355_7r4v3l3d_825b10ae}`: **HTTP 201 Created (`correct: true`)**
  - `picoCTF{7h3_r04d_l355_7r4v3l3d_825b10ae}`: **HTTP 201 Created (`correct: false`)**
  Validator CyLab Academy menerima wrapper native CyLab `academy{...}` dan menolak varian `picoCTF{...}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Kemampuan membaca dan merekonstruksi aliran kendali (*control flow analysis*) pada kode sumber Python dalam modul Reverse Engineering / General Skills.
  - Memahami bahwa pesan kesalahan atau output antarmuka CLI (*misleading prompts*) dapat dirancang sebagai pengalih perhatian (*anti-analysis deception*), sehingga analisis logika kode sumber statis selalu menjadi rujukan utama (*source of truth*).
- **Mitigasi Defensif:**
  - **Pemisahan Kredensial (Separation of Secrets):** Kunci rahasia dan data terproteksi tidak boleh disematkan di dalam berkas skrip yang didistribusikan ke lingkungan klien publik (*zero trust client assumption*).
  - **Server-Side Validation:** Logika otorisasi dan pelepasan token sensitif wajib diisolasi di lingkungan server backend terotentikasi, bukan diserahkan pada percabangan logika lokal di mesin klien.
  - **Kriptografi Terstandarisasi:** Gunakan algoritma enkripsi authenticated modern seperti AES-GCM atau ChaCha20-Poly1305 jika proteksi kerahasiaan data diperlukan di lingkungan produksi.
