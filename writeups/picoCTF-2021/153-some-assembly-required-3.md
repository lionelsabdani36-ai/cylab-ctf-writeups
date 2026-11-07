# Writeup: Some Assembly Required 3 (Challenge ID: 153)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / WebAssembly Binary Analysis & Inverted XOR Cipher
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 150
- **Author:** Sears Schulz
- **Flag:** `academy{8aae5dde384ce815668896d66b8f16a1}`

---

## Problem Statement & Scope
Tantangan `Some Assembly Required 3` merupakan lanjutan dari seri *Some Assembly Required* pada kompetisi picoCTF 2021. Aplikasi web menyajikan form input sederhana yang memeriksa kebenaran flag yang dimasukkan oleh pengguna di sisi peramban (*client-side*).

Berbeda dari aplikasi JavaScript konvensional, logika validasi pada tantangan ini dikompilasi ke dalam format biner biner WebAssembly (*Wasm*) bernama `qCCAcStfq3.wasm`. Pengguna ditantang untuk:
1. Mengunduh dan menganalisis biner WebAssembly yang dimuat secara dinamis oleh JavaScript pembungkus di browser.
2. Membaca struktur segmen memori linier (*linear memory*), tabel ekspor, serta fungsi-fungsi manipulasi string di dalamnya.
3. Mengidentifikasi logika transformasi masukan sebelum operasi pembandingan teks (`strcmp`).
4. Merekonstruksi algoritma inversi untuk memulihkan string flag rahasia tanpa bergantung pada eksekusi interaktif browser.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kepercayaan Berlebih pada Validasi Client-Side (CWE-602: Client-Side Enforcement of Server-Side Security):**
   Aplikasi menyerahkan seluruh tanggung jawab validasi flag kepada kode yang berjalan di browser klien. Meskipun kode dikompilasi ke dalam format biner WebAssembly, arsitektur WebAssembly adalah lingkungan terbuka (*open specification*) yang didesain transparan dan dapat didekompilasi sepenuhnya ke dalam representasi teks WebAssembly (*WAT*) maupun bahasa C menggunakan perkakas seperti `wabt` (`wasm2wat`, `wasm-decompile`) atau `wasm2c`.

2. **Arsitektur Memori Linier WebAssembly (Linear Memory Segment):**
   Modul Wasm mendefinisikan memori linier kontinu. Melalui dekompilasi `wasm-decompile`, ditemukan tata letak memori statis:
   - Offset `1024`: Segmen data `d_nAb416` sepanjang 41 byte yang menyimpan ciphertext target.
   - Offset `1067`: Segmen kunci `d_b` sepanjang 5 byte: `\xf1\xa7\xf0\x07\xed`.
   - Offset `1072`: Buffer tujuan masukan teks pengguna (`input`).

3. **Logika Transformasi Modulo-Indexed Inverted XOR (CWE-327):**
   Fungsi `copy(char, index)` menyalin karakter input pengguna ke dalam buffer `1072` dengan menerapkan enkripsi XOR berbasis siklus modulo 5 terbalik:
   $$j = \text{index} \pmod 5$$
   $$k = 4 - j = (5 - 1) - (\text{index} \pmod 5)$$
   $$\text{key\_byte} = d\_b[k]$$
   $$\text{encoded\_char} = \text{input\_char} \oplus \text{key\_byte}$$

4. **Involusi Simetris XOR (XOR Involution Property):**
   Operasi bitwise XOR memiliki sifat involutif:
   $$A \oplus B = C \iff C \oplus B = A$$
   Karena pembanding `strcmp` membandingkan string hasil transformasi dengan array terenkripsi di offset `1024`, maka karakter teks terang asli pada indeks $i$ diperoleh secara langsung dengan membalikkan operasi:
   $$P_i = C_i \oplus d\_b[4 - (i \pmod 5)]$$

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Biner WebAssembly dari Network Traffic / DevTools:**
   Melalui DevTools peramban atau inspeksi skrip JavaScript `index.js`, ditemukan permintaan fetch ke biner Wasm:
   ```javascript
   const exports = (await WebAssembly.instantiateStreaming(fetch('./qCCAcStfq3.wasm'))).instance.exports;
   ```

2. **Dekomplikasi Wasm ke Format Teks (WAT / Wasm-Decompile):**
   Menggunakan perkakas `wasm-decompile` dari paket `wabt`:
   ```bash
   wasm-decompile qCCAcStfq3.wasm -o script.dcmp
   ```
   Pada segmen data ditemukan:
   ```text
   data d_nAb416(offset: 1024) =
     "\9dn\93\c8\b2\b9A\8b\9f\90\8cb\c5\c3\95\884\c8\93\92\88?\c1\92\c7\db?\c8\9e\c7\891\c6\c5\c9\8b6\c6\c6\c0\90\00\00";
   data d_b(offset: 1067) = "\f1\a7\f0\07\ed";
   ```

3. **Analisis Fungsi Dekripsi XOR Statis:**
   Array byte terenkripsi diekstraksi ke representasi byte heksadesimal:
   ```python
   d_nAb416 = bytes([
       0x9d, ord('n'), 0x93, 0xc8, 0xb2, 0xb9, ord('A'), 0x8b,
       0x9f, 0x90, 0x8c, ord('b'), 0xc5, 0xc3, 0x95, 0x88,
       ord('4'), 0xc8, 0x93, 0x92, 0x88, ord('?'), 0xc1, 0x92,
       0xc7, 0xdb, ord('?'), 0xc8, 0x9e, 0xc7, 0x89, ord('1'),
       0xc6, 0xc5, 0xc9, 0x8b, ord('6'), 0xc6, 0xc6, 0xc0, 0x90
   ])
   d_b = bytes([0xf1, 0xa7, 0xf0, 0x07, 0xed])
   ```

4. **Eksekusi Inversi Dekripsi Bitwise:**
   Menerapkan persamaan inversi:
   ```python
   flag = ''.join(chr(b ^ d_b[4 - (i % 5)]) for i, b in enumerate(d_nAb416))
   ```
   Hasil dekripsi menghasilkan string flag utuh:
   ```text
   picoCTF{8aae5dde384ce815668896d66b8f16a1}
   ```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{8aae5dde384ce815668896d66b8f16a1}`
- **Native Platform Flag:** `picoCTF{8aae5dde384ce815668896d66b8f16a1}`
- **Status Solver:** Teruji dan terverifikasi 100% menggunakan skrip solver deterministik `scripts/solve_153_some_assembly_required_3.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Larangan Menyimpan Kunci & Rahasia di Sisi Klien:**
   Kompilasi kode ke biner WebAssembly hanya memberikan *obfuscation*, bukan enkripsi yang aman. Seluruh data yang disimpan pada modul Wasm klien dapat dibaca oleh pengguna melalui perkakas analisis biner terbuka.

2. **Kepatuhan Desain Zero-Trust pada Arsitektur Web:**
   Sesuai panduan NIST SP 800-115 dan OWASP ASVS (*Application Security Verification Standard*), seluruh verifikasi otentikasi, perizinan, dan pembandingan rahasia wajib dieksekusi secara ketat di sisi server (*server-side authorization*) melalui protokol terenkripsi TLS dengan proteksi rate-limiting. Client-side logic hanya boleh difungsikan untuk validasi format masukan awal demi kenyamanan antarmuka pengguna (*UX*).
