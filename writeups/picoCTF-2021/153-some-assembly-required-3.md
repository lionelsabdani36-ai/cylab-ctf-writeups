# Writeup: Some Assembly Required 3 (Challenge ID: 153)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / WebAssembly Binary Analysis & Inverted XOR Cipher
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 150
- **Author:** Sears Schulz
- **Flag:** `academy{033f77ed87dcdbcf212e352bde117d44}`

---

## Problem Statement & Scope
Tantangan `Some Assembly Required 3` merupakan lanjutan dari seri *Some Assembly Required* pada kompetisi picoCTF 2021. Aplikasi web menyajikan form input sederhana yang memeriksa kebenaran flag yang dimasukkan oleh pengguna di sisi peramban (*client-side*).

Berbeda dari aplikasi JavaScript konvensional, logika validasi pada tantangan ini dikompilasi ke dalam format biner WebAssembly (*Wasm*) yang dimuat dari instans lab dinamis CyLab (`./qCCYI0ajpD`). Pengguna ditantang untuk:
1. Mengunduh dan menganalisis biner WebAssembly yang dimuat secara dinamis oleh JavaScript pembungkus di browser.
2. Membaca struktur segmen memori linier (*linear memory*), tabel ekspor, serta fungsi-fungsi manipulasi string di dalamnya.
3. Mengidentifikasi logika transformasi masukan sebelum operasi pembandingan teks (`strcmp`).
4. Merekonstruksi algoritma inversi untuk memulihkan string flag rahasia tanpa bergantung pada eksekusi interaktif browser.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kepercayaan Berlebih pada Validasi Client-Side (CWE-602: Client-Side Enforcement of Server-Side Security):**
   Aplikasi menyerahkan seluruh tanggung jawab validasi flag kepada kode yang berjalan di browser klien. Meskipun kode dikompilasi ke dalam format biner WebAssembly, arsitektur WebAssembly adalah lingkungan terbuka (*open specification*) yang didesain transparan dan dapat didekompilasi sepenuhnya ke dalam representasi teks WebAssembly (*WAT*) maupun bahasa C menggunakan perkakas seperti `wabt` (`wasm2wat`, `wasm-decompile`) atau dianalisis langsung menggunakan runtime Node.js `WebAssembly.Instance`.

2. **Arsitektur Memori Linier WebAssembly (Linear Memory Segment):**
   Modul Wasm mendefinisikan memori linier kontinu. Melalui inspeksi segmen memori pada live instance CyLab, ditemukan tata letak memori statis:
   - Offset `1024`: Segmen ciphertext target sepanjang 41 byte:
     `[0x8c, 0x64, 0x91, 0xc3, 0x94, 0x80, 0x7e, 0x8b, 0x97, 0xc2, 0xde, 0x61, 0xc7, 0x90, 0x94, 0x89, 0x3f, 0xc7, 0xc3, 0x92, 0x89, 0x65, 0x93, 0xc1, 0xc3, 0xdc, 0x35, 0x95, 0x94, 0xc4, 0xdf, 0x65, 0x94, 0xc2, 0xc0, 0xdc, 0x30, 0x94, 0x93, 0xc5, 0x90]`.
   - Offset `1067`: Segmen kunci `d_b` sepanjang 5 byte: `[0xf1, 0xa7, 0xf0, 0x07, 0xed]`.
   - Offset `1072`: Buffer tujuan masukan teks pengguna (`input`).

3. **Logika Transformasi Modulo-Indexed Inverted XOR (CWE-327):**
   Fungsi `copy_char(char, index)` menyalin karakter input pengguna ke dalam buffer `1072` dengan menerapkan enkripsi XOR berbasis siklus modulo 5 terbalik:
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
1. **Ekstraksi Biner WebAssembly dari Instans Live CyLab:**
   Melalui inspeksi skrip JavaScript `rTEuOmSfG3.js` pada instans yang diluncurkan:
   ```javascript
   let _0x487b31 = await fetch('./qCCYI0ajpD');
   let _0x5eebfd = await WebAssembly['instantiate'](await _0x487b31['arrayBuffer']());
   ```

2. **Inspeksi Memori Linier Wasm:**
   Menggunakan runtime Node.js untuk mengekstrak array byte terenkripsi pada offset 1024 dan kunci pada offset 1067:
   ```javascript
   const mem = new Uint8Array(instance.exports.memory.buffer);
   const target = mem.slice(1024, 1065);
   const key = mem.slice(1067, 1072);
   ```

3. **Eksekusi Inversi Dekripsi Bitwise:**
   Menerapkan persamaan inversi:
   ```python
   target = bytes([
       0x8c, 0x64, 0x91, 0xc3, 0x94, 0x80, 0x7e, 0x8b, 0x97, 0xc2,
       0xde, 0x61, 0xc7, 0x90, 0x94, 0x89, 0x3f, 0xc7, 0xc3, 0x92,
       0x89, 0x65, 0x93, 0xc1, 0xc3, 0xdc, 0x35, 0x95, 0x94, 0xc4,
       0xdf, 0x65, 0x94, 0xc2, 0xc0, 0xdc, 0x30, 0x94, 0x93, 0xc5,
       0x90
   ])
   key = bytes([0xf1, 0xa7, 0xf0, 0x07, 0xed])
   flag = ''.join(chr(b ^ key[4 - (i % 5)]) for i, b in enumerate(target))
   ```
   Hasil dekripsi menghasilkan string flag utuh:
   ```text
   academy{033f77ed87dcdbcf212e352bde117d44}
   ```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{033f77ed87dcdbcf212e352bde117d44}`
- **Status Solver:** Teruji dan terverifikasi 100% pada instance live CyLab dan modul `scripts/solve_153_some_assembly_required_3.py` (HTTP 201 `correct: true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Larangan Menyimpan Kunci & Rahasia di Sisi Klien:**
   Kompilasi kode ke biner WebAssembly hanya memberikan *obfuscation*, bukan enkripsi yang aman. Seluruh data yang disimpan pada modul Wasm klien dapat dibaca oleh pengguna melalui perkakas analisis biner terbuka.

2. **Kepatuhan Desain Zero-Trust pada Arsitektur Web:**
   Sesuai panduan NIST SP 800-115 dan OWASP ASVS (*Application Security Verification Standard*), seluruh verifikasi otentikasi, perizinan, dan pembandingan rahasia wajib dieksekusi secara ketat di sisi server (*server-side authorization*) melalui protokol terenkripsi TLS dengan proteksi rate-limiting. Client-side logic hanya boleh difungsikan untuk validasi format masukan awal demi kenyamanan antarmuka pengguna (*UX*).
