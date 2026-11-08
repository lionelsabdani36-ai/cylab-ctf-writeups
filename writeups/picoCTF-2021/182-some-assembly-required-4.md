# Writeup: Some Assembly Required 4 (Challenge ID: 182)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / WebAssembly (WASM) Reverse Engineering & Memory Analysis
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 200
- **Author:** Sears Schulz
- **Flag:** `academy{e69e121eab55f85293c89b9082255ed7}`

---

## Problem Statement & Scope
Tantangan `Some Assembly Required 4` menyajikan aplikasi web berbasis klien (*client-side web application*) yang memvalidasi kunci akses atau flag melalui modul biner WebAssembly yang dimuat secara dinamis (`ZoRd23o0wd`). Antarmuka web menerima input pengguna melalui elemen formulir HTML, menyalin karakter input ke memori linear WASM melalui fungsi `copy_char()`, kemudian memanggil fungsi `check_flag()` untuk menentukan keabsahan flag.

Ruang lingkup audit keamanan aplikasi web dan rekayasa balik WASM ini mencakup:
1. Dekompilasi berkas biner WebAssembly ke format teks WebAssembly (*WebAssembly Text Format* / WAT) menggunakan perangkat WebAssembly Binary Toolkit (WABT) dan runtime Node.js.
2. Analisis pemetaan memori linear (*linear memory layout*), identifikasi alamat buffer input pengguna dan buffer *ciphertext* acuan.
3. Rekayasa balik alur logika validasi bertingkat pada subrutin `check_flag()` (transposisi pasangan byte, penyamaran XOR berbasis modulo indeks, dan umpan balik byte bertingkat).
4. Rekonstruksi algoritma inversi kriptografis untuk memulihkan flag sesuai metodologi bimbingan teknis **NIST SP 800-115 Section 4.2** (*Software Analysis and Reverse Engineering*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyimpanan Logika Validasi Sensitif pada Lingkungan Klien (CWE-603 / CWE-256):**
   - WebAssembly dieksekusi secara lokal pada mesin peramban pengguna (*browser client engine*). Meskipun dikompilasi menjadi biner tingkat rendah, struktur instruksi dan seluruh blok memori linear WASM sepenuhnya dapat diinspeksi, di-*debug*, dan dimanipulasi oleh pengguna melalui antarmuka *Developer Tools*.
   - Menyimpan algoritma verifikasi rahasia atau kunci flag secara lokal pada sisi klien merupakan pelanggaran prinsip pemisahan kepercayaan (*client-side trust boundary violation*).
2. **Keterbalikan Struktur Obfuskasi Sisi Memori (Reversible Symmetric Operations):**
   - Analisis dekompilasi `check_flag()` membuktikan bahwa fungsi validasi membandingkan input pengguna dengan array 41-byte yang tersimpan pada memori linear `1024`.
   - Modifikasi input dilakukan melalui tahapan pasangan byte (*pairwise byte swapping*) dan pemrosesan kausal beruntun:
     Output pada pasangan byte `(2k, 2k+1)` hanya bergantung pada karakter input hingga indeks `2k+1`. Karakter pada indeks yang lebih besar tidak memengaruhi byte keluaran pada posisi sebelumnya.
   - Karena setiap operasi memelihara sifat kausalitas lokal, penyelesaian dapat dilakukan secara sekuensial per pasangan byte dalam orde mikrodetik.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Aset WebAssembly & Inspeksi Skrip Loader:**
   - Mengakses instans lab yang diluncurkan dan memeriksa berkas JavaScript pembungkus (`rqe4VVml5W.js`).
   - Menemukan pemanggilan modul WASM dari endpoint relatif `./ZoRd23o0wd`.
   - Mengunduh berkas biner WASM dan membongkar ekspor modul:
     ```wat
     (export "memory" (memory 0))
     (export "strcmp" (func $strcmp))
     (export "check_flag" (func $check_flag))
     (export "copy_char" (func $copy_char))
     ```
2. **Pemetaan Alamat Memori Linear:**
   - Mengamati struktur buffer memori:
     - Alamat `1024`: Lokasi string target terenkripsi sepanjang 41 byte:
       `[0x03, 0x7b, 0x7f, 0x78, 0x0f, 0x06, 0x75, 0x15, 0x3e, 0x0f, 0x1b, 0x69, 0x4e, 0x0c, 0x0f, 0x78, 0x39, 0x3d, 0x0a, 0x11, 0x7e, 0x4d, 0x3d, 0x58, 0x10, 0x64, 0x10, 0x50, 0x08, 0x2a, 0x3a, 0x3b, 0x01, 0x10, 0x2f, 0x16, 0x69, 0x07, 0x10, 0x32, 0x1f]`
     - Alamat `1072`: Alamat tujuan penyalinan input pengguna oleh `copy_char()`.
3. **Penyusunan Skrip Inversi Kausalitas Pasangan Byte:**
   - Memanfaatkan isolasi kausalitas antar pasangan byte:
     ```javascript
     for (let p = 8; p < 40; p += 2) {
         for (let c1 = 32; c1 < 127; c1++) {
             for (let c2 = 32; c2 < 127; c2++) {
                 flag[p] = String.fromCharCode(c1);
                 flag[p+1] = String.fromCharCode(c2);
                 loadAndCheck(flag);
                 if (mem[1072 + p] === target[p] && mem[1072 + p + 1] === target[p + 1]) {
                     break;
                 }
             }
         }
     }
     ```
4. **Pemulihan Teks Jelas & Flag:**
   - Hasil rekonstruksi menghasilkan string flag utuh:
     `academy{e69e121eab55f85293c89b9082255ed7}`
   - Pemanggilan `check_flag()` memvalidasi hasil dengan return code `1` (Correct).

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{e69e121eab55f85293c89b9082255ed7}`
- **Status Verifikasi:** Terverifikasi 100% pada instance live CyLab dan modul `scripts/solve_182_some_assembly_required_4.py` (HTTP 201 `correct: true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Pemisahan Validasi Klien dan Server (LKS Web Security):**
   Dalam kurikulum LKS Cyber Security bidang Web Application Security, logika validasi kredensial, lisensi, atau data rahasia tidak boleh dieksekusi di sisi klien (*client-side execution*). WebAssembly hanya boleh digunakan untuk komputasi performa tinggi (grafis, pemrosesan audio/video), sedangkan otentikasi wajib dikonfirmasi melalui API backend terpercaya.
2. **Keterbatasan Obfuskasi Biner:**
   Teknik obfuskasi logika biner (seperti transposisi byte dan rantai operasi XOR) hanya memberikan ilusi keamanan (*security through obscurity*). Penyerang dengan pemahaman struktur instruksi biner tingkat rendah dapat memetakan graf kendali dan membalikkan algoritma secara deterministik.
3. **Penerapan NIST SP 800-115:**
   Analisis statis dan dinamis pada memori aplikasi peramban menegaskan bahwa pengujian penetrasi berbasis *whitebox/greybox* mampu mengekstraksi informasi rahasia tanpa memicu alarm deteksi di sisi server.
