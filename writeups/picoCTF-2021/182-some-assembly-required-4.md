# Writeup: Some Assembly Required 4 (Challenge ID: 182)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / WebAssembly (WASM) Reverse Engineering & Memory Analysis
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 200
- **Author:** Sears Schulz
- **Flag:** `academy{b9da2135bc2b724208745a4d74d232d2}`

---

## Problem Statement & Scope
Tantangan `Some Assembly Required 4` menyajikan aplikasi web berbasis klien (*client-side web application*) yang memvalidasi kunci akses atau flag melalui modul biner WebAssembly yang dimuat secara dinamis (`ZoRd23o0wd`). Antarmuka web menerima input pengguna melalui elemen formulir HTML, menyalin karakter input ke memori linear WASM melalui fungsi `copy_char()`, kemudian memanggil fungsi `check_flag()` untuk menentukan keabsahan flag.

Ruang lingkup audit keamanan aplikasi web dan rekayasa balik WASM ini mencakup:
1. Dekompilasi berkas biner WebAssembly ke format teks WebAssembly (*WebAssembly Text Format* / WAT) menggunakan perangkat WebAssembly Binary Toolkit (WABT) dan Chrome DevTools.
2. Analisis pemetaan memori linear (*linear memory layout*), identifikasi alamat buffer input pengguna dan buffer *ciphertext* acuan.
3. Rekayasa balik alur logika validasi bertingkat pada subrutin `check_flag()` (transposisi pasangan byte, penyamaran XOR berbasis modulo indeks, dan umpan balik byte bertingkat).
4. Rekonstruksi algoritma inversi kriptografis untuk memulihkan flag sesuai metodologi bimbingan teknis **NIST SP 800-115 Section 4.2** (*Software Analysis and Reverse Engineering*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyimpanan Logika Validasi Sensitif pada Lingkungan Klien (CWE-603 / CWE-256):**
   - WebAssembly dieksekusi secara lokal pada mesin peramban pengguna (*browser client engine*). Meskipun dikompilasi menjadi biner tingkat rendah, struktur instruksi dan seluruh blok memori linear WASM sepenuhnya dapat diinspeksi, di-*debug*, dan dimanipulasi oleh pengguna melalui antarmuka *Developer Tools*.
   - Menyimpan algoritma verifikasi rahasia atau kunci flag secara lokal pada sisi klien merupakan pelanggaran prinsip pemisahan kepercayaan (*client-side trust boundary violation*).
2. **Keterbalikan Struktur Obfuskasi Sisi Memori (Reversible Symmetric Operations):**
   - Analisis dekompilasi `check_flag()` membuktikan bahwa fungsi validasi membandingkan input pengguna dengan array 42-byte yang tersimpan pada memori linear `1024`.
   - Modifikasi input dilakukan melalui tahapan yang bersifat simetris (*bijective mappings*):
     1. **Transposisi Pasangan Byte (*Pairwise Byte Swapping*):** Menukar byte posisi $i$ dan $i+1$ untuk setiap langkah genap ($i \mathrel{+}= 2$).
     2. **XOR Berbasis Modulo Posisi (*Positional Modulo XOR*):**
        - Indeks modulo 3: jika $i \pmod 3 == 0 \implies \oplus 7$, jika $i \pmod 3 == 1 \implies \oplus 6$, lainnya $\oplus 5$.
        - Indeks modulo 2: jika $i \pmod 2 \ne 0 \implies \oplus 8$, lainnya $\oplus 9$.
        - Modulo 10: $\oplus (i \pmod{10})$.
     3. **Umpan Balik Rantai Riwayat (*Recursive History Chaining*):** Setiap byte di-XOR dengan byte acuan sebelumnya pada jarak offset $-1$ dan $-3$.
     4. **Penyamaran Masker Statis:** Operasi akhir dengan konstanta $\text{0x14}$ (desimal 20).
   - Karena setiap operasi memiliki invers matematis satu-ke-satu, seluruh rantai obfuskasi dapat dibalik secara analitis tanpa memerlukan komputasi *brute-force* dinamis.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Aset WebAssembly & Inspeksi DevTools:**
   - Mengakses aplikasi web dan memeriksa berkas JavaScript pembungkus (`index.js`).
   - Menemukan pemanggilan modul WASM dari endpoint relatif `./ZoRd23o0wd`.
   - Mengunduh berkas biner WASM dan membongkar ekspor modul:
     ```wat
     (export "memory" (memory 0))
     (export "strcmp" (func $strcmp))
     (export "check_flag" (func $check_flag))
     (export "copy_char" (func $copy_char))
     ```
2. **Pemetaan Alamat Memori Linear:**
   - Memasang breakpoint pada awal fungsi `strcmp` menggunakan Chrome DevTools debugger.
   - Mengamati struktur buffer memori:
     - Alamat `1024`: Lokasi string target terenkripsi sepanjang 42 byte.
     - Alamat `1072`: Alamat tujuan penyalinan input pengguna oleh `copy_char()`.
3. **Penyusunan Skrip Inversi Kriptografi Sisi Klien:**
   - Mengekstrak 42 byte dari offset `1024` pada memori WASM:
     ```javascript
     let memoryArray = new Uint8Array(exports.memory.buffer);
     let encryptedBytes = Array.from(memoryArray.slice(1024, 1024 + 42));
     ```
   - Menerapkan pembalikan logika secara deterministik:
     ```python
     # Membalik penukaran pasangan byte (pairwise unswap)
     for i in range(0, len(encrypted_bytes) - 1, 2):
         encrypted_bytes[i], encrypted_bytes[i + 1] = encrypted_bytes[i + 1], encrypted_bytes[i]

     # Membalik masking XOR dan umpan balik historis
     swapped = list(encrypted_bytes)
     for idx in range(len(encrypted_bytes)):
         char = encrypted_bytes[idx]
         if idx % 3 == 0:
             char ^= 7
         elif idx % 3 == 1:
             char ^= 6
         else:
             char ^= 5

         if idx % 2 != 0:
             char ^= 8
         else:
             char ^= 9

         char ^= (idx % 10)
         if idx > 2:
             char ^= swapped[idx - 3]
         if idx > 0:
             char ^= swapped[idx - 1]
         char ^= 20
         encrypted_bytes[idx] = char
     ```
4. **Pemulihan Teks Jelas & Flag:**
   - Hasil konversi byte array menghasilkan string teks asli:
     `picoCTF{b9da2135bc2b724208745a4d74d232d2}`
   - Format flag platform CyLab Academy:
     `academy{b9da2135bc2b724208745a4d74d232d2}`
5. **Validasi Solver Otomatis:**
   - Menjalankan skrip reproduktif:
     ```bash
     python3 scripts/solve_182_some_assembly_required_4.py
     ```
   - Skrip memverifikasi alur simulasi rekonstruksi inversi memori WASM dan assert token.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{b9da2135bc2b724208745a4d74d232d2}`
- **Komunitas Standar (CTF Format):** `CTF{b9da2135bc2b724208745a4d74d232d2}`
- **Native picoCTF Format:** `picoCTF{b9da2135bc2b724208745a4d74d232d2}`
- **Status Verifikasi:** Terverifikasi 100% pada pemetaan memori linear dan pembalikan siklus XOR WebAssembly.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Pemisahan Validasi Klien dan Server (LKS Web Security):**
   Dalam kurikulum LKS Cyber Security bidang Web Application Security, logika validasi kredensial, lisensi, atau data rahasia tidak boleh dieksekusi di sisi klien (*client-side execution*). WebAssembly hanya boleh digunakan untuk komputasi performa tinggi (grafis, pemrosesan audio/video), sedangkan otentikasi wajib dikonfirmasi melalui API backend terpercaya.
2. **Keterbatasan Obfuskasi Biner:**
   Teknik obfuskasi logika biner (seperti transposisi byte dan rantai operasi XOR) hanya memberikan ilusi keamanan (*security through obscurity*). Penyerang dengan pemahaman struktur instruksi biner tingkat rendah dapat memetakan graf kendali dan membalikkan algoritma secara deterministik.
3. **Penerapan NIST SP 800-115:**
   Analisis statis dan dinamis pada memori aplikasi peramban menegaskan bahwa pengujian penetrasi berbasis *whitebox/greybox* mampu mengekstraksi informasi rahasia tanpa memicu alarm deteksi di sisi server.
