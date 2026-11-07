# Writeup: Java Script Kiddie (Challenge ID: 29)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Client-Side Obfuscation & File Format Structure Reversal
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 400
- **Author:** John Johnson
- **Flag:** `academy{b8c2d4d4ccc483bf434b0f35f3e60f70}`

---

## Problem Statement & Scope
Tantangan `Java Script Kiddie` menyajikan aplikasi web yang menampilkan formulir input untuk memasukkan kunci 16-karakter numerik dan elemen gambar kosong (`<img id="Area" src=""/>`). Ketika pengguna menekan tombol Submit, fungsi JavaScript client-side `assemble_png(u_in)` dieksekusi. Fungsi tersebut memproses array mentah byte (`bytes`, panjang 688 byte yang diunduh dari `/bytes`) menggunakan transformasi transposisi kolom berdasarkan kunci yang dimasukkan pengguna. Jika kunci benar, gambar yang dihasilkan akan memunculkan kode QR berisi flag.

Ruang lingkup audit ini berfokus pada evaluasi keamanan validasi input client-side dan pengamanan rahasia pada arsitektur web modern berdasarkan standar **NIST SP 800-115 Section 4.3** (*Application Security Assessment & Input Validation*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyalahgunaan Client-Side Execution untuk Kontrol Akses Data (CWE-656: Reliance on Security Through Obscurity):**
   Aplikasi menaruh seluruh logika rekonstruksi dan data terenkripsi/teracak (`/bytes`) di sisi klien (browser). Di web security, klien adalah lingkungan yang tidak tepercaya (*untrusted boundary*). Mengandalkan algoritma transposisi sederhana di browser tanpa enkripsi autentikasi server-side memungkinkan analis membongkar logika matematika di balik permutasi byte.

2. **Dekomposisi Struktur File PNG (RFC 2083 Specification):**
   Format file PNG memiliki spesifikasi biner ketat yang diatur dalam RFC 2083:
   - **PNG File Signature (8 byte):** `0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A 0x0A` (`\x89PNG\r\n\x1a\n`).
   - **IHDR Chunk Length (4 byte):** `0x00 0x00 0x00 0x0D` (13 byte panjang data IHDR).
   - **IHDR Chunk Type (4 byte):** `0x49 0x48 0x44 0x52` (`IHDR`).
   Gabungan signature dan header IHDR ini membentuk 16 byte pertama yang bernilai pasti (*constant known plaintext*).

3. **Mekanisme Transposisi Siklis Kolom:**
   Pada fungsi `assemble_png`:
   ```javascript
   var LEN = 16;
   for(var i = 0; i < LEN; i++){
       shifter = key.charCodeAt(i) - 48;
       for(var j = 0; j < (bytes.length / LEN); j ++){
           result[(j * LEN) + i] = bytes[(((j + shifter) * LEN) % bytes.length) + i]
       }
   }
   ```
   Data `bytes` memiliki panjang 688 byte, yang setara dengan matriks 43 baris $\times$ 16 kolom ($43 \times 16 = 688$).
   Setiap kolom $i \in [0, 15]$ digeser secara vertikal (*cyclic row shift*) oleh nilai $s_i \in [0, 9]$ yang ditentukan oleh karakter kunci ke-$i$ (`key[i] - 48`).
   Untuk baris pertama ($j = 0$):
   $$\text{result}[i] = \text{bytes}[(s_i \times 16 \pmod{688}) + i]$$
   Karena 16 byte pertama $\text{result}[0 \dots 15]$ harus identik dengan header standar PNG, maka setiap digit pergeseran $s_i$ dapat dicari secara independen per kolom tanpa perlu melakukan *brute force* eksponensial terhadap seluruh ruang kunci $10^{16}$.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Struktur Data & Pemetaan Kandidat Digit:**
   - Unduh berkas `bytes` dari endpoint server lab (`/bytes`).
   - Panjang array: 688 integer.
   - Evaluasi setiap kolom $i \in [0, 15]$ untuk setiap calon $s \in [0, 9]$. Cocokkan nilai dengan `PNG_HEADER[i]`.
   - Hasil evaluasi menunjukkan jumlah kandidat per kolom:
     `[1, 1, 2, 1, 1, 2, 1, 1, 2, 3, 3, 1, 1, 1, 1, 1]`.
   - Total kombinasi yang mungkin terpangkas drastis dari $10^{16}$ menjadi hanya $1 \times 1 \times 2 \times 1 \times 1 \times 2 \times 1 \times 1 \times 2 \times 3 \times 3 = 72$ permutasi.

2. **Penyaringan Integritas PNG & IEND Trailer:**
   - Lakukan iterasi pada ke-72 kandidat kunci.
   - Periksa keberadaan chunk penutup PNG `IEND` (`\x49\x45\x4E\x44\xAE\x42\x60\x82`).
   - Ditemukan tepat satu kunci yang menghasilkan struktur gambar PNG valid dan dapat didekode:
     $$\text{Key} = 7948003345591126$$

3. **Ekstraksi Flag melalui Pemindaian Kode QR:**
   - Gambar yang direkonstruksi berukuran $370 \times 370$ piksel (format monochrome QR Code).
   - Jalankan utilitas barcode scanner (`zbarimg /tmp/test_7948003345591126.png`).
   - Simbol barcode terbaca: `QR-Code:academy{b8c2d4d4ccc483bf434b0f35f3e60f70}`.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{b8c2d4d4ccc483bf434b0f35f3e60f70}`
- **Komunitas Standar (CTF Format):** `CTF{b8c2d4d4ccc483bf434b0f35f3e60f70}`
- **Status Verifikasi:** REST API CyLab `POST /api/submissions/` mengembalikan `HTTP 201 Created` dengan `correct: true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Arsitektur Zero-Trust Client-Side:**
   Jangan pernah menyimpan aset rahasia atau mengandalkan logika validasi rahasia di sisi klien browser (*obfuscation is not encryption*). Setiap data sensitif harus dilindungi dan divalidasi di backend server dengan autentikasi berbasis sesi tepercaya.
2. **Kelemahan Pengetahuan Format File (File Magic Bytes):**
   Format file standar industri (PNG, JPEG, PDF, ELF) memiliki *magic bytes* dan struktur metadata yang deterministik. Analis keamanan dapat menggunakan *known plaintext attack* untuk membalikkan skema transposisi atau substitusi sederhana dalam hitungan milidetik.
3. **Penerapan NIST SP 800-115:**
   Dalam pengujian aplikasi web, lakukan tinjauan kode statis (*Static Application Security Testing* / SAST) pada bundle JavaScript pihak klien guna memastikan tidak ada rahasia, kunci enkripsi, atau algoritma logika akses yang terekspos ke publik.
