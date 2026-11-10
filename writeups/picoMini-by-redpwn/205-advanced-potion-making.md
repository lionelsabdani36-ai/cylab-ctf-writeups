# Writeup: advanced-potion-making (Challenge ID: 205)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / File Header Carving & Color Plane Steganography (CWE-1288)
- **Difficulty:** Medium (diff=2)
- **Event:** picoMini by redpwn
- **Points:** 200
- **Author:** e-sushi
- **Flag Resmi:** `picoCTF{w1z4rdry}`
- **Audit Batch:** Batch 188 (10 November 2026) - Live Verified HTTP 201 (`correct: true`)

---

## Problem Statement & Scope
Tantangan `advanced-potion-making` menyediakan berkas biner tanpa ekstensi bernama `advanced-potion-making`. Deskripsi tantangan berbunyi: *"Ron just found his own copy of advanced potion making, but it's been corrupted by some kind of spell. Help him recover it!"*. Berkas tersebut tidak dapat dibuka oleh penampil gambar standar dan utilitas `file` mengidentifikasinya sebagai data mentah (*raw data*). Peserta ditugaskan untuk melakukan analisis struktur biner berkas, memperbaiki bagian header yang terkorupsi sesuai spesifikasi format berkas resmi (RFC 2083), dan memulihkan teks rahasia yang tersembunyi di dalam media grafis.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Ketidakkonsistenan Tanda Tangan Format Berkas (CWE-1288 - Corrupted File Signature):**
   Spesifikasi Portable Network Graphics (PNG, RFC 2083) menetapkan tanda tangan 8-byte wajib pada awal berkas:
   ```text
   89 50 4E 47 0D 0A 1A 0A
   ```
   Inspeksi heksadesimal terhadap berkas tantangan menunjukkan byte awal berikut:
   ```text
   Offset 0x00..0x07: 89 50 42 11 0D 0A 1A 0A
   ```
   Byte pada indeks 2 dan 3 sengaja dirusak dari `4E 47` (`NG`) menjadi `42 11`. Akibatnya, parser gambar menolak berkas karena kegagalan pencocokan *magic bytes*.
2. **Korupsi Bidang Panjang Chunk IHDR (RFC 2083 Section 4.1.1):**
   Chunk pertama pada berkas PNG wajib berupa chunk `IHDR`. Format chunk PNG terdiri dari:
   - 4-byte *Length*: Jumlah byte data chunk.
   - 4-byte *Chunk Type*: Nama chunk ASCII (misal `IHDR`).
   - Data chunk.
   - 4-byte *CRC*: Checksum CRC-32 atas tipe dan data chunk.
   Pada berkas tantangan:
   ```text
   Offset 0x08..0x0B: 00 12 13 14
   ```
   Data chunk `IHDR` PNG selalu berukuran persis 13 byte (`0x0000000D`). Nilai `00 12 13 14` adalah panjang palsu yang merusak orientasi pembacaan chunk.
3. **Verifikasi Integritas Data via Checksum CRC-32:**
   Data chunk `IHDR` pada berkas tidak mengalami kerusakan:
   ```text
   49 48 44 52 00 00 09 90 00 00 04 D8 08 02 00 00 00
   ```
   - Lebar: 2448 piksel (`0x00000990`)
   - Tinggi: 1240 piksel (`0x000004D8`)
   - Bit depth: 8, Color type: 2 (Truecolor RGB), Compression: 0, Filter: 0, Interlace: 0.
   Kalkulasi `zlib.crc32(ihdr_bytes)` menghasilkan checksum `0x042DE778`, yang persis sama dengan 4 byte CRC pada offset `0x1D..0x20` berkas asli. Hal ini membuktikan bahwa payload dimensi citra masih utuh sempurna.
4. **Steganografi Variasi Saluran Warna Merah (Red Plane Variation):**
   Setelah berkas PNG diperbaiki, citra menampilkan kanvas merah pekat yang tampak seragam secara visual (`#FF0000`). Namun, teks bendera disembunyikan menggunakan modulasi piksel minor pada komponen warna merah. Melakukan thresholding atau ekstraksi bidang warna merah mengekspos glif teks bendera putih.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Heksadesimal Header Berkas:**
   Buka berkas menggunakan hexdump:
   ```bash
   xxd -l 32 advanced-potion-making
   ```
   Keluaran:
   ```text
   00000000: 8950 4211 0d0a 1a0a 0012 1314 4948 4452  .PB.........IHDR
   00000010: 0000 0990 0000 04d8 0802 0000 0004 2de7  ..............-.
   ```
2. **Penerapan Tambalan Byte Biner (Patching):**
   Gunakan Python untuk menimpa 8 byte tanda tangan dan 4 byte panjang IHDR:
   ```python
   with open('advanced-potion-making', 'rb') as f:
       data = bytearray(f.read())
   data[0:8] = b'\x89PNG\r\n\x1a\n'
   data[8:12] = b'\x00\x00\x00\r'
   with open('repaired.png', 'wb') as f:
       f.write(data)
   ```
   Verifikasi bahwa `repaired.png` kini dikenali oleh utilitas `file` sebagai `PNG image data, 2448 x 1240, 8-bit/color RGB, non-interlaced`.
3. **Ekstraksi Steganografi Citra:**
   Buka `repaired.png` menggunakan tool manipulasi citra (seperti StegSolve, PIL, atau ImageMagick). Saat filter *Red Plane 0/1* atau penyesuaian kontras kurva diterapkan, teks bendera putih terbaca di atas latar belakang hitam:
   `picoCTF{w1z4rdry}`.
4. **Otomasi Skrip Solver:**
   Alur perbaikan biner dan ekstraksi steganografi dipetakan pada `scripts/solve_205_advanced_potion_making.py`.

---

## Flag & Verifikasi
- **Flag Resmi:** `picoCTF{w1z4rdry}`
- **Wrapper Validator:** Native event wrapper (`picoCTF{...}`)
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_205_advanced_potion_making.py`.

### Re-verifikasi Audit Batch 188 (2026-11-10 UTC, sesi REST siswa `Arielwin` / user id 1072359)

| Token diuji | Wrapper | HTTP | Respons API |
| :--- | :--- | :--- | :--- |
| `picoCTF{w1z4rdry}` | native event | 201 | `{"user":1072359,"challenge":205,"flag":"picoCTF{w1z4rdry}","correct":true,"historical":false}` |
| `academy{w1z4rdry}` | CyLab rekey | 201 | `{"user":1072359,"challenge":205,"flag":"academy{w1z4rdry}","correct":false,"historical":false}` |

- **Temuan format validator:** Validator CyLab menerima wrapper asli event `picoCTF{...}` dan menolak wrapper rekey `academy{...}` dengan status `correct: false`.
- **Reproduktifitas offline:** Solver `scripts/solve_205_advanced_potion_making.py` merekonstruksi byte header secara valid dan mengonfirmasi integritas CRC chunk.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Analisis Integritas Struktur Media (NIST SP 800-115 §5.4):**
   Dalam investigasi forensik digital, penyerang sering merusak header berkas (*magic bytes stomping*) untuk mengelabui deteksi otomatis antivirus dan sensor EDR. Praktisi LKS harus menguasai anatomi spesifikasi biner standar (seperti chunk structure pada PNG/JPEG/ZIP/ELF) untuk memulihkan artefak bukti (*file carving*).
2. **Validasi File Strict pada Gerbang Unggah (Upload Gateway Hardening):**
   Aplikasi penerima berkas tidak boleh hanya bergantung pada ekstensi berkas atau header MIME `Content-Type` yang dikirimkan oleh klien. Terapkan validasi *magic bytes* lengkap dan verifikasi rekursif struktur chunk serta dekompresi sampel gambar menggunakan pustaka yang diisolasi (*sandboxed parser*).
3. **Pembersihan Metadata & Normalisasi Grafis Defensif:**
   Citra yang diunggah pengguna ke sistem publik wajib diproses ulang melalui *re-encoding pipeline* (misal merender ulang piksel ke format webp/png baru) untuk mensterilkan muatan steganografi atau metadata tersembunyi sebelum dipublikasikan.
