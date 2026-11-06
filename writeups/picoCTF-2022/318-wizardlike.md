# Writeup: Wizardlike (Challenge ID: 318)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering
- **Difficulty:** Hard
- **Event:** picoCTF 2022
- **Author:** LT 'SYREAL' JONES
- **Flag:** `academy{ur_4_w1z4rd_4ca90492}`

---

## Problem Statement & Scope

Tantangan menyajikan sebuah biner ELF 64-bit stripped bernama `game`. Program mengimplementasikan permainan *dungeon crawler* berbasis terminal teks (ncurses) dengan 10 lantai *dungeon*. Pemain dikendalikan menggunakan tombol `w`, `a`, `s`, `d`, dengan rintangan berupa *fog-of-war* dan dinding batu (`#`) yang mencegah akses ke area tertentu tempat huruf-huruf flag disembunyikan.

Batasan lingkungan:
- Biner ELF 64-bit x86-64 statically-linked dan stripped.
- Tidak ada akses langsung ke flag melalui fungsi `strings` standar karena token disusun dalam bentuk pola ubin peta ASCII 2D berukuran 100x100 pada setiap lantai.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Client-Side Enforcement & Unprotected Asset Storage:** Permainan mengandalkan pembatasan pergerakan di sisi klien (*collision check* dan *line-of-sight fog-of-war*) untuk menyembunyikan konten dari pemain. Seluruh data peta statis (10 lantai) disimpan mentah (*unencrypted raw byte arrays*) di dalam seksi `.data` biner pada alamat virtual `0x50a820` (file offset `0x109820`).
2. **Deterministic Memory Alignment:** Setiap lantai peta dialokasikan tepat berukuran $100 \times 100 = 10.000$ byte dengan interval penyelarasan `0x2720` (10.016 byte). Struktur data teratur ini memungkinkan ekstraksi *offline* tanpa perlu mengeksekusi biner atau melewati algoritma pembatasan fisika game.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Struktur Biner & Pemetaan Alamat:**
   - Melalui disasembli pada rutin loop utama (`0x402057`), biner memuat lantai 1 dari alamat `0x50a820` (`lea 0x108792(%rip), %rax`), lantai 2 dari `0x50cf40`, lantai 3 dari `0x50f660`, dan seterusnya.
   - Jarak antar pointer peta adalah konstan: `0x50cf40 - 0x50a820 = 0x2720`.
2. **Ekstraksi Peta & Rekonstruksi Glyph:**
   - Membaca 10 blok memori berukuran 10.000 byte dari biner.
   - Setiap lantai memuat representasi huruf ASCII art yang digambar menggunakan karakter `#` dan dinding pembatas:
     - Lantai 1: `academy{`
     - Lantai 2: `ur_4_w1z4rd_`
     - Lantai 3: `4`
     - Lantai 4: `c`
     - Lantai 5: `a`
     - Lantai 6: `9`
     - Lantai 7: `0`
     - Lantai 8: `4`
     - Lantai 9: `9`
     - Lantai 10: `2}`
3. **Penggabungan Token & Validasi:**
   - Hasil penggabungan seluruh karakter menghasilkan string utuh: `academy{ur_4_w1z4rd_4ca90492}`.
   - Flag diverifikasi secara langsung ke endpoint REST API CyLab `POST /api/submissions/`.

---

## Flag & Verifikasi

- **Flag:** `academy{ur_4_w1z4rd_4ca90492}`
- **Bukti Validasi:** REST API CyLab merespons dengan HTTP Status 201 Created:
  ```json
  {"user": 1072359, "challenge": 318, "flag": "academy{ur_4_w1z4rd_4ca90492}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Prinsip Validasi Server-Side:** Pada arsitektur perangkat lunak berbasis verifikasi misi atau permainan, *game state* dan aset rahasia tidak boleh disimpan secara statis di memori biner klien jika integritasnya bernilai kritis. Evaluasi progres harus divalidasi oleh otoritas terpercaya (server-side).
- **Hardening & Obfuscation:** Bila data harus disimpan di sisi klien, gunakan enkripsi tingkat aplikasi dengan kunci yang diturunkan secara dinamis saat *runtime* setelah verifikasi kondisi integritas tercapai.
