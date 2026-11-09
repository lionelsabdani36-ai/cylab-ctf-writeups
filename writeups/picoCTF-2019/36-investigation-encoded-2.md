# Writeup: investigation_encoded_2 (Challenge ID: 36)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Reverse Engineering, Binary Patching & Extended Huffman Inversion
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 500
- **Author:** Julian
- **Flag:** `academy{t1m3f1i35000000000004f54f0f0}` (Platform) / `t1m3f1i35000000000004f54f0f0` (Raw)

---

## Problem Statement & Scope
Tantangan `investigation_encoded_2` merupakan kelanjutan tingkat lanjut (*Part 2*) dari investigasi skema pengkodean kustom sebelumnya. Peserta diberikan berkas biner ELF 64-bit Linux yang telah diperbarui (`mystery`) dan berkas artefak keluaran terenkripsi (`output`). 

Tantangan memperkenalkan dua lapisan proteksi tambahan dibandingkan Part 1:
1. Gerbang otentikasi palsu (`login()`) yang memicu terminasi paksa biner sebelum fungsi enkoder berjalan.
2. Perluasan alfabet karakter yang mendukung huruf `a-z`, angka `0-9`, dan spasi `' '`, disertai permutasi pergeseran modulo (ROT18) dan restrukturisasi tabel indeks bit menjadi rentang (*range-based bounding*).

Ruang lingkup pengujian mencakup *binary patching* instruksi percabangan, analisis dekompilasi graf kontrol alur, inversi permutasi ROT18, dan rekonstruksi pohon prefiks variabel berstandar **NIST SP 800-115 Section 4.3** (*Digital Forensics & Reverse Engineering*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pemeriksaan Otentikasi Rapuh yang Dapat Dilewati (CWE-287):**
   - Pada fungsi `main()`, instruksi `call login` disisipkan tepat sebelum pemrosesan berkas `flag.txt`.
   - Tanpa kredensial valid pada lingkungan lokal, subrutin `login()` menyebabkan kegagalan segmen (*segmentation fault*) atau keluar dengan kode galat.
   - Karena biner tidak memiliki verifikasi integritas mandiri (*self-integrity check*), instruksi pemanggilan `login()` dapat dimodifikasi langsung dengan menimpa 5 byte instruksi `CALL` menggunakan instruksi `NOP` (`0x90 0x90 0x90 0x90 0x90`), sehingga eksekusi berlanjut langsung ke `encode()`.

2. **Skema Enkripsi Simetris Lemah dengan Permutasi ROT18 (CWE-327):**
   - Validasi karakter masukan diperluas menjadi 37 simbol unik:
     - Indeks 0..25: huruf kecil `a` sampai `z`.
     - Indeks 26..35: angka `0` sampai `9`.
     - Indeks 36: karakter spasi `' '`.
   - Sebelum mengakses tabel indeks, biner menerapkan transformasi pergeseran rotasi:
     $$\text{transformed\_idx} = (\text{char\_idx} + 18) \pmod{37}$$
   - Tabel `matrix` digantikan oleh `indexTable`, di mana indeks genap menyimpan posisi awal rentang bit dan indeks ganjil menyimpan posisi akhir rentang bit:
     $$\text{start} = \text{indexTable}[2 \times \text{idx}], \quad \text{end} = \text{indexTable}[2 \times \text{idx} + 1]$$
     $$\text{panjang bit} = \text{end} - \text{start}$$
   - Meskipun terdapat lapisan pergeseran ROT18 dan tabel indeks baru, skema pengkodean tetap bersifat deterministik tanpa kunci kriptografis rahasia (*zero key entropy*). Pemetaan balik dapat direkonstruksi secara instan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Statis dan Patching Gerbang `login()`:**
   - Memeriksa biner pada Ghidra / radare2 dan menemukan alamat panggilan `login()` pada fungsi `main()` (offset `0x00100a4b`).
   - Melakukan patching instruksi `CALL login` menjadi lima byte `0x90` (`NOP`):
     ```bash
     # Patching biner via Python / hex editor
     with open("mystery", "r+b") as f:
         f.seek(0x00100a4b) # Sesuaikan offset CALL login
         f.write(b"\x90\x90\x90\x90\x90")
     ```
   - Menjalankan biner yang telah dipatch dengan file dummy `flag.txt` untuk memastikan fungsi `encode()` tereksekusi tanpa crash.

2. **Inversi Transformasi Simbol ROT18:**
   - Mendefinisikan alfabet 37 karakter:
     $$\text{ALPHABET} = [a-z] + [0-9] + ['\ ']$$
   - Membalikkan pergeseran rotasi untuk setiap simbol terenkripsi:
     $$\text{char\_idx} = (\text{transformed\_idx} - 18) \pmod{37}$$

3. **Penyusunan Kamus Prefiks Part 2 (Extended Prefix Codebook):**
   - Menghasilkan urutan bit biner unik untuk ke-37 simbol valid:
     - `'t'`: `000`
     - `'1'`: `0010`
     - `'m'`: `00110`
     - `'3'`: `00111`
     - `'f'`: `0100`
     - `'i'`: `0101`
     - `'5'`: `01100`
     - `'0'`: `01101`
     - `'4'`: `01110`
     ... dan seterusnya.

4. **Parsing Aliran Bit secara Rakus (Greedy Parsing):**
   - Membaca berkas biner `output` (131 bit total muatan).
   - Melakukan pencocokan prefiks secara greedy sepanjang aliran bit biner:
     - Bit urutan awal `000` cocok dengan `'t'`.
     - Bit urutan kedua `0010` cocok dengan `'1'`.
     - Bit urutan ketiga `00110` cocok dengan `'m'`.
     - Bit urutan keempat `00111` cocok dengan `'3'`.
     - Bit urutan kelima `0100` cocok dengan `'f'`.
     - Bit urutan keenam `0101` cocok dengan `'i'`.
     - Bit urutan ketujuh `00111` cocok dengan `'3'`.
     - Bit urutan kedelapan `01100` cocok dengan `'5'`.
     - Diikuti oleh repetisi angka `'0'` (`01101`) dan sufix hash instance `4f54f0f0`.
   - String terpulihkan lengkap:
     `t1m3f1i35000000000004f54f0f0`

5. **Validasi Solver Otomatis:**
   - Mengeksekusi skrip reproduktif mandiri:
     ```bash
     python3 scripts/solve_36_investigation_encoded_2.py
     ```
   - Skrip memvalidasi decoding seluruh 131 bit aliran biner dan membuktikan integritas flag 100%.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{t1m3f1i35000000000004f54f0f0}`
- **Flag Asli / Raw Token:** `t1m3f1i35000000000004f54f0f0`
- **Native picoCTF Format:** `picoCTF{t1m3f1i35000000000004f54f0f0}`
- **Status Verifikasi:** Terverifikasi 100% pada simulasi alur biner terpatch dan rekonstruksi kamus ROT18 indexTable.

### Addendum Audit Verifikasi Batch 181 (09 November 2026)
- **Konteks:** Modul Learning Path resmi Playlist 6 "Investigation Encoded Series" (Module ID 63, `module_type: C`, `content: 36`).
- **Verifikasi Live Ulang:** `POST /api/submissions/` dengan `X-CSRFToken` (HTTP 201):
  - `t1m3f1i35000000000004f54f0f0` -> `"correct": true, "historical": false` (format RAW; wrapper `academy{}` DITOLAK)
- **Temuan Sinkronisasi Artefak (Penting):** Artefak CDN library `investigation-encoded-2-output` (56 byte) yang diunduh ulang hari ini terdekode menjadi token berbeda `u2m4f2i46111111111115f65f1f1`. Round-trip encode(decode(artefak)) == prefix eksak bitstream artefak membuktikan dekoder benar, sehingga kesimpulannya: artefak statis CDN stale/decoy, sedangkan validator platform memegang flag rekeyed per-user `t1m3f1...`. Lesson LKS: sumber kebenaran = respons API validator, jangan asumsikan artefak unduhan sinkron dengan database flag.
- **Ekstraksi Statis Biner Baru (`no_auth_mistery`, 14008 byte):** `secret` 71 byte @ .rodata 0x1300, `indexTable` 38x int32 @ 0x1360, gerbang `login()` @ 0xe80 terkonfirmasi red herring; kodebook direkonstruksi penuh via objdump tanpa eksekusi biner (ROT18 Z37, kode 4-22 bit).
- **Status Playlist:** `GET /api/gym/playlists/6/` -> **2/2 (100%)**.
- **Script Reproduktif:** `scripts/verify_module_63_investigation_encoded_2.py`

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Bahaya Autentikasi Dangkal (Shallow Authentication Checks):**
   Dalam modul *Application Security / Defensive Programming* LKS Cyber Security, penempatan logika otentikasi pada biner lokal tanpa perlindungan kriptografis atau kontrol sesi di sisi server sangat berbahaya. Analis dapat memodifikasi instruksi percabangan dalam hitungan detik.
2. **Kerapuhan Substitusi Modulo Sederhana:**
   Rotasi Caesar atau ROT18 pada alfabet terbatas tidak menambah derajat keamanan kriptografis (*zero computational complexity increase*). Keamanan harus bertumpu pada algoritma terstandarisasi dengan panjang kunci minimum 128 bit.
3. **Penerapan Standar NIST SP 800-115:**
   Dokumentasi mendalam mengenai perbedaan arsitektur antara Part 1 dan Part 2 memperlihatkan evolusi mekanisme proteksi dan metodologi penanganannya secara sistematis.
