# Writeup: Piece by Piece (Challenge ID: 740)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Multi-Part File Carving, Split Archives & Passphrase Decompression (NIST SP 800-115 §4.4)
- **Difficulty:** Easy (1)
- **Points:** 50
- **Author:** Yahaya Meddy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{z1p_and_spl1t_f1l3s_4r3_fun_6af185ac}`
- **Flag Komunitas:** `CTF{z1p_and_spl1t_f1l3s_4r3_fun_6af185ac}`
- **Standar Referensi:** NIST SP 800-115 §4.4 (System and Application Security Testing), PKWARE .ZIP File Format Specification (APPNOTE.TXT), RFC 1951 (DEFLATE Compressed Data Format Specification), POSIX.1-2017 Utility Definitions (split, cat, and shell byte streams), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), & OWASP ASVS V8 (Data Protection & Storage Cryptography).

---

## Problem Statement & Scope
Pada tantangan `Piece by Piece`, peserta diberikan akses akun unprivileged melalui protokol SSH (`ctf-player@xebec.cylabacademy.net`) ke lingkungan container Linux:
- Struktur direktori: Direktori kerja pengguna memuat berkas petunjuk `instructions.txt` serta lima berkas biner terpisah: `part_aa`, `part_ab`, `part_ac`, `part_ad`, dan `part_ae`.
- Batasan tantangan: Berkas terenkripsi atau terfragmentasi tidak dapat diekstrak secara langsung per fragmen menggunakan utilitas zip konvensional.
- Sasaran pengujian: Mengidentifikasi tanda tangan biner (magic bytes) format kontainer arsip terkompresi, merekonstruksi aliran byte utuh secara sekuensial mengikuti spesifikasi POSIX stream, mendekripsi payload terproteksi sandi, dan membaca token verifikasi resmi dari `flag.txt`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Struktur Arsip PKWARE ZIP & Lokasi Magic Bytes (APPNOTE.TXT)
Format arsip PKZIP memiliki struktur record terdistribusi:
- Setiap entri berkas dimulai dengan header berkas lokal (*Local File Header*) dengan magic bytes `0x50 0x4B 0x03 0x04` (`PK\x03\x04`).
- Struktur direktori pusat (*Central Directory*) dan penanda akhir direktori (*End of Central Directory Record* / EOCD) dengan magic bytes `0x50 0x4B 0x05 0x06` (`PK\x05\x06`) diletakkan di bagian paling akhir berkas arsip.
Ketika sebuah berkas arsip dipotong-potong menggunakan utilitas `split` tingkat sistem operasi berbasis ukuran byte tetap:
```bash
split -b <size> combined.zip part_
```
Struktur format internal ZIP tidak dimodifikasi, melainkan hanya dipartisi secara fisik. Fragmen pertama (`part_aa`) menyimpan magic bytes awal, sementara fragmen terakhir (`part_ae`) memegang record EOCD. Upaya mengekstrak fragmen individual secara parsial akan gagal dengan kesalahan `BadZipFile` atau korupsi CRC karena parser ZIP kehilangan metadata direktori sentral.

### 2. Sifat Invariansi Aliran Byte POSIX (POSIX Stream Invariance)
Standar POSIX menetapkan bahwa utilitas `cat` melakukan penggabungan aliran byte linier tanpa menyisipkan header atau mengubah isi representasi memori:
$$\text{Arsip Asli} = \text{part\_aa} \mathbin{\Vert} \text{part\_ab} \mathbin{\Vert} \text{part\_ac} \mathbin{\Vert} \text{part\_ad} \mathbin{\Vert} \text{part\_ae}$$
Karena penamaan sufiks hasil utilitas `split` mengikuti urutan leksikografis alfabetik (`aa` hingga `az`), ekspresi ekspansi shell POSIX `part_*` atau `part_a[a-e]` menghasilkan urutan rekombinasi deterministik yang persis memulihkan integritas offset tabel kompresi DEFLATE (RFC 1951).

### 3. Kelemahan Penyimpanan Sandi Statis dalam Teks Terbuka (CWE-200)
Meskipun arsip ZIP dilindungi dengan kata sandi, berkas manifest `instructions.txt` yang berada pada lingkungan yang sama memuat kata sandi simetris dalam bentuk teks terbuka (*plaintext*): `supersecret`. Hal ini menunjukkan kelemahan manajemen rahasia (*hardcoded/exposed credential*), di mana proteksi kriptografis menjadi hampa karena material kunci berada dalam batas kepercayaan (*trust boundary*) yang dapat diakses oleh subjek penguji.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Autentikasi SSH & Investigasi Direktori Kerja
Koneksi SSH dibuka ke instance lab:
```bash
sshpass -p "<password>" ssh -p <port> ctf-player@xebec.cylabacademy.net
```
Daftar berkas menampilkan:
```text
-rw-r--r-- 1 ctf-player ctf-player   74 instructions.txt
-rw-r--r-- 1 ctf-player ctf-player  100 part_aa
-rw-r--r-- 1 ctf-player ctf-player  100 part_ab
-rw-r--r-- 1 ctf-player ctf-player  100 part_ac
-rw-r--r-- 1 ctf-player ctf-player  100 part_ad
-rw-r--r-- 1 ctf-player ctf-player   96 part_ae
```

### Langkah 2: Analisis Magic Bytes Berkas Fragmen
Pemeriksaan header byte menggunakan perintah `xxd` atau `hexdump`:
```bash
head -c 4 part_aa | xxd
# Output: 00000000: 504b 0304                             PK..
```
Nilai `0x50 0x4B 0x03 0x04` mengonfirmasi bahwa berkas induk adalah arsip PKZIP.

### Langkah 3: Rekombinasi Aliran Byte & Dekompresi
Seluruh fragmen digabungkan kembali sesuai urutan alfabetis:
```bash
cat part_aa part_ab part_ac part_ad part_ae > combined.zip
```
Berkas `instructions.txt` menginstruksikan kata sandi dekompresi `supersecret`. Arsip diekstrak menggunakan perintah `unzip`:
```bash
unzip -P supersecret combined.zip
```
Proses menghasilkan ekstraksi berkas `flag.txt`:
```bash
cat flag.txt
# Output: academy{z1p_and_spl1t_f1l3s_4r3_fun_6af185ac}
```

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{z1p_and_spl1t_f1l3s_4r3_fun_6af185ac}`
- **Flag Format Komunitas:** `CTF{z1p_and_spl1t_f1l3s_4r3_fun_6af185ac}`
- **Verifikasi Live REST API CyLab:**
  Submisi ke `https://learn.cylabacademy.org/api/submissions/` mengembalikan respons status HTTP 201:
  `{"user": 1072359, "challenge": 740, "flag": "academy{z1p_and_spl1t_f1l3s_4r3_fun_6af185ac}", "correct": true, "historical": false}`.
- **Verifikasi Simulasi Offline:** Skrip `scripts/solve_740_piece_by_piece.py` memvalidasi komponen `PieceByPieceSimulator` untuk menguji rekonstruksi aliran byte dan parsing struktur ZIP secara mandiri sesuai NIST SP 800-115.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. File Carving & Stream Reconstruction dalam Forensik Siber LKS
Dalam skenario insiden respon dan investigasi forensik digital LKS Cyber Security:
- Penyerang atau saluran transmisi data sering kali memecah berkas biner eksfiltrasi menjadi paket-paket kecil untuk menghindari sensor Network Intrusion Detection System (NIDS) atau batasan payload email/HTTP.
- Analis wajib mengidentifikasi tanda tangan struktur berkas (seperti Local Header dan EOCD pada ZIP, SOI/EOI pada JPEG, atau header tar/gzip) dan mampu menyusun ulang aliran byte mentah tanpa bergantung pada ekstensi berkas.

### 2. Manajemen Kunci dan Pemisahan Media Kredensial
Menyimpan kata sandi dekripsi di samping berkas data terenkripsi melanggar prinsip dasar pertahanan mendalam (*defense-in-depth*). Kunci enkripsi harus dikelola melalui media terpisah (*out-of-band*), *Key Management Service* (KMS), atau *Hardware Security Module* (HSM).

### 3. Integritas Data & Verifikasi Hash Kriptografis
Setiap proses fragmentasi berkas skala besar harus disertai dengan *checksum* kriptografis (misalnya SHA-256 manifest) untuk memastikan setiap fragmen tidak mengalami kerusakan atau manipulasi bit selama transit.
