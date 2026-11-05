# Writeup: Lookey here (Challenge ID: 279)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Text Carving & Pattern Matching
- **Difficulty:** Medium (diff=2)
- **Author:** LT 'syreal' Jones / Mubarak Mikail
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{gr3p_15_@w3s0m3_33595e98}`

---

## Problem Statement & Scope

Tantangan menguji teknik pencarian pola dan ekstraksi artefak teks pada korpus data besar:
> *"Attackers have hidden information in a very large mass of data in the past, maybe they are still doing it. Download the data and search for the flag based on the known prefix."*

Peserta diberikan berkas teks `anthem.flag.txt` berukuran ~108 KB yang memuat 2,146 baris teks novel. Tujuan modul adalah mengasah efisiensi inspeksi forensik teks (*text carving*) menggunakan utilitas ekspresi reguler tanpa melakukan pembacaan manual.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Analisis Forensik Teks Sesuai NIST SP 800-115:**
   - Dalam investigasi forensik insiden siber (NIST SP 800-86 dan SP 800-115 Section 5.3), analis sering berhadapan dengan tumpukan log berukuran puluhan hingga ratusan megabyte.
   - Teknik penyembunyian data di antara tumpukan teks sah (*hiding in plain sight / needle in a haystack*) adalah taktik umum untuk menyamarkan token eksfiltrasi atau artefak muatan berbahaya.
   - Pemanfaatan algoritma pencarian ekspresi reguler (Boyer-Moore / DFA pada POSIX `grep`) memproses pencarian dalam kompleksitas waktu linier $O(N)$ terhadap total panjang karakter.

2. **Keterbukaan Pola Token Tanpa Enkripsi (CWE-312 & CWE-200):**
   - Meskipun token disisipkan di antara ribuan baris teks acak, token mempertahankan pola format wrapper standar (`academy{...}`).
   - Karena tidak adanya lapisan transformasi kriptografis atau pemecahan bit (*fragmentation*), integritas token dapat diekstraksi secara deterministik dengan satu ekspresi reguler tunggal.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Artefak Berkas:**
   Unduh berkas korpus dari repositori CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/1e5b915df467718ade9bc65b9de2094f73159c40c620fbea7bfec17f657252b3/anthem.flag.txt
   ```

2. **Inspeksi Karakteristik Korpus:**
   Hitung volume baris dan karakter:
   ```bash
   wc -l anthem.flag.txt
   wc -c anthem.flag.txt
   ```
   Keluaran:
   ```text
   2146 anthem.flag.txt
   107994 anthem.flag.txt
   ```

3. **Pencarian Pola Token via `grep`:**
   Jalankan ekspresi reguler pencarian awalan token:
   ```bash
   grep -E "academy\{[^\}]+\}" anthem.flag.txt
   ```
   Atau cukup dengan mencocokkan pola awalan:
   ```bash
   grep "academy{" anthem.flag.txt
   ```
   Keluaran menampilkan baris paragraf yang memuat token:
   ```text
   we think that the men of the City were not foolish. academy{gr3p_15_@w3s0m3_33595e98}
   ```

4. **Ekstraksi Token Bersih:**
   ```bash
   grep -o -E "academy\{[^\}]+\}" anthem.flag.txt
   ```
   Keluaran:
   ```text
   academy{gr3p_15_@w3s0m3_33595e98}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{gr3p_15_@w3s0m3_33595e98}`
- **Verifikasi API Platform:** Validasi token melalui endpoint `POST /api/submissions/` menghasilkan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 279, "flag": "academy{gr3p_15_@w3s0m3_33595e98}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi Inti LKS Cyber Security:** Dalam modul respons insiden dan forensik, peserta wajib menguasai utilitas manipulasi teks CLI (`grep`, `awk`, `sed`, `ripgrep`). Memfilter jejak penyerang, alamat IP jahat, atau flag kompetisi di dalam berkas dump memori/log raksasa adalah keterampilan dasar penentu kecepatan penyelesaian.
- **Mitigasi Defensif (Data Loss Prevention & Masking):**
  1. *Penerapan DLP (Data Loss Prevention):* Organisasi harus memindai saluran keluar (*egress traffic*) dan repositori dokumen untuk mendeteksi keberadaan pola token sensitif (API key, NIK, nomor kartu kredit) menggunakan aturan regex terdefinisi.
  2. *Audit Log Sanitization:* Pastikan fungsi pencatatan log aplikasi menerapkan mekanisme redaksi otomatis terhadap payload parameter sensitif agar tidak terekspos dalam teks terbuka di log server.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_279_lookey_here.py`.
