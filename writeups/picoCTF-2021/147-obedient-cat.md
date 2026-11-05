# Writeup: Obedient Cat (Challenge ID: 147)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Standard I/O Stream & File Concatenation
- **Difficulty:** Easy (diff=1)
- **Author:** syreal
- **Event:** picoCTF 2021
- **Points:** 5
- **Flag:** `academy{s4n1ty_v3r1f13d_61ddac22}`

---

## Problem Statement & Scope

Diberikan sebuah berkas teks biasa (*in-the-clear file*) bernama `flag`. Deskripsi tantangan menyatakan: *"This file has a flag in plain sight (aka 'in-the-clear')"*.

Tantangan sanity-check ini mengevaluasi keterampilan fundamental navigasi baris perintah sistem operasi Linux, pengunduhan berkas jaringan (`wget` / `curl`), pembacaan dokumen manual (`man`), serta pemanfaatan utilitas standar stream I/O POSIX (`cat`) untuk membaca isi berkas ke terminal.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Standar POSIX Stream I/O & Utilitas `cat` (IEEE Std 1003.1):**
   - Utilitas `cat` (*concatenate*) membaca berkas yang diberikan secara sekuensial dan meneruskan isinya ke *standard output* (`stdout`).
   - Merupakan salah satu utilitas paling esensial dalam lingkungan Unix-like untuk inspeksi cepat konfigurasi sistem, log, dan berkas artefak selama fase *information gathering* (NIST SP 800-115).
2. **Ketiadaan Enkripsi & Akses Kontrol Teks Bebas (CWE-312 / CWE-732):**
   - Berkas `flag` disimpan dalam bentuk teks polos (*plaintext*) tanpa kontrol akses berbasis peran (RBAC) atau enkripsi pada media penyimpanan (*at-rest encryption*).
   - Setiap pengguna dengan izin baca (*read permission*, `r`) pada sistem berkas dapat membaca rahasia tersebut tanpa tantangan autentikasi tambahan.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Berkas Target:**
   Unduh artefak lab langsung ke lingkungan kerja menggunakan utilitas `wget`:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/11b9e730524b026e2bce9e561dad9e8f1905b575e3fc6a1477eb1698b59e6585/flag
   ```
2. **Pemeriksaan Tipe Berkas:**
   Verifikasi arsitektur/encoding berkas target:
   ```bash
   file flag
   ```
   Keluaran menunjukkan: `flag: ASCII text`.
3. **Membaca Isi Berkas Menggunakan Utilitas `cat`:**
   Cetak seluruh isi berkas ke layar:
   ```bash
   cat flag
   ```
   Terminal menampilkan flag resmi:
   ```text
   academy{s4n1ty_v3r1f13d_61ddac22}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{s4n1ty_v3r1f13d_61ddac22}`
- **Verifikasi API:** Validasi token pada endpoint `POST /api/submissions/` mengembalikan `{"correct": true, "challenge": 147}` (Status HTTP 201 Created).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Fundamental Sanitasi Shell (LKS Linux Administration):** Dalam perlombaan LKS Cyber Security, kemampuan cepat mengoperasikan command-line interface (CLI), membaca manual page (`man cat`), dan memanipulasi pipe/redirection merupakan prasyarat mutlak untuk modul Server Hardening dan Incident Response.
- **Prinsip Least Privilege & Enkripsi Data Sensitif:**
  - File yang memuat kredensial, token akses, atau kunci rahasia wajib memiliki restriksi hak akses ketat (misalnya `chmod 600` atau `chown root:root`).
  - Data kredensial tidak boleh dibiarkan dalam kondisi *plaintext* di dalam direktori publik atau repositori bersama (NIST SP 800-88 / SP 800-123).

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_147_obedient_cat.py` untuk mengunduh dan membaca flag secara terprogram.
