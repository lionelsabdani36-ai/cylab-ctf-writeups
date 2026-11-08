# Writeup: Autorev 1 (Challenge ID: 754)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Procedural Disassembly & Automated Analysis (NIST SP 800-115 §5)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** CyLab Engineering Team
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{4u7o_r3v_g0_brrr_78c345aa}`
- **Flag Komunitas:** `CTF{4u7o_r3v_g0_brrr_78c345aa}`

---

## Problem Statement & Scope

Tantangan menguji kecepatan analisis rekayasa balik (reverse engineering speedrun) pada biner yang dihasilkan secara otomatis:
> *"You think you can reverse engineer? Let's test out your speed."*

Peserta diberikan tantangan berbasis instans container on-demand atau biner ELF 64-bit yang dihasilkan melalui pipeline prosedural. Tujuan evaluasi adalah mengidentifikasi alur verifikasi internal, mengekstraksi token otentikasi secara deterministik, dan memverifikasi token terhadap endpoint resmi platform CyLab Security Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Procedural Logic Generation & Static Reversibility (CWE-656):**
   - Dalam lingkungan CTF dan sistem otomasi verifikasi, biner yang dibuat melalui generator prosedural sering kali berfokus pada variasi logika percabangan permukaan tanpa menyertakan mekanisme pengaburan (*obfuscation*) yang mendalam.
   - Meskipun alur percabangan dibuat banyak, data sensitif (seperti konstanta komparasi, format token, atau substring kunci) sering kali dibiarkan dalam bentuk plaintext atau penyandian sederhana di segmen `.rodata` maupun immediate operands instruksi mesin pada segmen `.text`.

2. **Ketiadaan Proteksi Anti-Analisis (Anti-Debugging & Anti-Tampering Omission):**
   - Biner tidak menerapkan teknik deteksi ptrace (`PTRACE_TRACEME`), inspeksi breakpoint software (`int3`), integritas hash kode, ataupun pengemasan executable (seperti UPX berproteksi atau VM protector).
   - Akibatnya, biner sepenuhnya rentan terhadap analisis statis otomatis melalui pencarian pola regular expression (*pattern scanning*) dan pembongkaran kode simbolik (*symbolic disassembly*).

3. **Prinsip Evaluasi Biner NIST SP 800-115 §5 (Binary Analysis & Code Review):**
   - Standar NIST SP 800-115 merekomendasikan pendekatan analisis statis terlebih dahulu sebelum melakukan instrumentasi dinamis. Jika rahasia sistem dapat diidentifikasi secara statis tanpa eksekusi, risiko dan waktu pengujian berkurang secara signifikan, membuktikan kegagalan kontrol kerahasiaan data dalam biner terdistribusi.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Header & Format Executable:**
   - Memeriksa struktur biner target dengan perintah `file`:
     ```bash
     file autorev1
     # autorev1: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked
     ```

2. **Pencarian Pola Memori Statis (Pattern Scanning):**
   - Menggunakan pemindaian pola regex untuk mendeteksi keberadaan format flag standar picoCTF/CyLab:
     ```python
     import re

     with open("autorev1", "rb") as f:
         data = f.read()

     matches = re.findall(rb'(picoCTF|academy)\{[a-zA-Z0-9_]+\}', data)
     for m in matches:
         print(m.decode())
     ```
   - Pola token yang teridentifikasi: `academy{4u7o_r3v_g0_brrr_78c345aa}`.

3. **Verifikasi Logika Komparasi:**
   - Melakukan cross-reference alamat instruksi pembanding menggunakan `objdump -d -M intel`:
     - Menemukan blok komparasi karakter yang memvalidasi string input terhadap rangkaian byte `4u7o_r3v_g0_brrr_78c345aa`.
     - Validasi bersifat deterministik tanpa ketergantungan pada status acak sistem atau waktu.

4. **Eksekusi Otomasi Solver:**
   - Menjalankan skrip otomasi `scripts/solve_754_autorev_1.py` yang mengekstrak token dan memvalidasi ke REST API CyLab.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{4u7o_r3v_g0_brrr_78c345aa}`
- **Format Flag Komunitas:** `CTF{4u7o_r3v_g0_brrr_78c345aa}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 754, "flag": "academy{4u7o_r3v_g0_brrr_78c345aa}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Penghapusan Simbol & Metadata (Binary Stripping):**
   - Dalam pipeline CI/CD produksi, seluruh biner wajib dibersihkan dari informasi debugging dan simbol fungsi menggunakan `strip --strip-all` untuk menyulitkan pemetaan logika aplikasi.

2. **Penggunaan String Encryption & Control Flow Obfuscation (CWE-656 Remediation):**
   - Jangan pernah menyematkan rahasia atau kunci lisensi dalam bentuk string statis pada biner.
   - Terapkan enkripsi string saat kompilasi (misalnya menggunakan template metaprogramming C++ atau LLVM obfuscator pass) sehingga string hanya didekripsi secara transien di memori runtime saat dibutuhkan.

3. **Validasi Sisi Server (Server-Side Authentication Enclave):**
   - Kunci lisensi, token otentikasi, dan logika hak akses kritis harus diverifikasi pada server aman, bukan mengandalkan pengecekan lokal di sisi klien yang selalu dapat dibongkar penyerang.

---

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)

- **David (Leader):** Mengarahkan strategi reverse engineering kecepatan tinggi dan memvalidasi kepatuhan dokumentasi NIST SP 800-115.
- **Charlie (Trend-hunter):** Mengidentifikasi pola tantangan automated speedrun reverse engineering pada kompetisi keamanan siber modern.
- **Alex (Fullstack-dev) & Omnirush (Coding Agent):** Mengembangkan modul ekstraksi biner prosedural dan pipeline submit token REST API.
- **Julius (QA-engineer):** Menguji ketahanan skrip solver terhadap biner varian serta memverifikasi status HTTP 201 CyLab.
- **Athena (Security-engineer):** Meninjau implikasi kelemahan CWE-656 dan merekomendasikan kontrol pengerasan biner kompilasi.
- **Judith (Guru LKS):** Merangkum teknik ekstraksi pola biner cepat ke dalam materi pembekalan peserta lomba LKS Cyber Security.
