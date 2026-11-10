# Writeup: GDB Test Drive (Challenge ID: 273)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Dynamic Debugging & Instruction Flow Control (CWE-215 / NIST SP 800-115 § 4.3)
- **Difficulty:** Medium (diff=2)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{d3bugg3r_dr1v3_4cc75120}`

---

## Problem Statement & Scope

Tantangan menyajikan sebuah berkas biner ELF 64-bit Linux (`gdbme`):
> *"Can you get the flag? Download this binary. Here's the test drive instructions: `$ chmod +x gdbme`, `$ gdb gdbme`, `(gdb) layout asm`, `(gdb) break *(main+99)`, `(gdb) run`, `(gdb) jump *(main+104)`"*

Spesifikasi lingkungan:
- Format berkas: ELF 64-bit LSB PIE executable, x86-64, dynamically linked, not stripped.
- Program dirancang dengan penundaan eksekusi buatan (*sleep stall*) bernilai besar sehingga tidak akan selesai berjalan dalam durasi normal.
- Peserta diminta mempraktikkan navigasi instruksi tingkat rendah menggunakan GNU Debugger (GDB) guna mengalihkan alur eksekusi (*instruction pointer manipulation*) melewati instruksi penunda (*sleep*) sehingga string flag dicetak ke *stdout*.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Dynamic Execution Flow Control ($rip Manipulation):**
   - Biner kompilasi x86_64 mengeksekusi instruksi secara linier berdasarkan register penunjuk instruksi (`$rip`).
   - Pada fungsi `main`, program memuat nilai konstanta besar (`0x186a0` = 100.000 detik) ke register argumen `$edi` kemudian memanggil fungsi `sleep()` pada alamat offset `main+99`.
   - Tanpa intervensi, proses akan terhenti (*sleep stall*) selama lebih dari 27 jam.

2. **Manipulasi Register Instruksi via Ptrace Debugging:**
   - Fasilitas debugging `ptrace` pada kernel Linux memungkinkan inspeksi memori, breakpoint penyelaan, dan manipulasi register thread proses.
   - Dengan menyetel breakpoint tepat di `*(main+99)` sebelum instruksi `call sleep@plt`, analis dapat menghentikan proses sebelum masuk ke panggilan sistem penunda.
   - Perintah `jump *(main+104)` pada GDB secara atomik memperbarui register `$rip` ke alamat offset `main+104`, melompati panggilan `sleep` seutuhnya.

3. **Dekripsi Statis & Algoritma ROT47 (Dual Path Verification):**
   - Analisis disasembli fungsi `rotate_encrypt` mengungkap bahwa algoritma transformasi adalah subtitusi simetris ROT47:
     Untuk setiap bita karakter $b \in [33, 126]$:
     $$b' = \begin{cases} b + 47 - 94, & \text{jika } b + 47 > 126 \\ b + 47, & \text{lainnya} \end{cases}$$
   - Empat nilai konstanta 64-bit little-endian yang dialokasikan pada stack slot `[rbp-0x30]` hingga `[rbp-0x18]` adalah:
     `0x4C4A3E3635323432`, `0x4362383846336235`, `0x6330624760433530`, `0x4E5F616064663434`.
   - Rangkaian bita mentah tersebut (`24256>JL5b3F88bC05C`Gb0c44fd`a_N`) didekripsi menggunakan ROT47 menjadi `academy{d3bugg3r_dr1v3_4cc75120}`.

4. **Kepatuhan NIST SP 800-115 § 4.3 (Binary Analysis & Software Testing):**
   - Standar NIST SP 800-115 menggarisbawahi perlunya analisis dinamis (*dynamic runtime instrumentation*) untuk mengevaluasi alur logika eksekusi perangkat lunak, memvalidasi kontrol aliran, dan mendeteksi fungsi penunda anti-analisis.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Metadata Berkas Biner:**
   ```bash
   file gdbme
   # Output: gdbme: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, not stripped
   ```

2. **Disasembli Fungsi `main` Menggunakan GDB:**
   ```bash
   gdb -batch -ex "disas main" ./gdbme
   ```
   Ditemukan potongan instruksi kontrol alur:
   ```asm
   0x0000000000001325 <+94>:  mov    edi, 0x186a0
   0x000000000000132a <+99>:  call   0x1110 <sleep@plt>
   0x000000000000132f <+104>: lea    rax, [rbp-0x30]
   0x0000000000001333 <+108>: mov    rsi, rax
   0x0000000000001336 <+111>: mov    edi, 0x0
   0x000000000000133b <+116>: call   0x1209 <rotate_encrypt>
   ```

3. **Eksekusi Pengalihan Instruksi Dinamis:**
   Pasang breakpoint di `*(main+99)`, jalankan program, dan langsung lompat ke `*(main+104)`:
   ```bash
   gdb -batch \
       -ex "break *(main+99)" \
       -ex "run" \
       -ex "jump *(main+104)" \
       ./gdbme
   ```
   Keluaran eksekusi:
   ```text
   Breakpoint 1, 0x000055555555532a in main ()
   academy{d3bugg3r_dr1v3_4cc75120}
   ```

4. **Otomasi Mandiri via Skrip Python (`scripts/solve_273_gdb_test_drive.py`):**
   ```bash
   python3 scripts/solve_273_gdb_test_drive.py
   ```
   Keluaran:
   ```text
   [*] Solving Challenge 273: GDB Test Drive
   [*] Stage 1: Inspecting ELF architecture and main disassembly
       [+] Format: ELF 64-bit x86-64 PIE executable (dynamically linked)
       [+] Sleep stall detected: main+94 mov edi, 0x186a0; main+99 call sleep
       [+] Target jump offset  : main+104 (bypasses sleep, enters rotate_encrypt)
   [*] Stage 2: Attempting dynamic instruction pointer diversion via GDB on '/tmp/c273/gdbme'
       [+] GDB diversion succeeded. Recovered: academy{d3bugg3r_dr1v3_4cc75120}
   [+] Reconstructed Flag: academy{d3bugg3r_dr1v3_4cc75120}

   [SUCCESS] Module 273 (GDB Test Drive) fully audited and solved: academy{d3bugg3r_dr1v3_4cc75120}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{d3bugg3r_dr1v3_4cc75120}`
- **Verifikasi API Platform:** Penyerahan token melalui endpoint REST API `POST /api/submissions/` menghasilkan status **HTTP 201 Created**:
  ```json
  {
    "user": 1072359,
    "challenge": 273,
    "flag": "academy{d3bugg3r_dr1v3_4cc75120}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Relevansi Modul LKS Cyber Security (Binary Analysis & Reverse Engineering):**
  - Manipulasi penunjuk instruksi ($rip) adalah teknik dasar penting dalam analisis biner dinamis.
  - Banyak varian sampel malware nyata menggunakan trik sleep delay yang panjang untuk menghindari timeout mesin sandbox otomatis. Analis LKS harus terbiasa mem-bypass sleep stall menggunakan debugger tanpa perlu mengubah biner di media penyimpanan.
- **Remediasi & Mitigasi Defensif Komprehensif:**
  1. **Deteksi Anti-Debugging & Ptrace Check:**
     Terapkan pemanggilan `ptrace(PTRACE_TRACEME, 0, 1, 0)` saat inisialisasi aplikasi untuk mencegah proses dilekatkan oleh debugger eksternal.
  2. **Verifikasi Integritas Alur Eksekusi (Timing & Checksum Verification):**
     Implementasikan pengecekan waktu eksekusi relatif via `rdtsc` atau timer sistem untuk memvalidasi apakah ada lompatan alur kontrol tak terduga.
  3. **Penghilangan Simbol & Pengaburan Kode (Stripping & Obfuscation):**
     Hapus seluruh tabel simbol debug (`strip --strip-all`) dan terapkan kontrol alur datar (*control flow flattening*) agar titik fungsi kritis tidak mudah diidentifikasi.
