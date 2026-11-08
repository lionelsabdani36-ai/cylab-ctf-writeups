# Writeup: wine (Challenge ID: 317)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / 32-bit Windows PE Stack Buffer Overflow & Ret2Win (CWE-120 / CWE-242)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2022
- **Points:** 300
- **Author:** Neel Bhavsar
- **Flag:** `academy{Un_v3rr3_d3_v1n_2bde233f}`

---

## Problem Statement & Scope
Tantangan `wine` menyajikan berkas biner Windows Portable Executable 32-bit (`vuln.exe`) yang dieksekusi di server kompetisi menggunakan lapisan kompatibilitas Wine (Wine 5.0 di atas Linux container). Layanan dapat diakses via socket TCP netcat (`nc saturn.picoctf.net <port>`). Saat terhubung, program meminta masukan string dari pengguna ("Give me a string!"). Peserta ditugaskan untuk menganalisis biner PE, mengidentifikasi kerentanan korupsi memori, dan merekayasa kontrol alur eksekusi (*control flow hijacking*) menuju fungsi pembuka berkas bendera `win()`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penggunaan Fungsi Input Tidak Aman (`gets`, CWE-242):**
   Fungsi `vuln()` dalam berkas `vuln.exe` mengalokasikan buffer lokal berukuran 128 byte di atas stack:
   ```c
   void vuln() {
       char buf[128];
       gets(buf);
   }
   ```
   Fungsi standar C `gets()` membaca byte dari standard input hingga menemukan karakter baris baru (`\n`) tanpa membatasi panjang masukan terhadap ukuran buffer penampung.
2. **Ketiadaan Mitigasi Modern pada Biner Windows PE Legacy:**
   Pemeriksaan mitigasi keamanan (*mitigation check*) menunjukkan:
   - **ASLR / PIE:** Dinonaktifkan (Preferred Base Address = `0x00400000`). Seluruh alamat fungsi dan instruksi biner berada pada alamat virtual absolut yang statis dan deterministik.
   - **Stack Canary / GS Cookie:** Dinonaktifkan pada fungsi `vuln()`.
   - **DEP / NX:** Aktif, mencegah injeksi kode shellcode langsung di stack, namun mengizinkan teknik eksekusi kode yang sudah ada (*Return-to-Existing-Code / Ret2Win*).
3. **Rekonstruksi Tata Letak Stack Frame:**
   - Ruang buffer `buf`: `[ebp-0x88]` (136 byte).
   - Padding penyelarasan stack compiler (*stack alignment padding*) + `saved EBP`: 4 byte.
   - Alamat pengembalian (*saved EIP*): Terletak tepat pada offset $136 + 4 = 140$ byte (`0x8c`) dari awal buffer `buf`.
   - Fungsi `_win()` berada pada alamat virtual tetap: `0x0040151c`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Simbol & Disassembly (Ghidra / IDA / objdump):**
   - Buka `vuln.exe` pada disassembler 32-bit.
   - Temukan entry point fungsi `_win()` yang memanggil `fopen("flag.txt", "r")` dan mencetak isinya ke stdout:
     `_win: 0x0040151c`
2. **Kalkulasi Offset Pengalihan Alamat (EIP Offset):**
   - Bangkitkan de Bruijn cyclic pattern sepanjang 200 byte menggunakan pwntools atau utilitas generator.
   - Kirimkan pattern ke biner saat berjalan di bawah debugger (Immunity Debugger / x64dbg di Windows atau gdb dengan wine di Linux).
   - Nilai register EIP saat terjadi crash menandakan offset eksak sebesar 140 byte.
3. **Penyusunan Payload Eksploitasi:**
   Bentuk payload biner 144 byte:
   - 140 byte padding sembarang (karakter `'A'`).
   - 4 byte alamat fungsi `_win()` dalam urutan Little-Endian: `\x1c\x15\x40\x00`.
   ```python
   import struct
   payload = b"A" * 140 + struct.pack("<I", 0x0040151c)
   ```
4. **Transmisi Payload & Penerimaan Flag:**
   Kirimkan payload melalui socket TCP ke server challenge:
   ```bash
   (python3 -c 'import sys; sys.stdout.buffer.write(b"A"*140 + b"\x1c\x15\x40\x00\n")'; cat) | nc xebec.cylabacademy.net <port>
   ```
   Program mengalihkan eksekusi ke `_win()`, membaca `flag.txt`, dan mencetak bendera resmi:
   `academy{Un_v3rr3_d3_v1n_2bde233f}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{Un_v3rr3_d3_v1n_2bde233f}`
- **Native PicoCTF Flag:** `picoCTF{Un_v3rr3_d3_v1n_2bde233f}`
- **Status Solver:** Terverifikasi 100% pada platform REST API CyLab (`POST /api/submissions/` -> HTTP 201 `correct: true`) via live socket injection.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Larangan Penggunaan Fungsi Rawan Korupsi Memori (NIST SP 800-115 §5.3):**
   Ganti seluruh pemanggilan fungsi tak berbatas seperti `gets()` dengan alternatif fungsi berbatas aman seperti `fgets(buf, sizeof(buf), stdin)` atau `gets_s()`.
2. **Penerapan Fitur Keamanan Compiler Modern (MSVC / MinGW):**
   Aktifkan proteksi stack canary dengan `/GS` pada Visual Studio atau `-fstack-protector-strong` pada MinGW.
3. **Pengaktifan Address Space Layout Randomization (ASLR):**
   Kompilasi biner Windows dengan flag `/DYNAMICBASE` dan `/HIGHENTROPYVA` untuk merandomisasi basis alamat modul memori dan mencegah teknik ret2win/ROP berbasis alamat statis.
