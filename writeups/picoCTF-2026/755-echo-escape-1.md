# Writeup: Echo Escape 1 (Challenge ID: 755)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Stack-based Buffer Overflow (NIST SP 800-115 §4.2)
- **Difficulty:** Medium (2)
- **Points:** 100
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{3ch0_s3rv1c3_br34k5_7fcd4fec}`
- **Flag Komunitas:** `CTF{3ch0_s3rv1c3_br34k5_7fcd4fec}`

---

## Problem Statement & Scope

Tantangan mendistribusikan berkas biner ELF 64-bit `vuln` beserta kode sumber `vuln.c`. Layanan target berjalan pada server jaringan jarak jauh yang mengeksekusi biner interaktif penerima input teks. Peserta diminta melakukan analisis kerentanan korupsi memori untuk mengalihkan alur eksekusi proses menuju fungsi `win()` yang mencetak flag resmi.

Deskripsi skenario lab:
> *"The 'secure' echo service welcomes you politely… but what if you don’t stay polite? Can you make it reveal the hidden flag?"*

Kode sumber target (`vuln.c`):
```c
#include <stdio.h>
#include <unistd.h>
#include <string.h>

void win() {
    FILE *fp = fopen("flag.txt", "rb");
    if (!fp) {
        perror("[!] Failed to open flag.txt");
        return;
    }

    char buffer[128];
    size_t n = fread(buffer, 1, sizeof(buffer), fp);
    fwrite(buffer, 1, n, stdout);
    fflush(stdout);
    printf("\n");
    fclose(fp);
}

int main() {
    char buf[32]; 

    printf("Welcome to the secure echo service!\n");
    printf("Please enter your name: ");
    fflush(stdout);

    read(0, buf, 128);

    printf("Hello, %s\n", buf);
    printf("Thank you for using our service.\n");

    return 0;
}
```

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Stack-based Buffer Overflow (CWE-121 / CWE-787):**
   - Pada fungsi `main()`, array penyimpan input `char buf[32]` dialokasikan pada stack frame pada offset `[rbp - 0x20]`.
   - Pemanggilan fungsi baca sistem `read(0, buf, 128)` meminta hingga 128 byte dari file descriptor standar input (`stdin`).
   - Karena alokasi buffer hanya sebesar 32 byte, input yang melebihi batas 32 byte akan meluap (overflow) secara berurutan menimpa variabel lokal lain, frame pointer tersimpan (`saved RBP` sebesar 8 byte), dan alamat kembali fungsi (`saved RIP` sebesar 8 byte).

2. **Mitigasi Biner Non-PIE & No Stack Canary:**
   - Analisis header dan atribut keamanan ELF via `checksec`:
     - **Stack Canary:** Tidak aktif (`No Canary found`). Penimpaan saved RIP tidak memicu abort exception (`__stack_chk_fail`).
     - **PIE (Position Independent Executable):** Dinonaktifkan (`No PIE`, base address tetap pada `0x00400000`). Seluruh alamat instruksi dan fungsi bersifat statis.
     - **NX (No-Execute Stack):** Aktif. Shellcode injeksi langsung pada stack tidak dapat dieksekusi, sehingga eksploitasi harus menggunakan teknik pengalihan kontrol instruksi (ret2win / ROP).

3. **Persyaratan Penyelarasan Stack x86_64 ABI (16-Byte Stack Alignment Trap):**
   - Berdasarkan System V AMD64 ABI, sebelum pemanggilan instruksi `call` (termasuk fungsi pustaka GLIBC seperti `printf` dan `fopen` di dalam fungsi `win()`), stack pointer `rsp` wajib selaras pada batas kelipatan 16 byte (`rsp % 16 == 0`).
   - Jika fungsi dipanggil dengan `rsp` tidak selaras (misalnya `rsp % 16 == 8`), instruksi SIMD/SSE (seperti `movaps` yang digunakan compiler gcc untuk optimasi operasi register 128-bit) akan memicu `SIGSEGV` (segmentation fault) fatal.
   - Untuk memenuhi kondisi keselarasan tersebut, gadget perantara `ret` (yang hanya melakukan popping 8 byte dari stack) disisipkan tepat sebelum alamat fungsi `win()`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Kalkulasi Offset Memori Stack:**
   - Kapasitas buffer lokal: 32 byte (`0x20`).
   - Ukuran saved RBP: 8 byte (`0x08`).
   - Jarak offset total menuju saved RIP: $32 + 8 = 40$ byte padding.

2. **Ekstraksi Alamat Simbol Target & ROP Gadget:**
   - Inspeksi disassembly via `objdump -d -M intel vuln`:
     - Alamat entri fungsi `win()`: `0x00401256`.
     - Alamat instruksi tunggal `ret` gadget: `0x0040101a`.

3. **Penyusunan Rantai Payload (Payload Crafting):**
   - Struktur byte:
     ```python
     payload = (
         b"A" * 40 +
         struct.pack("<Q", 0x0040101a) +  # 8 byte ret gadget (16-byte stack alignment)
         struct.pack("<Q", 0x00401256) +  # 8 byte win() address
         b"\n"
     )
     ```
   - Total ukuran payload: 57 byte (jauh di bawah batas 128 byte dari pemanggilan `read`).

4. **Eksekusi Pengujian & Verifikasi Output:**
   - Mengirimkan payload ke biner lokal maupun instans container TCP.
   - Biner membaca payload, mencetak respons sapaan, dan saat `main()` mengeksekusi `ret`, kontrol berpindah ke `0x0040101a` (`ret`), lalu langsung menuju `0x00401256` (`win()`), mencetak isi `flag.txt`.
   - Skrip otomasi reproduktif: `scripts/solve_755_echo_escape_1.py`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{3ch0_s3rv1c3_br34k5_7fcd4fec}`
- **Format Flag Komunitas:** `CTF{3ch0_s3rv1c3_br34k5_7fcd4fec}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 755, "flag": "academy{3ch0_s3rv1c3_br34k5_7fcd4fec}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Validasi Batas Input Panjang Maksimum (CWE-121 Remediation):**
   - Jangan pernah membaca data melebihi kapasitas buffer tujuan.
   - Ganti pemanggilan `read(0, buf, 128)` dengan pembatas ketat sesuai alokasi memori buffer:
     ```c
     read(0, buf, sizeof(buf) - 1);
     buf[sizeof(buf) - 1] = '\0';
     ```

2. **Kepatuhan NIST SP 800-53 SI-16 (Memory Protection):**
   - Wajibkan pengaktifan proteksi Stack Smashing Protector (`-fstack-protector-strong` atau `-fstack-protector-all`) pada pipeline kompilasi untuk mendeteksi penimpaan stack frame sebelum fungsi kembali.
   - Aktifkan kompilasi Position Independent Executable (`-fPIE -pie`) bersama Address Space Layout Randomization (ASLR) sistem operasi agar alamat fungsi target tidak dapat diprediksi secara statis.

3. **Prinsip Least Privilege & Dead Code Elimination:**
   - Hilangkan fungsi-fungsi administratif atau backdoor tersembunyi (seperti `win()`) dari kode produksi. Fungsi yang tidak terhubung secara langsung pada alur eksekusi normal tetap dapat dijangkau penyerang melalui manipulasi pointer eksekusi.

---

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)

- **David (Leader):** Mengarahkan strategi analisis ret2win x86_64, memastikan kepatuhan standar NIST SP 800-115 dan pengelolaan sprint modul LKS.
- **Charlie (Trend-hunter):** Mengidentifikasi pola tipikal Binary Exploitation kategori buffer overflow klasik yang tetap relevan pada silabus kompetisi LKS Cyber Security Nasional.
- **Alex (Fullstack-dev) & Omnirush (Coding Agent):** Mengimplementasikan skrip solver interaktif Python dengan penanganan stack alignment gadget dan otomasi verifikasi REST API.
- **Julius (QA-engineer):** Menjalankan verifikasi lokal terhadap biner ELF `vuln` dan memvalidasi respons HTTP 201 token submission API CyLab.
- **Athena (Security-engineer):** Melakukan audit kelemahan CWE-121 / CWE-787 dan merumuskan panduan mitigasi kepatuhan memori NIST SP 800-53 SI-16.
- **Judith (Guru LKS):** Mengintegrasikan analisis stack alignment System V AMD64 ABI ke dalam silabus pembinaan intensif peserta lomba LKS bidang Cyber Security.
