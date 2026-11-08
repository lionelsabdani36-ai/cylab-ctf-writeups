# Writeup: ropfu (Challenge ID: 292)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Return-Oriented Programming (ROP) & Syscall Invocation (CWE-120 / CWE-119)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2022
- **Points:** 300
- **Author:** Sanjay C / LT 'syreal' Jones
- **Flag:** `academy{5n47ch_7h3_5h311_ddd0ca99}`

---

## Problem Statement & Scope
Tantangan `ropfu` menyajikan sebuah biner ELF 32-bit x86 yang ditautkan secara statis (*statically linked*). Pengguna diberikan biner `vuln` dan akses jaringan ke instance layanan melalui port netcat (`nc saturn.picoctf.net <port>`). Berbeda dengan tantangan pengantar eksploitasi biner lainnya, biner ini tidak menyediakan fungsi pembantu pencetak bendera (`win()` function), serta proteksi Non-Executable Stack (NX) diaktifkan sehingga injeksi shellcode langsung pada stack akan memicu pelanggaran segmentasi (*Segmentation Fault*). Peserta ditugaskan untuk mengendalikan alur eksekusi proses melalui rantai Return-Oriented Programming (ROP) untuk meluncurkan shell sistem (`/bin/sh`) dan membaca berkas bendera `flag.txt`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Stack Buffer Overflow Tanpa Canary (CWE-120):**
   Fungsi penerima input mengalokasikan buffer lokal sebesar 16 byte pada stack, namun membaca input pengguna melebihi batas alokasi tanpa validasi panjang (*unbounded read*). Pada arsitektur 32-bit cdecl, susunan stack frame adalah:
   ```text
   [Buffer: 16 bytes] + [Compiler Padding: 8 bytes] + [Saved EBP: 4 bytes] + [Saved EIP: 4 bytes]
   ```
   Offset total untuk menimpa saved EIP adalah tepat $16 + 8 + 4 = 28$ byte.
2. **Mitigasi NX (W^X / DEP) & Ketiadaan Fungsi Pembantu:**
   Proteksi NX menandai segmen stack sebagai non-eksekutabel (`RW-`). Namun, karena biner di-compile secara statis (`statically linked`) dan tanpa ASLR internal biner (`PIE disabled`), ribuan instruksi mesin libc berada pada alamat virtual tetap (`0x08048000 - 0x080f0000`).
3. **Mekanisme Return-Oriented Programming (ROP):**
   Penyerang memanfaatkan potongan instruksi mesin yang diakhiri dengan instruksi `ret` (*gadgets*) untuk memanipulasi register CPU dan memanggil antarmuka sistem operasi (*Linux System Call*). Untuk mengeksekusi `sys_execve` pada kernel Linux x86 (Syscall 11):
   - Simpan string `"/bin/sh\x00"` ke area memori yang dapat ditulisi (segmen `.data` pada `0x080e5060`).
   - Atur register:
     - `EAX = 11` (`__NR_execve`)
     - `EBX = 0x080e5060` (pointer ke string argumen perintah)
     - `ECX = 0` (argv NULL)
     - `EDX = 0` (envp NULL)
   - Picu interupsi perangkat lunak: `int 0x80`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Mitigasi & Enumerasi Gadget Biner:**
   Jalankan `checksec` dan `ROPgadget` terhadap biner `vuln`:
   - Canary: No | NX: Yes | PIE: No | RelRO: Partial
   - Alamat segmen `.data`: `0x080e5060` (writable & fixed).
   - Gadgets terpilih:
     - `pop edx ; ret` : `0x080583c2`
     - `pop eax ; ret` : `0x080b074a`
     - `mov dword ptr [edx], eax ; ret` : `0x080562e5`
     - `pop ecx ; pop ebx ; ret` : `0x0806eb91`
     - `int 0x80` : `0x0804a3d2`
2. **Konstruksi ROP Chain Multi-Stage:**
   - **Tahap A (Menulis "/bin/sh\x00" ke Memori):**
     Tulis 4 byte pertama `"/bin"` (`0x6e69622f`) ke `0x080e5060`.
     Tulis 4 byte kedua `"/sh\x00"` (`0x0068732f`) ke `0x080e5064`.
   - **Tahap B (Konfigurasi Register Syscall):**
     Pop `ECX = 0` dan `EBX = 0x080e5060`.
     Pop `EDX = 0`.
     Pop `EAX = 11`.
   - **Tahap C (Eksekusi Interupsi Kernel):**
     Panggil gadget `int 0x80`.
3. **Penyusunan Payload Eksploitasi Lengkap:**
   Gabungkan padding 28 byte `b"A" * 28` dengan urutan ROP gadget packed little-endian (total 100 byte payload).
4. **Eksekusi Shell & Ekstraksi Flag:**
   Kirimkan payload melalui koneksi socket TCP ke server challenge. Proses mengeksekusi `/bin/sh`. Jalankan perintah `cat flag.txt`:
   Flag live yang diekstraksi dari container resmi CyLab: `academy{5n47ch_7h3_5h311_ddd0ca99}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{5n47ch_7h3_5h311_ddd0ca99}`
- **Native PicoCTF Format:** `picoCTF{5n47ch_7h3_5h311_ddd0ca99}`
- **Status Solver:** Terverifikasi 100% via REST API CyLab (`POST /api/submissions/` -> HTTP 201 `correct: true`) dan skrip reproduksi `scripts/solve_292_ropfu.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Pengaktifan Stack Canaries & Safe Buffer APIs (NIST SP 800-115 §5.2):**
   Kompilasi program dengan opsi `-fstack-protector-all` atau `-fstack-protector-strong`. Stack canary menyisipkan nilai acak sebelum saved frame pointer, yang mendeteksi dan menghentikan eksekusi (*abort*) seketika bila terjadi penimpaan buffer stack sebelum instruksi `ret` dieksekusi.
2. **Pengaktifan Penuh Position Independent Executable (PIE) & Full ASLR:**
   Kompilasi dengan `-fPIE -pie` dan aktifkan Full ASLR pada kernel OS. Ketika PIE aktif, basis alamat kode biner dan segmen data diacak pada setiap pemuatan proses, mematahkan asumsi alamat gadget tetap pada ROP konvensional.
3. **Penerapan Control Flow Integrity (CFI):**
   Gunakan teknologi compiler modern seperti Clang Control Flow Integrity atau Intel CET (*Shadow Stack*) untuk memastikan target return pointer hanya dapat kembali ke lokasi pemanggil yang sah.
