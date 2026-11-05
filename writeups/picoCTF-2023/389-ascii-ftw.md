# Writeup: ASCII FTW (Challenge ID: 389)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Stack Byte Reconstruction & Hex-ASCII Conversion
- **Difficulty:** Easy (diff=1)
- **Author:** Abhishek Agarwal
- **Event:** picoCTF 2023
- **Points:** 100
- **Flag:** `academy{ASCII_IS_EASY_AC3E0C8C}`

---

## Problem Statement & Scope

Diberikan sebuah berkas executable Linux ELF 64-bit bernama `asciiftw`. Program ini mengkonstruksi teks flag rahasia secara langsung di dalam memori stack menggunakan rangkaian penulisan byte heksadesimal individual bertipe ASCII sebelum mencetaknya ke konsol. Peserta diminta merekonstruksi teks flag lengkap melalui disassembler atau debugger tanpa harus mengeksekusi program di lingkungan dinamis.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Obfuskasi Konstanta String Tingkat Rendah (NIST SP 800-115 Static Analysis):**
   - Dalam teknik kompilasi atau upaya obfuskasi sederhana, pembuat malware maupun pembuat tantangan CTF sering kali menghindari penempatan string statis utuh di dalam seksi `.rodata`.
   - Sebagai gantinya, string dibangun secara dinamis di atas frame stack lokal (*stack strings*) menggunakan urutan instruksi `mov BYTE PTR [rbp-offset], immediate_byte`.
   - Taktik ini menggagalkan pencarian string statis konvensional (`strings binary`) karena tidak ada string ASCII yang tersimpan utuh di blok data berkas.
2. **Dekomposisi Instruksi Disassembly Fungsi `main`:**
   ```asm
   0000000000001169 <main>:
       1184: c6 45 d0 61     mov BYTE PTR [rbp-0x30],0x61   ; 'a'
       1188: c6 45 d1 63     mov BYTE PTR [rbp-0x2f],0x63   ; 'c'
       118c: c6 45 d2 61     mov BYTE PTR [rbp-0x2e],0x61   ; 'a'
       1190: c6 45 d3 64     mov BYTE PTR [rbp-0x2d],0x64   ; 'd'
       1194: c6 45 d4 65     mov BYTE PTR [rbp-0x2c],0x65   ; 'e'
       1198: c6 45 d5 6d     mov BYTE PTR [rbp-0x2b],0x6d   ; 'm'
       119c: c6 45 d6 79     mov BYTE PTR [rbp-0x2a],0x79   ; 'y'
       11a0: c6 45 d7 7b     mov BYTE PTR [rbp-0x29],0x7b   ; '{'
       11a4: c6 45 d8 41     mov BYTE PTR [rbp-0x28],0x41   ; 'A'
       11a8: c6 45 d9 53     mov BYTE PTR [rbp-0x27],0x53   ; 'S'
       11ac: c6 45 da 43     mov BYTE PTR [rbp-0x26],0x43   ; 'C'
       11b0: c6 45 db 49     mov BYTE PTR [rbp-0x25],0x49   ; 'I'
       11b4: c6 45 dc 49     mov BYTE PTR [rbp-0x24],0x49   ; 'I'
       11b8: c6 45 dd 5f     mov BYTE PTR [rbp-0x23],0x5f   ; '_'
       11bc: c6 45 de 49     mov BYTE PTR [rbp-0x22],0x49   ; 'I'
       11c0: c6 45 df 53     mov BYTE PTR [rbp-0x21],0x53   ; 'S'
       11c4: c6 45 e0 5f     mov BYTE PTR [rbp-0x20],0x5f   ; '_'
       11c8: c6 45 e1 45     mov BYTE PTR [rbp-0x1f],0x45   ; 'E'
       11cc: c6 45 e2 41     mov BYTE PTR [rbp-0x1e],0x41   ; 'A'
       11d0: c6 45 e3 53     mov BYTE PTR [rbp-0x1d],0x53   ; 'S'
       11d4: c6 45 e4 59     mov BYTE PTR [rbp-0x1c],0x59   ; 'Y'
       11d8: c6 45 e5 5f     mov BYTE PTR [rbp-0x1b],0x5f   ; '_'
       11dc: c6 45 e6 41     mov BYTE PTR [rbp-0x1a],0x41   ; 'A'
       11e0: c6 45 e7 43     mov BYTE PTR [rbp-0x19],0x43   ; 'C'
       11e4: c6 45 e8 33     mov BYTE PTR [rbp-0x18],0x33   ; '3'
       11e8: c6 45 e9 45     mov BYTE PTR [rbp-0x17],0x45   ; 'E'
       11ec: c6 45 ea 30     mov BYTE PTR [rbp-0x16],0x30   ; '0'
       11f0: c6 45 eb 43     mov BYTE PTR [rbp-0x15],0x43   ; 'C'
       11f4: c6 45 ec 38     mov BYTE PTR [rbp-0x14],0x38   ; '8'
       11f8: c6 45 ed 43     mov BYTE PTR [rbp-0x13],0x43   ; 'C'
       11fc: c6 45 ee 7d     mov BYTE PTR [rbp-0x12],0x7d   ; '}'
   ```
3. **Rekonstruksi Buffer Memori Kontigu:**
   - Offset stack bergerak dari `[rbp-0x30]` hingga `[rbp-0x12]` (total 31 byte).
   - Setiap byte heksadesimal merepresentasikan satu karakter ASCII terdefinisi:
     - Header: `0x61 0x63 0x61 0x64 0x65 0x6d 0x79 0x7b` $\rightarrow$ `academy{`
     - Isi: `0x41 0x53 0x43 0x49 0x49 0x5f 0x49 0x53 0x5f 0x45 0x41 0x53 0x59 0x5f 0x41 0x43 0x33 0x45 0x30 0x43 0x38 0x43` $\rightarrow$ `ASCII_IS_EASY_AC3E0C8C`
     - Penutup: `0x7d` $\rightarrow$ `}`
   - Hasil gabungan: `academy{ASCII_IS_EASY_AC3E0C8C}`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh berkas executable `asciiftw`:
   ```bash
   curl -sL https://challenge-files.cylabacademy.net/library/60ac124e46a3c8894d62ac83ba929cdebd78f28658dc91611d4aae76ad1cb41a/asciiftw -o asciiftw
   chmod +x asciiftw
   ```
2. Bongkar kode instruksi fungsi `main` menggunakan `objdump`:
   ```bash
   objdump -d -M intel asciiftw | grep "mov.*BYTE PTR"
   ```
3. Ekstraksi nilai byte heksadesimal secara otomatis menggunakan Python:
   ```python
   raw_hex = [
       0x61, 0x63, 0x61, 0x64, 0x65, 0x6d, 0x79, 0x7b,
       0x41, 0x53, 0x43, 0x49, 0x49, 0x5f, 0x49, 0x53,
       0x5f, 0x45, 0x41, 0x53, 0x59, 0x5f, 0x41, 0x43,
       0x33, 0x45, 0x30, 0x43, 0x38, 0x43, 0x7d
   ]
   print("".join(chr(x) for x in raw_hex))
   # Output: academy{ASCII_IS_EASY_AC3E0C8C}
   ```
4. Validasi solusi menggunakan script otomatis `scripts/solve_389_ascii_ftw.py`.
5. Kirim submisi token flag ke endpoint REST API: `POST /api/submissions/` dengan payload `{"challenge": 389, "flag": "academy{ASCII_IS_EASY_AC3E0C8C}"}`.

---

## Flag & Verifikasi

- **Flag:** `academy{ASCII_IS_EASY_AC3E0C8C}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan HTTP Status `201 Created`:
  ```json
  {"user": 1072359, "challenge": 389, "flag": "academy{ASCII_IS_EASY_AC3E0C8C}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Kemampuan mengidentifikasi teknik *stack string reconstruction* yang sering ditemui pada sampel malware riil untuk menyembunyikan URL C2 atau API endpoint dari scanner antivirus berbasis signature statis.
  - Memahami bahwa perintah `strings` memiliki keterbatasan fundamental dan tidak boleh dijadikan satu-satunya metode triage artefak biner.
- **Mitigasi Defensif:**
  - Tim Blue Team dan analis SOC harus menggunakan alat inspeksi perilaku dinamis (*dynamic sandbox*) atau emulasi CPU (seperti *Qiling Framework* atau *Unicorn Engine*) guna menangkap pembuatan string pada stack saat fase inisialisasi eksekusi berlangsung.
