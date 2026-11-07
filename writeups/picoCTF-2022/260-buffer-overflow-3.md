# Writeup: buffer overflow 3 (Challenge ID: 260)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Custom Static Canary Leak & Stack Buffer Overflow (CWE-121 / CWE-697)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2022
- **Points:** 300
- **Author:** Sanjay C / Palash Oswal
- **Flag:** `academy{Stat1C_c4n4r13s_4R3_b4D_f9792127}`

---

## Problem Statement & Scope
Tantangan `buffer overflow 3` menyajikan program biner ELF 32-bit (`i386-32-little`) yang berjalan pada arsitektur Linux x86. Program dikompilasi dengan proteksi Partial RELRO, NX enabled (non-executable stack), dan No PIE (`0x08048000`), namun tanpa proteksi compiler-level Stack Canary bawaan GCC (`-fno-stack-protector`). Sebagai gantinya, pengembang mengimplementasikan mekanisme *custom stack canary* berbasis ruang pengguna (*userland canary*) untuk mendeteksi serangan *stack smashing*. Peserta ditugaskan untuk mengaudit mekanisme perlindungan khusus tersebut, membobol nilai canary tanpa membuat proses terminasi fatal permanen, dan mengarahkan kembali alur eksekusi (*control flow hijacking*) menuju fungsi `win()` yang mencetak flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penerimaan Panjang Input Tidak Terikat (Arbitrary Length Input, CWE-120):**
   Fungsi `vuln()` mengalokasikan array karakter `buf` berukuran 64 byte. Namun, sebelum membaca data, program menanyakan berapa byte yang ingin ditulis (`count`) dan membacanya ke dalam string `length` lalu di-parse via `sscanf(length, "%d", &count)`. Program kemudian memanggil `read(0, buf, count)` tanpa memeriksa apakah `count <= BUFSIZE`. Hal ini memungkinkan penyerang menulis data dengan panjang sembarang melebihi kapasitas buffer lokal.
2. **Kelemahan Canary Statis Lintas-Eksekusi / Fork (CWE-697):**
   Pada awal eksekusi, fungsi `read_canary()` membaca 4 byte dari file `canary.txt` ke dalam variabel global `global_canary`. Nilai canary yang sama kemudian di-`memcpy` ke variabel stack `canary` di setiap pemanggilan `vuln()`. Karena nilai canary dibaca dari file statis dan proses pada server jaringan (atau fork) mempertahankan nilai canary yang sama untuk setiap koneksi, canary tidak mengalami perubahan secara probabilistik (berbeda dengan canary acak berbasis register `%gs:0x14` GCC yang diacak ulang per eksekusi baru).
3. **Reduksi Kompleksitas Eksponensial ke Linear via Boolean Oracle:**
   Jika canary 4 byte (32-bit) harus ditebak secara serentak, ruang pencarian adalah $256^4 \approx 4{,}29 \times 10^9$ percobaan, yang tidak layak (*infeasible*) melalui jaringan. Namun, karena program memeriksa integritas menggunakan `memcmp(canary, global_canary, CANARY_SIZE)`, penyerang dapat menimpa buffer tepat hingga byte ke-$k$ ($k \in \{1, 2, 3, 4\}$):
   - Jika tebakan byte ke-$k$ salah, program mencetak:
     `***** Stack Smashing Detected ***** : Canary Value Corrupt!`
   - Jika tebakan byte ke-$k$ benar, program tidak mendeteksi kerusakan dan melanjutkan eksekusi ke pesan:
     `Ok... Now Where's the Flag?`
   Dengan demikian, penyerang dapat memulihkan canary secara linear byte-per-byte dalam maksimal $4 \times 256 = 1.024$ percobaan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Struktur Memori Stack Frame `vuln()`:**
   Melalui disassembly Ghidra/GDB, struktur tata letak stack 32-bit dapat dipetakan secara presisi:
   - Buffer lokal `buf`: `[ebp-0x50]` hingga `[ebp-0x10]` (panjang: 64 byte / 0x40 byte).
   - Custom Canary `canary`: `[ebp-0x10]` hingga `[ebp-0x0c]` (panjang: 4 byte).
   - Compiler Alignment & Saved EBP: `[ebp-0x0c]` hingga `[ebp+0x00]` (panjang: 16 byte).
   - Saved Return Address (EIP): `[ebp+0x04]` (panjang: 4 byte).
2. **Brute Force Byte-by-Byte Rekonstruksi Canary:**
   Penyerang mengirimkan panjang `count = 65` (64 byte junk `'A'` + 1 kandidat byte). Ketika server merespons dengan `Ok...`, byte ke-0 berhasil diverifikasi. Proses diulang untuk `count = 66, 67, 68` hingga seluruh 4 byte canary terungkap (misalnya nilai ASCII: `BiRd`).
3. **Penyusunan Payload Ret2Win (Control Flow Hijacking):**
   Setelah canary didapatkan, penyerang menyusun payload pengalihan alamat kembali (*saved return address*):
   - Offset menuju canary: 64 byte (`b"A" * 64`)
   - Canary valid: 4 byte (`b"BiRd"`)
   - Padding menuju Saved EIP: 16 byte (`b"B" * 16`)
   - Target EIP (`win()`): Alamat fungsi `win()` yang terletak pada alamat statis `0x08049367` (dikarenakan No PIE).
4. **Eksekusi Eksploit & Ekstraksi Flag:**
   Payload dikirim dengan panjang `count = 88`. Program melewati verifikasi `memcmp()` tanpa memicu peringatan *stack smashing*, dan saat `vuln()` mengembalikan eksekusi via opcode `ret`, kontrol CPU melompat ke `win()`, membuka `flag.txt`, dan mencetak flag ke terminal.
5. **Hasil Verifikasi Flag:**
   `picoCTF{Stat1C_c4n4r13s_4R3_b4D_f9792127}` dinormalisasi ke token resmi CyLab: `academy{Stat1C_c4n4r13s_4R3_b4D_f9792127}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{Stat1C_c4n4r13s_4R3_b4D_f9792127}`
- **Native PicoCTF Flag:** `picoCTF{Stat1C_c4n4r13s_4R3_b4D_f9792127}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_260_buffer_overflow_3.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Kepatuhan Validasi Batas Buffer (OWASP ASVS v4.0 §14.2 & NIST SP 800-115 §5.3):**
   Hindari mempercayai nilai panjang yang diberikan oleh pengguna untuk membatasi fungsi pembacaan I/O. Gunakan ukuran statis buffer sebagai batas keras:
   ```c
   // Defensif: batasi pembacaan secara tegas pada kapasitas buffer
   read(0, buf, sizeof(buf));
   ```
2. **Penerapan Compiler-Enforced Stack Protection:**
   Jangan mengimplementasikan canary buatan sendiri di level aplikasi pengguna. Aktifkan perlindungan bawaan compiler GCC/Clang:
   ```bash
   gcc -fstack-protector-strong -fstack-clash-protection -pie -fPIE -Wl,-z,relro,-z,now -o secure_app vuln.c
   ```
   Canary bawaan GCC disimpan pada *thread-local storage* (`%gs:0x14` pada x86 atau `%fs:0x28` pada x86_64), memuat null-byte (`0x00`) untuk memutus manipulasi fungsi string standar, dan diacak secara kriptografis menggunakan sumber entropi kernel (`getrandom()`).
3. **Deteksi Anomali Brute-Force & Proteksi Crash:**
   Pada lingkungan produksi, proses yang menerima koneksi jaringan berulang dengan kegagalan integritas memori harus segera memicu pembatasan laju (*rate limiting*) atau pemblokiran IP oleh IDS/WAF untuk mencegah serangan linear probing terhadap canary byte.
