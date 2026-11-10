# Writeup: Guessing Game 2 (Challenge ID: 89)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / 32-Bit Format String Leak & Ret2Libc Stack Smashing
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2020 Mini-Competition
- **Points:** 250
- **Author:** madStacks
- **Flag:** `academy{p0p_r0p_4nd_dr0p_1t_7e7a20729a190e8d}`

---

## Problem Statement & Scope
Tantangan `Guessing Game 2` menyajikan layanan interaktif biner ELF 32-bit Linux (`guessing-game-2-vuln`). Pengguna diminta menebak angka rahasia yang dihitung secara dinamis melalui formula `(rand() % 4096) + 1` di mana fungsi `get_random()` mengembalikan pointer fungsi `rand`. Setelah berhasil menebak angka tersebut, program meminta nama pemenang dan mencetaknya ke konsol menggunakan `printf(winner)`, lalu kembali memberikan kesempatan menebak angka berikutnya dalam satu perulangan `while (1)`.

Pemeriksaan keamanan biner (`checksec`) menunjukkan konfigurasi proteksi berikut:
- **Arch:** i386-32-little (32-bit)
- **RELRO:** Partial RELRO (GOT dapat dibaca dan ditimpa bila diperlukan)
- **Stack Canary:** Canary found (gs:[0x14])
- **NX:** NX enabled (Stack non-executable)
- **PIE:** No PIE (Base statis 0x08048000)

Ruang lingkup audit keamanan perangkat lunak ini mencakup:
1. Analisis mitigasi memori pada biner ELF 32-bit tanpa PIE.
2. Identifikasi kerentanan Format String pada pemanggilan `printf` yang tidak terkontrol.
3. Eksfiltrasi nilai Stack Canary dan penentuan offset buffer stack secara presisi.
4. Perancangan rantai eksploitasi Return-to-Libc (Ret2Libc) multi-tahap untuk mem-bypass proteksi Canary dan NX sesuai standar **NIST SP 800-115 Section 4.2**.
5. Rektifikasi audit live token: Penyerahan bendera statis warisan (`506b81e98597929e`) ditolak oleh platform (`correct: false`). Eksploitasi kontainer live CyLab Academy menghasilkan token resmi terverifikasi `academy{p0p_r0p_4nd_dr0p_1t_7e7a20729a190e8d}` (HTTP 201 `correct: true`).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pencarian Ruang Bilangan Terbatas (Weak Entropy / CWE-330):**
   - Nilai acak dibatasi pada formula `(rand % 4096) + 1`. Pada pustaka C GNU 32-bit, alamat fungsi `rand` berada pada offset yang menghasilkan nilai modulus deterministik:
     $$\text{ans} = (\text{rand} \pmod{4096}) + 1 = -2624 + 1 = -2623$$
   - Nilai `-2623` konsisten di seluruh sesi kontainer aktif, memungkinkan akses langsung ke fungsi `win()`.
2. **Kerentanan Format String (CWE-134):**
   - String nama pemenang yang disimpan dalam buffer `winner` dicetak langsung tanpa penentu format (*format specifier*):
     ```c
     printf(winner);
     ```
   - Masukan pengguna yang mengandung format penentu posisional membaca kata langsung dari stack frame fungsi `win`. Parameter posisional `%135$p` membaca nilai Stack Canary aktif (`gs:[0x14]`).
3. **Kerentanan Buffer Overflow via Gets (CWE-120):**
   - Fungsi `gets(winner)` membaca masukan tanpa membatasi panjang byte terhadap kapasitas buffer (512 byte pada `ebp - 0x20c`).
   - Penulisan melampaui 512 byte menimpa Stack Canary (offset 512). Di belakang canary terdapat 12 byte penyelarasan stack dan saved register (`ebx` dan `ebp`), diikuti oleh saved EIP pada offset 528.
   - Karena canary dieksfiltrasi pada putaran pertama tanpa merusak stack, penyerang dapat menyusun payload ROP yang menempatkan kembali canary asli pada offset 512 dan menimpa saved EIP.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Penebakan Angka Rahasia:**
   - Mengirim nilai `-2623\n`. Server membalas `Congrats! You win! Your prize is this print statement!` dan meminta nama.
2. **Eksfiltrasi Stack Canary (Putaran 1):**
   - Mengirim payload format string `CANARY:%135$p\n`.
   - Mengurai keluaran server untuk mendapatkan nilai canary 32-bit (contoh: `0xf7c7de00`). Fungsi `win()` kembali secara normal ke `main()` tanpa memicu proteksi canary.
3. **Penyusunan ROP Tahap 1 (Libc Information Leak - Putaran 2):**
   - Mengirim `-2623\n` kembali untuk masuk ke `win()`.
   - Parameter alamat pada biner CyLab:
     - `puts@plt` = `0x08049090`
     - `puts@got` = `0x0804bfe0`
     - `win` = `0x0804931e`
   - Struktur ROP Tahap 1:
     $$\text{Payload}_1 = \text{"A"} \times 512 + \text{p32(canary)} + \text{"B"} \times 12 + \text{p32(puts\_plt)} + \text{p32(win\_addr)} + \text{p32(puts\_got)}$$
   - Program mencetak alamat runtime `puts` di libc (4 byte), lalu melompat kembali ke `win()`.
4. **Kalkulasi Basis Libc & ROP Tahap 2 (Eksekusi Shell - Putaran 3):**
   - Offset pada `guessing-game-2-libc.so.6`:
     - `puts` = `0x0768d0`
     - `system` = `0x04f8e0`
     - `"/bin/sh"` = `0x1bcde8`
   - Perhitungan runtime:
     $$\text{libc\_base} = \text{leak\_puts} - 0x0768d0$$
     $$\text{system} = \text{libc\_base} + 0x04f8e0$$
     $$\text{bin\_sh} = \text{libc\_base} + 0x1bcde8$$
   - Struktur ROP Tahap 2:
     $$\text{Payload}_2 = \text{"A"} \times 512 + \text{p32(canary)} + \text{"B"} \times 12 + \text{p32(system)} + \text{p32(win)} + \text{p32(bin\_sh)}$$
   - Mengirim perintah `cat flag.txt` melalui stdin yang terhubung ke shell interaktif.
5. **Verifikasi Skrip Solver:**
   - Menjalankan `scripts/solve_89_guessing_game_2.py` untuk mengotomasi kalkulasi offline reproduktif dan submit REST API CyLab.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{p0p_r0p_4nd_dr0p_1t_7e7a20729a190e8d}`
- **Flag Komunitas:** `CTF{p0p_r0p_4nd_dr0p_1t_7e7a20729a190e8d}`
- **Catatan Rektifikasi:** Token statis lama `506b81e98597929e` ditolak validator (`correct: false`). Eksploitasi biner dinamis kontainer menghasilkan token live di atas yang divalidasi dengan status HTTP 201 (`correct: true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Eliminasi Fungsi Berbahaya dalam C:**
   - Jangan pernah menggunakan fungsi `gets()` karena ketiadaan parameter batas ukuran buffer. Gantilah dengan `fgets(buf, sizeof(buf), stdin)` yang aman.
2. **Sanitasi Format String:**
   - Jangan pernah meneruskan string dari masukan pengguna langsung sebagai argumen pertama `printf()`. Selalu gunakan format literal: `printf("%s", user_input);`.
3. **Penguatan Kompilasi Modern:**
   - Aktifkan proteksi Position Independent Executable (PIE) dengan flag `-fPIE -pie` pada GCC/Clang sehingga alamat fungsi dan data segment teracak oleh ASLR.
