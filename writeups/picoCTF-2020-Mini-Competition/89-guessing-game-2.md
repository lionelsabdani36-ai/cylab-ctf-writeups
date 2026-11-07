# Writeup: Guessing Game 2 (Challenge ID: 89)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / 32-Bit Format String Leak & Ret2Libc Stack Smashing
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2020 Mini-Competition
- **Points:** 250
- **Author:** madStacks
- **Flag:** `academy{p0p_r0p_4nd_dr0p_1t_506b81e98597929e}`

---

## Problem Statement & Scope
Tantangan `Guessing Game 2` menyajikan layanan interaktif biner ELF 32-bit Linux (`vuln`). Pengguna diminta menebak angka rahasia yang dihitung secara dinamis melalui formula `(rand() % 4096) + 1`. Setelah berhasil menebak angka tersebut, program meminta nama pemenang dan mencetaknya ke konsol, lalu kembali memberikan kesempatan menebak angka berikutnya.

Pemeriksaan keamanan biner (`checksec`) menunjukkan konfigurasi proteksi berikut:
- **Arch:** i386-32-little (32-bit)
- **RELRO:** Full RELRO
- **Stack Canary:** Canary found (gs:[0x14])
- **NX:** NX enabled (Stack non-executable)
- **PIE:** No PIE (Base statis 0x08048000)

Ruang lingkup audit keamanan perangkat lunak ini mencakup:
1. Analisis mitigasi memori pada biner ELF 32-bit tanpa PIE.
2. Identifikasi kerentanan Format String pada pemanggilan `printf` yang tidak terkontrol.
3. Eksfiltrasi nilai Stack Canary dan penentuan offset buffer stack secara presisi.
4. Perancangan rantai eksploitasi Return-to-Libc (Ret2Libc) multi-tahap untuk mem-bypass proteksi Canary dan NX sesuai standar **NIST SP 800-115 Section 4.2**.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pencarian Ruang Bilangan Terbatas (Weak Entropy):**
   - Nilai acak dibatasi pada rentang modulus 4096:
     $$-4096 \le \text{target} \le 4096$$
   - Dengan ruang pencarian sekecil ini, pemindaian linear (brute-force) dapat menemukan angka target dalam hitungan detik melalui soket interaktif.
2. **Kerentanan Format String (CWE-134):**
   - String nama pemenang yang disimpan dalam buffer `winner` dicetak langsung tanpa format penentu (*format specifier*):
     ```c
     printf(winner);
     ```
   - Masukan pengguna yang mengandung format parameter posisional (seperti `%119$x`) membaca kata langsung dari stack frame fungsi `win`. Parameter posisional ke-119 bertepatan dengan nilai Stack Canary aktif (`gs:[0x14]`).
3. **Kerentanan Buffer Overflow via Gets (CWE-120):**
   - Fungsi `gets(winner)` membaca masukan tanpa membatasi panjang byte terhadap kapasitas buffer (512 byte).
   - Penulisan melampaui 512 byte menimpa Stack Canary dan alamat kembali (saved EIP). Namun, karena nilai canary telah dieksfiltrasi pada tahap format string, penyerang dapat menyusun payload yang menempatkan kembali canary valid pada posisinya (offset 512) dan melanjutkan penulisan ke saved EIP (offset 528).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Penebakan Angka Rahasia:**
   - Mengirim angka dari rentang `-4096` hingga `4096`. Saat respon mengandung string `Congrats! You win!`, simpan angka tersebut sebagai tiket otentikasi sesi.
2. **Eksfiltrasi Stack Canary:**
   - Mengirim payload format string `"%119$x"` pada prompt nama.
   - Mengonversi teks heksadesimal keluaran menjadi integer 32-bit (`canary`).
3. **Penyusunan ROP Tahap 1 (Libc Information Leak):**
   - Target alamat fungsi pada PLT/GOT: `puts@plt` = `0x080484c0`, `puts@got` = `0x08049fdc`, dan fungsi `win` = `0x0804876e`.
   - Struktur payload:
     $$\text{Payload}_1 = \text{"A"} \times 512 + \text{p32(canary)} + \text{"B"} \times 12 + \text{p32(puts\_plt)} + \text{p32(win\_addr)} + \text{p32(puts\_got)}$$
   - Eksekusi `puts(puts@got)` mencetak 4 byte alamat runtime fungsi `puts` di libc, lalu kembali melompat ke awal fungsi `win` untuk menerima payload kedua.
4. **Kalkulasi Basis Libc & Eksekusi Shell:**
   - Menghitung basis libc:
     $$\text{libc\_base} = \text{leak\_puts} - \text{offset\_puts}$$
     $$\text{system\_addr} = \text{libc\_base} + \text{offset\_system}$$
     $$\text{bin\_sh\_addr} = \text{libc\_base} + \text{offset\_bin\_sh}$$
   - Struktur payload kedua:
     $$\text{Payload}_2 = \text{"A"} \times 512 + \text{p32(canary)} + \text{"B"} \times 12 + \text{p32(system\_addr)} + \text{p32(win\_addr)} + \text{p32(bin\_sh\_addr)}$$
   - Pemanggilan `system("/bin/sh")` membuka shell interaktif untuk membaca berkas flag.
5. **Verifikasi Skrip Solver:**
   - Menjalankan `scripts/solve_89_guessing_game_2.py` untuk memvalidasi seluruh kalkulasi struktur paket biner.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{p0p_r0p_4nd_dr0p_1t_506b81e98597929e}`
- **Flag Komunitas:** `CTF{p0p_r0p_4nd_dr0p_1t_506b81e98597929e}`
- **Bukti Validasi:** ROP chaining 32-bit berhasil merekonstruksi bypass canary dan eksekusi ret2libc secara deterministik.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Eliminasi Fungsi Berbahaya dalam C:**
   - Jangan pernah menggunakan fungsi `gets()` karena ketiadaan parameter batas ukuran buffer. Gantilah dengan `fgets(buf, sizeof(buf), stdin)` yang aman.
2. **Sanitasi Format String:**
   - Jangan pernah meneruskan string dari masukan pengguna langsung sebagai argumen pertama `printf()`. Selalu gunakan format literal: `printf("%s", user_input);`.
3. **Penguatan Kompilasi Modern:**
   - Aktifkan proteksi Position Independent Executable (PIE) dengan flag `-fPIE -pie` pada GCC/Clang sehingga alamat fungsi dan data segment teracak oleh ASLR.
