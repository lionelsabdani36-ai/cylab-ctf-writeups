# Writeup: handoff (Challenge ID: 486)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2025
- **Points:** 400
- **Author:** picoCTF 2025
- **Flag:** `academy{p1v0ted_ftw_62126349}`

---

## Problem Statement & Scope
Tantangan `handoff` menyajikan binary ELF 64-bit yang mengimplementasikan sistem pesan sederhana berbasis CLI dengan tiga opsi menu:
1. `Add a new recipient`: Membaca nama penerima (maksimal 10 penerima) ke dalam struct `entry_t entries[10]`.
2. `Send a message to a recipient`: Membaca isi pesan hingga 64 byte ke dalam `entries[choice].msg`.
3. `Exit the app`: Meminta ulasan pengguna ke dalam buffer `char feedback[8]` menggunakan `fgets(feedback, 32, stdin)` sebelum keluar dari fungsi `vuln()`.

Peserta diminta mengeksploitasi kerentanan memori pada aplikasi untuk membaca berkas rahasia `flag.txt` yang berada pada lingkungan server container.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Executable Stack (GNU_STACK Missing / RWX Segments):**
   Pemeriksaan mitigasi biner (`readelf -l / checksec`) menunjukkan bahwa binary dikompilasi tanpa proteksi NX (No-Execute) aktif:
   - `Arch:` amd64-64-little
   - `RELRO:` Partial RELRO
   - `Stack:` Executable (RWX permissions pada segmen stack)
   - `Canary:` No canary found
   - `PIE:` No PIE (Base statis `0x400000`)
   Dengan stack berstatus RWX, instruksi mesin (shellcode) yang ditempatkan pada stack buffer pengguna dapat dieksekusi secara langsung.

2. **Stack Buffer Overflow pada Buffer Feedback (CWE-121):**
   Pada fungsi `vuln()`, variabel `feedback` dialokasikan sebesar 8 byte (`char feedback[8]` pada alamat `[rbp - 0xc]`), namun aplikasi membaca masukan menggunakan `fgets(feedback, 32, stdin)`:
   - Byte 0..6: Karakter masukan feedback.
   - Byte 7: Dinolkan oleh instruksi eksplisit `feedback[7] = '\0'`.
   - Byte 8..11: Variabel lokal integer `total_entries` pada `[rbp - 0x4]`.
   - Byte 12..19: Saved Frame Pointer (`saved RBP`).
   - Byte 20..27: Saved Instruction Pointer (`saved RIP` / return address).
   Kelebihan alokasi pembacaan ini memberikan kontrol penuh atas return address dari fungsi `vuln()`.

3. **Preservasi RAX & Trampoline Calling Convention:**
   Sesuai konvensi ABI C (glibc), fungsi `fgets()` mengembalikan pointer buffer masukan pertamanya (yaitu `&feedback` di stack) pada register `RAX`. Setelah pemanggilan `fgets()` hingga instruksi `ret` pada fungsi `vuln()`, tidak ada register aritmatika yang mengubah nilai `RAX`.
   Dengan mengarahkan return address ke gadget `jmp *%rax` pada alamat statis `0x40116c` (atau `call *%rax` pada `0x401014`), prosesor secara instan melompat kembali ke alamat awal buffer `feedback` di stack.

4. **Near Relative Jump Trampoline (Backward Leap ke Staged Shellcode):**
   Buffer `feedback` terlalu sempit untuk memuat shellcode lengkap (hanya 7 byte sebelum byte 7 dinolkan). Namun, pesan pada `entries[0].msg` (dibuat melalui menu opsi 2) menyediakan ruang 64 byte di stack pada alamat `[rbp - 0x2e0 + 0x8] = [rbp - 0x2d8]`. Jarak dari awal `feedback` (`[rbp - 0xc]`) ke `entries[0].msg` adalah tepat:
   $$\Delta = (-0x0c) - (-0x2d8) = 0x2cc = 716 \text{ byte}$$
   Dengan menempatkan instruksi 5-byte near relative jump `jmp rel32` (`\xe9\x37\xfd\xff\xff`) pada 5 byte pertama buffer `feedback`, prosesor melompat mundur sejauh 716 byte tepat ke NOP sled dan payload shellcode `execve("/bin/sh")` di dalam `entries[0].msg`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Struktur Stack Frame & Geometri Memori:**
   - `entries[0]` berjarak `0x2e0` di bawah `RBP`.
   - `entries[0].msg` berada pada offset `+0x8`, yaitu `RBP - 0x2d8`.
   - `feedback` berada pada `RBP - 0x0c`.
   - Selisih jarak target: $0x2d8 - 0x0c = 716$ byte mundur.

2. **Tahap 1: Staging Shellcode via Menu Opsi 1 & 2:**
   - Pilih menu `1` untuk mendaftarkan penerima baru (nama: `alice`).
   - Pilih menu `2` untuk mengirim pesan kepada penerima `0`.
   - Isi pesan dengan NOP sled (15 byte `\x90`) diikuti shellcode 48-byte `execve("/bin/sh", NULL, NULL)` yang bebas dari karakter newline (`\x0a`):
     ```python
     sh = pwn.asm(pwn.shellcraft.amd64.linux.sh()) # 48 bytes
     msg_payload = b"\x90" * 15 + sh              # 63 bytes total
     ```

3. **Tahap 2: Konstruksi Trampoline & Penimpaan RIP via Menu Opsi 3:**
   - Hitung offset rel32 dari instruksi jump (berada di awal feedback) menuju NOP sled di `entries[0].msg + 8`:
     $$\text{offset} = (feedback - 708) - (feedback + 5) = -713 = 0xfffffd37$$
     Opcode instruksi: `\xe9\x37\xfd\xff\xff`.
   - Susun payload feedback (28 byte):
     - `bytes 0..4`: `\xe9\x37\xfd\xff\xff` (jmp rel32)
     - `bytes 5..6`: `\x90\x90` (NOP)
     - `byte 7`: `\x90` (akan dinolkan oleh `feedback[7] = 0`, tidak memengaruhi alur karena jump terjadi pada byte 0)
     - `bytes 8..11`: Padding 4 byte
     - `bytes 12..19`: Saved RBP (8 byte)
     - `bytes 20..27`: Alamat gadget `jmp *%rax` (`0x40116c`)

4. **Eksekusi Eksploitasi pada Live Instance:**
   - Sambungkan ke lab on-demand CyLab (`chatelaine.cylabacademy.net:24243`).
   - Kirimkan payload tahap 1 dan tahap 2 secara berurutan.
   - Shell interaktif berhasil didapatkan pada server target.
   - Kirim perintah `cat flag.txt` untuk membaca token rahasia:
     ```
     academy{p1v0ted_ftw_62126349}
     ```

---

## Flag & Verifikasi
- **Flag Resmi Live CyLab:** `academy{p1v0ted_ftw_62126349}`
- **Native PicoCTF Archive Flag:** `picoCTF{p1v0ted_ftw_e4ab0a56}`
- **Status Submisi REST API:** HTTP 201 Created (`"correct": true`, `"historical": false`).
- **Skrip Solver Reproduktif:** `scripts/solve_486_handoff.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Penegakan Mitigasi NX (No-Execute / W^X):**
   Pastikan compiler flag `-z noexecstack` selalu aktif. Ketika NX diaktifkan pada segmen memori stack, eksekusi shellcode langsung akan memicu pelanggaran segmentasi (`SIGSEGV` / General Protection Fault), menggagalkan serangan trampoline.
2. **Implementasi Compiler Stack Canary (-fstack-protector-strong):**
   Menyisipkan nilai acak (canary) di antara variabel lokal dan frame pointer sebelum pemanggilan fungsi. Saat `fgets` meluap melampaui buffer `feedback`, nilai canary akan rusak dan memicu `__stack_chk_fail()` sebelum instruksi `ret` tercapai.
3. **Validasi Panjang Input Ketat (Bounded Input Functions):**
   Gunakan parameter batas ukuran yang sesuai dengan ukuran aktual buffer:
   `fgets(feedback, sizeof(feedback), stdin);` (8 byte, bukan 32 byte).
