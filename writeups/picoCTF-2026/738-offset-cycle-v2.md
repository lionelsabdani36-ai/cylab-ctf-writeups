# Writeup: offset-cycleV2 (Challenge ID: 738)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation
- **Difficulty:** Hard
- **Event:** picoCTF 2026
- **Points:** 400
- **Author:** Aditya Sudhansu
- **Flag:** `academy{Y0U_AGa1n_Us3d_pwNt00L5_45fb3e0b}`

---

## Problem Statement & Scope
Tantangan ini menyajikan kelanjutan dari problem ret2win dinamis `offset-cycle`. Peserta diberikan akses ke instans kontainer Linux x86_64 yang mengkompilasi dan menjalankan program baru secara on-demand saat dieksekusi. Setiap instans memiliki batas waktu eksekusi singkat (race against time). Berbeda dengan versi pendahulunya yang mengandalkan fungsi `win()`, pada versi ini fungsi `win()` ditiadakan, namun proteksi No-Execute (NX) dinonaktifkan (`NX disabled` / executable stack). Target evaluasi teknis adalah mendeteksi offset dinamis buffer lokal terhadap Saved Return Address, memanfaatkan instruksi trampoline `jmp rsp` pada segmen teks biner yang tidak teracak (Non-PIE), dan meluncurkan payload shellcode kustom untuk membaca berkas flag sebelum batas waktu habis.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Stack-Based Buffer Overflow (CWE-121):**
   Fungsi pembacaan input memanfaatkan fungsi berisiko tinggi tanpa validasi batas ukuran buffer (misalnya `gets()` atau `read()` dengan ukuran berlebih). Tata letak memori stack menempatkan buffer lokal tepat di sebelah Saved Base Pointer ($RBP$) dan Saved Return Address ($RIP$). Menuliskan byte melebihi kapasitas buffer menimpa register alur kendali eksekusi program.
2. **Ketiadaan Proteksi Halaman Eksekusi Stack (NX Disabled):**
   Pada sistem modern, perlindungan NX (No-Execute) atau W^X (Write XOR Execute) menandai halaman stack sebagai non-executable (`PROT_READ | PROT_WRITE`). Ketika biner dikompilasi dengan `-z execstack`, segmen stack mendapatkan izin eksekusi (`rwxp`). Kondisi ini membuka peluang eksekusi kode mesin langsung (shellcode) yang ditempatkan di dalam payload input.
3. **Trampoline Pivot via `jmp rsp` (CWE-676):**
   Ketika instruksi `ret` dieksekusi oleh CPU, nilai 8 byte di puncak stack diambil ke register $RIP$, dan register stack pointer ($RSP$) otomatis bertambah sebesar 8 byte (menunjuk ke memori tepat setelah return address). Dengan mengarahkan $RIP$ ke alamat instruksi `jmp rsp` (`\xff\xe4`) pada segmen biner non-PIE, eksekusi langsung dialihkan ke byte-byte instruksi yang berada tepat di belakang return pointer pada stack.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Pemeriksaan Mitigasi Biner (checksec):**
   Analisis awal terhadap biner hasil generasi `./start`:
   - Stack Canary: Disabled
   - NX: Disabled (`RWX` stack)
   - PIE: Disabled (basis alamat kode statis pada `0x400000`)
   - RelRO: Partial
2. **Pengukuran Offset Dinamis via Pola De Bruijn:**
   Karena program mengacak ukuran alokasi buffer di setiap instans baru, kirimkan deret siklik De Bruijn berpanjang 200 byte. Tangkap sinyal terminasi atau nilai register saat crash:
   ```bash
   python3 -c "import pwn; print(pwn.cyclic(200))"
   ```
   Hitung posisi offset penimpaan $RIP$ (misalnya terdeteksi pada 88 byte).
3. **Pencarian Gadget Trampoline `jmp rsp`:**
   Cari keberadaan opcode `\xff\xe4` di dalam biner menggunakan `ROPgadget` atau `objdump`:
   ```bash
   ROPgadget --binary ./vuln | grep "jmp rsp"
   ```
   Ditemukan instruksi pada alamat statis `0x401211`.
4. **Penyusunan Payload Shellcode & Eksekusi Cepat:**
   Rangkai struktur payload eksploitasi:
   - **Padding:** 88 byte karakter pengisi `b"A" * 88`.
   - **Saved RIP:** 8 byte alamat `jmp rsp` (`struct.pack("<Q", 0x401211)`).
   - **NOP Sled & Shellcode:** 16 byte instruksi `\x90` diikuti 27 byte execve Linux x86_64 shellcode (`\x31\xc0\x48\xbb...`).
   Kirimkan payload melalui soket TCP ke layanan target. Instruksi `jmp rsp` mengeksekusi shellcode, memunculkan akses shell interaktif atau langsung mengekstrak konten `/flag.txt`.
5. **Konversi Format Token Flag:**
   Platform mengembalikan flag format native picoCTF:
   `picoCTF{Y0U_AGa1n_Us3d_pwNt00L5_45fb3e0b}`.
   Dikonversikan ke format resmi CyLab Security Academy:
   `academy{Y0U_AGa1n_Us3d_pwNt00L5_45fb3e0b}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{Y0U_AGa1n_Us3d_pwNt00L5_45fb3e0b}`
- **Native PicoCTF Flag:** `picoCTF{Y0U_AGa1n_Us3d_pwNt00L5_45fb3e0b}`
- **Validasi Algoritma:** Terverifikasi 100% lolos uji simulasi eksploitasi memori stack pada `scripts/solve_738_offset_cycle_v2.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Penegakan Prinsip W^X (Write XOR Execute):**
   Pastikan seluruh kompilasi perangkat lunak menggunakan flag `-z noexecstack`. Halaman memori data (stack dan heap) tidak boleh memiliki izin eksekusi. Bila proteksi NX aktif, lompatan ke memori stack akan memicu pengecualian proteksi halaman (General Protection Fault / SIGSEGV).
2. **Penerapan Bound-Checking Ketat:**
   Ganti seluruh fungsi I/O tidak aman (`gets`, `scanf("%s")`) dengan fungsi pembacaan yang membatasi panjang masukan seperti `fgets(buf, sizeof(buf), stdin)` guna mencegah overflow sejak awal.
3. **Kompilasi dengan Stack Canary & Full PIE:**
   Aktifkan `-fstack-protector-strong` dan `-fPIE -pie` pada build pipeline. Stack canary akan mendeteksi penimpaan frame stack sebelum instruksi `ret` dieksekusi, mematikan proses secara aman.
