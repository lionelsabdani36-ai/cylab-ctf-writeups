# Writeup: babygame02 (Challenge ID: 346)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Stack Out-Of-Bounds Write & Saved EIP Overwrite (CWE-129 / CWE-787)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2023
- **Points:** 300
- **Author:** Palash Oswal
- **Flag Resmi:** `academy{gamer_jump1ng_4r0unD_5bc4b2bd}`
- **Standar Audit:** NIST SP 800-115 § 4.2 (Vulnerability Analysis) & § 4.3 (Validation Verification)

---

## Problem Statement & Scope

Tantangan `babygame02` menyajikan berkas biner ELF 32-bit x86 interaktif bernama `game`. Biner ini menjalankan permainan petualangan berbasis terminal dengan peta kisi $30 \times 90$. Berbeda dengan varian pendahulunya (`babygame01`) di mana mencapai koordinat pintu keluar $(29, 89)$ langsung mencetak bendera, pada `babygame02` mencapai pintu keluar hanya mencetak string `"You win!"` dan keluar dari program tanpa mengeksekusi fungsi pembaca bendera.

Fungsi `win()` (`0x0804975d`) tetap ada di dalam biner namun tidak pernah dipanggil secara langsung (*dead code*). Peserta ditugaskan merekayasa balik memori tumpukan (*stack layout*) dan mengeksploitasi penulisan di luar batas larik (*Out-Of-Bounds Write*) untuk membajak alur kontrol program menuju fungsi `win()`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Tata Letak Variabel Stack (*Stack Frame Layout*):**
   Pada fungsi `main()` (`0x08049674`):
   - Struktur data koordinat pemain `player` disimpan pada `ebp - 0xaa0` (variabel `row` pada offset $+0$, `col` pada offset $+4$).
   - Buffer peta permainan `map` berukuran $30 \times 90 = 2700$ byte dialokasikan pada `ebp - 0xa95`.
   - Di dalam fungsi `move_player()`, alamat sel yang diperbarui dihitung dengan rumus indeks 2D:
     $$\text{Alamat Tulis} = \text{map} + \text{row} \times 90 + \text{col}$$

2. **Ketiadaan Validasi Batas Array (*Improper Index Validation - CWE-129*):**
   Logika pergerakan tombol `'w'`, `'a'`, `'s'`, dan `'d'` memodifikasi nilai `row` dan `col` tanpa pengecekan batas bawah ($\ge 0$) maupun batas atas ($< 30$ dan $< 90$). Hal ini memungkinkan indeks negatif yang merujuk pada alamat memori di luar batas awal buffer `map`.

3. **Perhitungan Pergeseran Alamat Return (*Saved EIP Distance*):**
   Slot alamat kembali (*saved return address*) dari pemanggilan fungsi `move_player()` berada pada `ebp_move_player + 4 = ebp_main - 0xab4`. Jarak relatif dari awal buffer `map` (`ebp_main - 0xa95`) ke alamat return adalah:
   $$\text{Displacement} = (\text{ebp} - 0xab4) - (\text{ebp} - 0xa95) = -0xab4 + 0xa95 = -39\text{ byte}$$
   Setiap penulisan pada indeks relatif $-39$ terhadap buffer `map` akan menimpa byte paling rendah (*Least Significant Byte / LSB*) dari alamat kembali `move_player()`.

4. **Penghindaran Tabrakan Koordinat Pemain (*Stack Collision Avoidance*):**
   Struktur `player` berada pada `ebp - 0xaa0`, setara dengan indeks $\text{map} - 11$. Jika pemain berjalan mundur horizontal dari baris 0 (`col = -39`), gerakan tersebut akan menimpa koordinat `player` itu sendiri di stack, menyebabkan korupsi memori tak terkendali (*crash*).
   Strategi navigasi dua dimensi yang aman:
   - Gerakkan pemain ke kanan secara horizontal di dalam batas peta hingga `col = 51` ($4 + 47 = 51$).
   - Ubah karakter ubin pemain menggunakan perintah rahasia `'l'` menjadi karakter `` ` `` (`0x60`, mengarah ke fungsi `win()` entry `0x08049760`).
   - Gerakkan pemain ke atas 5 langkah hingga `row = -1` ($4 - 5 = -1$).
   - Koordinat akhir:
     $$\text{Offset Target} = (-1) \times 90 + 51 = -90 + 51 = -39$$
   - Ketika `move_player()` menyelesaikan eksekusi dan memanggil instruksi `ret`, eksekusi dialihkan langsung ke instruksi `win()`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Statis Biner:**
   Dekomposisi biner ELF 32-bit x86 menunjukkan:
   - Fungsi `win()` berada di alamat virtual `0x0804975d`.
   - Instruksi pemanggilan `move_player()` di dalam `main()` memiliki alamat kembali normal pada `0x08049709`.
   - Menimpa byte terendah (LSB) dari `0x09` menjadi `0x60` (atau `0x5d`) akan membajak instruksi return langsung ke fungsi `win()`.

2. **Penyusunan Vektor Input Eksploitasi:**
   - 47 langkah ke kanan: `'d' * 47` -> `col = 51`.
   - Perintah pengubahan ubin: `'l'` diikuti byte `0x60` (karakter `` ` ``).
   - 5 langkah ke atas: `'w' * 5` -> `row = -1`.
   - Karakter baris baru: `'\n'` (untuk mengosongkan buffer jalur terminal kanonikal).
   Muatan utuh:
   ```python
   payload = (b"d" * 47) + b"l" + bytes([0x60]) + (b"w" * 5) + b"\n"
   ```

3. **Injeksi Payload & Pembajakan Kontrol:**
   Kirimkan muatan ke soket layanan CTF remote:
   ```bash
   python3 -c 'sys.stdout.buffer.write(b"d"*47 + b"l`" + b"w"*5 + b"\n")' | nc chatelaine.cylabacademy.net <port>
   ```
   Instruksi `ret` dari `move_player` melompat ke `win()`, membuka berkas `flag.txt` di lingkungan kontainer dan mencetaknya ke konsol:
   `academy{gamer_jump1ng_4r0unD_5bc4b2bd}`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{gamer_jump1ng_4r0unD_5bc4b2bd}`
- **Status Submisi REST API:** HTTP 201 Created (`correct: true`, `historical: false`).
- **Skrip Solver:** `scripts/solve_346_babygame02.py` (eksekusi deterministik mandiri exit 0).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Analisis Kerentanan Eksploitasi Biner & Rekayasa Tumpukan (NIST SP 800-115 § 4.2):**
   Eksploitasi array index out-of-bounds menunjukkan pentingnya pemahaman mendalam tentang tata letak memori tumpukan (*stack layout*). Satu byte modifikasi tidak sah dapat membajak alur kontrol program tanpa memicu alarm proteksi canary jika canary tidak berada di antara buffer dan return pointer.

2. **Validasi Batas Indeks Masukan (Boundary Checks):**
   Setiap akses larik dalam bahasa C/C++ wajib memverifikasi bahwa indeks berada dalam rentang valid:
   ```c
   if (row < 0 || row >= MAX_ROWS || col < 0 || col >= MAX_COLS) {
       return; // Tolak pergerakan di luar batas
   }
   ```

3. **Penerapan Mitigasi Kompilator Modern (Compiler Protections):**
   - **Stack Canaries (`-fstack-protector-all`):** Menyisipkan nilai acak antara variabel lokal dan pointer return untuk mendeteksi penulisan memori yang melompat atau linier.
   - **Position Independent Executable (`-fPIE -pie`):** Mengacak alamat dasar kode segmen sehingga penimpaan alamat absolut fungsi `win()` menjadi tidak dapat diprediksi secara deterministik.
