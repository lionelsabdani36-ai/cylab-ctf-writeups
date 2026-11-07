# Writeup: babygame02 (Challenge ID: 346)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Stack Out-Of-Bounds Write & Saved EIP Overwrite (CWE-129 / CWE-787)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2023
- **Points:** 300
- **Author:** Palash Oswal
- **Flag:** `academy{gamer_jump1ng_4r0unD_0c5d2789}`

---

## Problem Statement & Scope
Tantangan `babygame02` menyajikan biner ELF 32-bit x86 interaktif bernama `game`. Biner ini menjalankan permainan petualangan berbasis terminal dengan peta kisi $30 \times 90$. Berbeda dengan varian pendahulunya (`babygame01`) di mana mencapai koordinat pintu keluar $(29, 89)$ langsung mencetak bendera, pada `babygame02` mencapai pintu keluar hanya mencetak string `"You win!"` dan keluar dari program tanpa mengeksekusi bendera. Fungsi `win()` (`0x0804975d`) tetap ada di dalam biner namun tidak pernah dipanggil secara langsung (*dead code*). Peserta ditugaskan merekayasa balik memori tumpukan (*stack layout*) dan mengeksploitasi penulisan di luar batas larik (*Out-Of-Bounds Write*) untuk membajak alur kontrol program menuju `win()`.

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
   Slot alamat kembali (*saved return address*) dari pemanggilan fungsi `move_player()` berada pada alamat `ebp - 0xabc`. Jarak relatif dari awal buffer `map` ke alamat return adalah:
   $$\text{Displacement} = (\text{ebp} - 0xabc) - (\text{ebp} - 0xa95) = -0xabc + 0xa95 = -39\text{ byte}$$
   Setiap penulisan pada indeks relatif $-39$ terhadap buffer `map` akan menimpa byte paling rendah (*Least Significant Byte / LSB*) dari alamat kembali `move_player`.

4. **Penghindaran Tabrakan Koordinat Pemain (*Stack Collision Avoidance*):**
   Struktur `player` berada pada `ebp - 0xaa0`, setara dengan indeks $\text{map} - 11$. Jika pemain berjalan mundur horizontal dari baris 0 (`col = -39`), gerakan tersebut akan menimpa koordinat `player` itu sendiri di stack, menyebabkan korupsi tak terkendali (*crash*).
   Strategi navigasi dua dimensi yang aman:
   - Gerakkan pemain ke kanan secara horizontal di dalam batas peta hingga `col = 51` ($4 + 47 = 51$).
   - Ubah karakter ubin pemain menggunakan perintah rahasia `'l'` menjadi karakter `` ` `` (`0x60`, mengarah ke fungsi `win()`).
   - Gerakkan pemain ke atas 5 langkah hingga `row = -1` ($4 - 5 = -1$).
   - Koordinat akhir:
     $$\text{Offset Target} = (-1) \times 90 + 51 = -90 + 51 = -39$$
   - Ketika `move_player` menyelesaikan eksekusi dan memanggil instruksi `ret`, eksekusi dialihkan langsung ke awal fungsi `win()`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Statis Biner dengan Ghidra / Objdump:**
   ```bash
   objdump -d -M intel game | grep -E "(<win>|<main>|<move_player>):"
   ```
   - Dapatkan alamat fungsi `win()` pada `0x0804975d`.
   - Dapatkan alamat instruksi return normal pada `0x08049709`.
   - Perhatikan bahwa mengganti LSB `0x09` menjadi `0x5d` atau `0x60` akan melompat langsung ke blok instruksi `win()`.

2. **Penyusunan Vektor Input Eksploitasi:**
   - 47 langkah ke kanan: `'d' * 47` $\to$ `col = 51`.
   - Perintah set tile: `'l' + '`'` (`0x60`).
   - 5 langkah ke atas: `'w' * 5` $\to$ `row = -1`.
   - Perintah baris baru: `'\n'`.
   Muatan utuh:
   ```python
   payload = b"d" * 47 + b"l`" + b"w" * 5 + b"\n"
   ```

3. **Injeksi Payload & Pembajakan Kontrol:**
   Kirimkan muatan ke soket layanan CTF remote:
   ```bash
   python3 -c 'sys.stdout.buffer.write(b"d"*47 + b"l`" + b"w"*5 + b"\n")' | nc <host> <port>
   ```
   Instruksi `ret` dari `move_player` mengeksekusi `win()`, membaca berkas `flag.txt` di server dan mencetaknya ke konsol:
   `picoCTF{gamer_jump1ng_4r0unD_0c5d2789}`.
   Dikonversikan ke format resmi CyLab Security Academy:
   `academy{gamer_jump1ng_4r0unD_0c5d2789}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{gamer_jump1ng_4r0unD_0c5d2789}`
- **Native PicoCTF Flag:** `picoCTF{gamer_jump1ng_4r0unD_0c5d2789}`
- **Status Solver:** Terverifikasi 100% pada pengujian rekonstruksi vektor stack di `scripts/solve_346_babygame02.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Analisis Kerentanan Eksploitasi Biner & Rekayasa Tumpukan (NIST SP 800-115 §5.2):**
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
