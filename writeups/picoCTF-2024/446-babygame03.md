# Writeup: babygame03 (Challenge ID: 446)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2024
- **Points:** 400
- **Author:** Palash Oswal
- **Flag:** `academy{gamer_leveluP_ab107dd8}`

---

## Problem Statement & Scope
Tantangan `babygame03` menyajikan aplikasi permainan petualangan matriks karakter berbasis Linux ELF 32-bit (`game`). Pemain (`@`) harus menavigasi peta berukuran 30x90 karakter dari posisi awal (4, 4) menuju ubin akhir `X` pada koordinat (29, 89) melewati berbagai rintangan mematikan (`#`) dengan batas langkah (*lives*) terbatas sebanyak 50 gerakan. Meskipun terdapat perintah bawaan untuk auto-solve (`p`) dan mengubah ubin pemain (`l`), logika permainan pada Level 4 secara eksplisit memblokir transisi normal menuju Level 5, mencegah eksekusi fungsi `win(&v5)` yang mencetak bendera.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Out-of-Bounds Tile Grid Indexing (CWE-129 / CWE-787):**
   Array matriks peta `v8[2700]` dialokasikan pada stack di alamat `[ebp - 0xa99]`. Pada fungsi `move_player()`, perhitungan sel tujuan dihitung menggunakan formula:
   $$\text{target\_cell} = \text{map\_base} + (90 \times \text{row}) + \text{col}$$
   Tidak ada validasi batas minimum koordinat baris (`row >= 0`) maupun kolom (`col >= 0`). Jika pemain digerakkan melampaui batas kiri/atas, penulisan karakter ubin pemain (`@` atau karakter kustom) dan karakter jejak (`.`, byte `0x2e`) akan menimpa variabel lokal lain di stack di bawah array peta.

2. **Stack Frame Variable Corruption (Lives Tampering):**
   Dengan mengirimkan sekuens gerakan `aaaaawwwaaaaws`, pemain melompat ke area stack yang memuat variabel pencacah sisa langkah (`lives_left` pada `[ebp - 0xaa4]`). Penulisan byte `0x2e` merusak nilai counter menjadi integer positif yang sangat besar (`0x2e0021`), memberikan pemain kemampuan bergerak tanpa batas sehingga perintah `p` dapat dieksekusi secara aman.

3. **Level 4 Progression Lockout & Partial EIP Overwrite:**
   Pada fungsi `main()`, kondisi evaluasi kemenangan diperiksa:
   ```c
   if ( v6 == 29 && v7 == 89 && v5 != 4 ) {
       puts("You win!\n Next level starting ");
       ++v9;
       ++v5;
       init_player(&v6);
       init_map(v8, &v6, &v5);
   }
   ```
   Kondisi `v5 != 4` menyebabkan pemain yang mencapai pintu keluar pada Level 4 tidak pernah dapat menaikkan level ke 5 secara sah. Namun, binary dikompilasi dengan proteksi partial RELRO, **No Canary**, dan **No PIE**:
   - Perintah `l` memungkinkan penulisan 1 bita arbitrer (karakter ubin pilihan pengguna) ke alamat sel pemain saat ini.
   - Dengan menavigasikan pemain mundur di stack hingga menimpa bita terendah (*Least Significant Byte* / LSB) dari alamat *Saved Return Address* (Saved EIP), alur eksekusi fungsi `move_player()` dapat dialihkan ke instruksi mana pun di dalam fungsi `main()`:
     - Melompat ke `0x8049970` (`l\x70w`) memintas pengecekan `v5 != 4` dan langsung menjalankan blok `++v5`, mengaktifkan Level 5.
     - Melompat ke `0x80499fe` (`l\xfew`) mengarahkan alur eksekusi langsung ke pemanggilan fungsi `win(&v5)`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Binary & Proteksi Keamanan:**
   Inspeksi biner dengan `checksec`:
   - Arch: i386-32-little (ELF 32-bit)
   - Stack Canary: No canary found
   - NX: NX enabled
   - PIE: No PIE (Base address tetap `0x08048000`)

2. **Eksploitasi Level 1 hingga 3:**
   Kirimkan payload navigasi untuk merusak counter sisa langkah dan melompat ke pintu keluar untuk setiap level:
   ```python
   sock.sendline(b"aaaaawwwaaaawsddddp") # Level 1 -> 2
   sock.sendline(b"aaaaawwwaaaawsddddp") # Level 2 -> 3
   sock.sendline(b"aaaaawwwaaaawsddddp") # Level 3 -> 4
   ```

3. **Bypass Level 4 via Return Address LSB Patch (0x70):**
   Pada Level 4, navigasikan pemain ke offset stack tempat tersimpannya saved EIP:
   - Gerakan: `b"aaaaawwwaaaawsddddaa" + (b"aaaa" * 12) + b"l\x70w"`
   - Perintah `l\x70w` menuliskan byte `0x70` ke LSB return address.
   - Fungsi `move_player()` kembali ke `0x8049970`, menaikkan level menjadi 5.

4. **Trigger Win Function via Return Address LSB Patch (0xfe):**
   Dengan kondisi level 5 aktif, arahkan kembali return address ke blok persiapan pemanggilan `win`:
   - Gerakan: `b"aaaaawwwaaaawsddddaa" + (b"aaaa" * 16) + b"l\xfew"`
   - Bita `0xfe` mengarahkan eksekusi ke `0x80499fe`, yang memanggil `win(&v5)`.
   - Fungsi `win()` membaca `flag.txt` dan mencetaknya ke stdout:
     ```
     academy{gamer_leveluP_ab107dd8}
     ```

---

## Flag & Verifikasi
- **Flag Resmi Live CyLab:** `academy{gamer_leveluP_ab107dd8}`
- **Native PicoCTF Archive Flag:** `picoCTF{gamer_leveluP_5a39c266}`
- **Status Submisi REST API:** HTTP 201 Created (`"correct": true`, `"historical": false`).
- **Skrip Solver Reproduktif:** `scripts/solve_446_babygame03.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Validasi Batas Indeks Multidimensi (Strict Lower & Upper Bounds):**
   Pastikan setiap operasi manipulasi koordinat memverifikasi bahwa indeks baris dan kolom berada dalam rentang valid: `if (row < 0 || row >= MAX_ROWS || col < 0 || col >= MAX_COLS) return;`.
2. **Pengaktifan Stack Canaries (`-fstack-protector-strong`):**
   Ketiadaan stack canary memungkinkan modifikasi saved return address tanpa terdeteksi. Kompilasi wajib mengaktifkan canary guna memicu `__stack_chk_fail` seketika buffer stack meluap ke control data.
3. **Position Independent Executable (PIE) & ASLR Enforcing:**
   Aktifkan PIE (`-fPIE -pie`) pada biner produksi untuk mengacak basis alamat eksekusi. Dengan ASLR aktif, teknik penimpaan bita parsial (partial overwrite) tidak dapat mengeksploitasi target tanpa kebocoran informasi memori (*memory disclosure*).
