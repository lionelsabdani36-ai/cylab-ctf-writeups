# Writeup: WinAntiDbg0x300 (Challenge ID: 431)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Windows Anti-Debugging & UPX Decompression
- **Difficulty:** Medium
- **Author:** Nandan Desai
- **Event:** picoCTF 2024
- **Points:** 400
- **Flag:** `academy{Wind0ws_antid3bg_0x300_1415757f}`

---

## Problem Statement & Scope
Tantangan menyajikan sebuah berkas eksekusi biner Windows PE32 terkompresi (`WinAntiDbg0x300.exe`), berkas simbol debugging Program Database (`WinAntiDbg0x300.pdb`), serta berkas konfigurasi biner terenkripsi (`config.bin`) yang dikemas dalam arsip berpasword ZIP (`academy`). Tantangan ini merupakan puncak dari trilogi anti-debugging WinAntiDbg (0x100, 0x200, 0x300), yang menggabungkan teknik kompresi biner (binary packing), manipulasi privilege proses, serta deteksi debugger bertingkat.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyelubungan Kode Melalui UPX Packing:**
   Biner `WinAntiDbg0x300.exe` dikemas menggunakan *Ultimate Packer for eXecutables* (UPX versi 4.2.4). Pengemasan ini mengompresi seksi `.text` dan `.rdata` asli ke dalam seksi virtual `UPX0` dan seksi data kompresi `UPX1`, sehingga menyembunyikan Import Address Table (IAT) dan string program dari analisis statis langsung. Dekompresi biner dilakukan menggunakan utilitas standar `upx -d`.

2. **Analisis Simbol PDB & Arsitektur Anti-Debugging:**
   Berkas PDB yang disediakan mengungkap struktur fungsi internal program:
   - `DetectDebuggerAtLaunch`: Memeriksa apakah program dijalankan di bawah konteks debugger sejak awal peluncuran melalui `IsDebuggerPresent()` dan pemeriksaan register proses.
   - `EnableDebugPrivilege`: Meminta hak istimewa `SeDebugPrivilege` pada access token proses via `OpenProcessToken` dan `AdjustTokenPrivileges`.
   - `DebugActiveProcess` / `DebugActiveProcessStop`: Menguji mekanisme lampiran debugger aktif lintas proses.
   - `DecryptFlag`: Rutinitas akhir dekripsi muatan flag.

3. **Format Biner Penyimpanan Konfigurasi (`config.bin`):**
   - Offset `0x00`: Panjang buffer string 32-bit ($N = 40$ byte / `0x28`).
   - Offset `0x04`: Keystream inisial $s_1$ ($40$ byte alfabet non-kapital: `kkplkivjszuzmgulqzsyhhklyvoirodroluxvdnr`).
   - Offset `0x2C`: Pemisah biner / null-byte.
   - Offset `0x2D`: Ciphertext $s_2$ ($40$ byte biner mentah).

4. **Transformasi Matematika Berbasis Hamming Weight (Popcount Shift):**
   Fungsi pergeseran pada alamat `0x402BC0` menerapkan rotasi siklis berbasis jumlah bit 1 (*population count*) dari indeks array modulo 255:
   $$s_1[i] = \text{'a'} + \left((s_1[i] - \text{'a'} + \text{popcount}(i \pmod{255})) \pmod{26}\right)$$
   Dalam alur eksekusi valid tanpa intervensi debugger eksternal, rotasi ini dieksekusi secara kumulatif sebanyak **12 iterasi**.

5. **Dekripsi Muatan Stream XOR:**
   Fungsi `DecryptFlag` mengeksekusi operasi bitwise XOR antara keystream $s_1$ hasil rotasi 12 putaran dengan ciphertext $s_2$:
   $$\text{Flag}[i] = s_1[i] \oplus s_2[i]$$
   menghasilkan string flag resmi: `academy{Wind0ws_antid3bg_0x300_1415757f}`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Dekompresi Biner dengan UPX:**
   ```bash
   upx -d WinAntiDbg0x300.exe -o unpacked.exe
   ```
   Dekompresi menghasilkan berkas PE32 utuh berukuran 75.264 byte dengan pemulihan seksi `.text`, `.rdata`, `.data`, dan `.idata`.
2. **Inspeksi Simbolik Berkas PDB:**
   Pemeriksaan string biner pada `WinAntiDbg0x300.pdb` memvalidasi kehadiran fungsi:
   - `DetectDebuggerAtLaunch`
   - `EnableDebugPrivilege`
   - `DecryptFlag`
3. **Analisis Disassembly Fungsi Rotasi (`0x402BC0`):**
   ```assembly
   402bcf: movl   $0x55,-0x10(%ebp)   ; Masker 0x55 untuk popcount
   402bd6: movl   $0x33,-0x18(%ebp)   ; Masker 0x33 untuk popcount
   402bdd: movl   $0xf,-0x20(%ebp)    ; Masker 0x0F untuk popcount
   402be4: movb   $0x61,-0x1(%ebp)    ; Karakter dasar 'a'
   ...
   402c78: mov    $0x1a,%esi          ; Modulo 26
   402c7d: idiv   %esi
   ```
4. **Rekonstruksi Solusi Python Statis:**
   Dengan membaca $s_1$ dan $s_2$ dari `config.bin`, algoritma rotasi popcount dieksekusi sebanyak 12 iterasi sebelum di-XOR dengan $s_2$:
   ```python
   def apply_shift(buf, iterations):
       for _ in range(iterations):
           for i in range(len(buf)):
               shift_val = bin(i % 255).count("1")
               buf[i] = ord("a") + ((buf[i] - ord("a") + shift_val) % 26)

   apply_shift(s1, 12)
   flag = bytes(a ^ b for a, b in zip(s1, s2)).decode()
   ```
5. **Output Hasil:**
   ```text
   academy{Wind0ws_antid3bg_0x300_1415757f}
   ```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{Wind0ws_antid3bg_0x300_1415757f}`
- **Verifikasi Platform:** REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 431, "flag": "academy{Wind0ws_antid3bg_0x300_1415757f}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Identifikasi dan Unpacking Malware Terkompresi:** Dalam kompetisi LKS Cyber Security bidang Incident Response dan Reverse Engineering, analis harus terlebih dahulu memeriksa *magic header* dan *section entropy* dari berkas artefak. Tanda-tanda UPX (`UPX0`, `UPX1`) menandakan bahwa biner harus didekompresi sebelum pemetaan fungsi dan disassembly dilakukan.
- **Batasan Analisis Statis vs Proteksi Berkelanjutan:** Meskipun pengembang malware memadukan teknik anti-debugging dengan packer, keberadaan simbol debugging (PDB) atau artefak konfigurasi lokal memungkinkan reverse engineer melakukan rekonstruksi alur logika secara murni matematis (*deterministic emulation*). Pada arsitektur defensif sejati, kunci kriptografi dan logika validasi sensitif harus dieksekusi di lingkungan terpercaya (Trusted Execution Environment / Enclave) atau divalidasi oleh otentikasi server jarak jauh.
