# Writeup: WinAntiDbg0x100 (Challenge ID: 429)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Windows Anti-Debugging & PE Binary Analysis
- **Difficulty:** Medium
- **Author:** Nandan Desai
- **Event:** picoCTF 2024
- **Points:** 200
- **Flag:** `academy{d3bug_f0r_th3_Win_0x100_411bc019}`

---

## Problem Statement & Scope
Tantangan menyajikan sebuah berkas eksekusi biner Windows PE32 (`WinAntiDbg0x100.exe`) beserta berkas konfigurasi biner terenkripsi (`config.bin`). Aplikasi ini didesain oleh pengembang malware hipotetis yang menyematkan teknik *anti-debugging* guna menggagalkan analisis dinamis. Pengguna diminta melakukan rekayasa balik untuk menembus pemeriksaan anti-debugger dan merekonstruksi flag resmi yang disembunyikan.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Mekanisme Anti-Debugging Windows (`IsDebuggerPresent`):**
   Fungsi API Win32 `kernel32!IsDebuggerPresent` membaca secara langsung bit `BeingDebugged` pada struktur Process Environment Block (PEB) dari proses saat ini (`FS:[0x30] + 0x02` pada arsitektur x86 32-bit):
   - Jika proses sedang dilampirkan (*attached*) ke debugger seperti x64dbg atau Visual Studio Debugger, flag `BeingDebugged` bernilai `1` (`TRUE`).
   - Malware memeriksa nilai balik ini untuk mengubah alur kontrol (*control flow divergence*), memicu pesan pengalihan palsu dan membatalkan rutinitas dekripsi payload.
2. **Struktur Data Penyimpanan Konfigurasi (`config.bin`):**
   Berkas `config.bin` memiliki tata letak biner terstruktur:
   - Offset `0x00`: Integer 32-bit little-endian penentu panjang buffer ($N = 41$ byte / `0x29`).
   - Offset `0x04`: Buffer teks awal $s_1$ (41 karakter alfabet non-kapital).
   - Offset `0x2E`: Buffer ciphertext biner $s_2$ (41 byte mentah).
3. **Transformasi Algoritmik Multi-Tahap:**
   - **Tahap 1 (Pre-Check Shift):** Fungsi `0x401440` mengeksekusi rotasi alfabetik berbasis *population count* (Hamming weight) dari indeks array sebanyak 7 iterasi:
     $$s_1[i] = \text{'a'} + \left((s_1[i] - \text{'a'} + \text{popcount}(i \pmod{255})) \pmod{26}\right)$$
   - **Tahap 2 (Anti-Debug Gate):** Memanggil `IsDebuggerPresent()`. Jika terdeteksi debugger (`eax != 0`), eksekusi keluar tanpa mengeksekusi Tahap 3.
   - **Tahap 3 (Post-Check Shift):** Jika pemeriksaan debugger dilewati (`eax == 0`), fungsi `0x401440` dieksekusi kembali sebanyak 11 iterasi ($0\text{xb}$), menghasilkan total pergeseran $18$ kali ($7 + 11$).
   - **Tahap 4 (Dekripsi Aliran XOR):** Fungsi `0x401530` melakukan operasi bitwise XOR antara keystream $s_1$ yang telah digeser penuh dengan ciphertext $s_2$:
     $$\text{Flag}[i] = s_1[i] \oplus s_2[i]$$
   - Hasil akhir dikonversi ke string lebar UTF-16LE via `MultiByteToWideChar` dan dikirimkan ke `OutputDebugStringW`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Header PE dan Tabel Impor (Import Address Table):**
   Menggunakan `objdump -p` dan `objdump -d`, teridentifikasi impor API `IsDebuggerPresent` pada alamat `0x00403014` dan `OutputDebugStringW` pada `0x00403008`.
2. **Inspeksi Alur Kendali pada Fungsi Utama (`0x401581`):**
   ```assembly
   4015f2: push   0x7
   4015f4: call   0x401440            ; Shift buffer s1 sebanyak 7 iterasi
   4015fc: call   ds:0x403014         ; IsDebuggerPresent()
   401602: test   eax, eax
   401604: je     0x40161b            ; Lompat jika debugger TIDAK terdeteksi
   401606: push   0x4035c8            ; "### Oops! The debugger was detected..."
   40160b: call   OutputDebugStringW
   401611: jmp    0x4016a2            ; Abort tanpa memproses flag
   40161b: push   0xb
   40161d: call   0x401440            ; Shift lanjutan buffer s1 sebanyak 11 iterasi
   401625: mov    edx, ds:0x405404    ; Pointer s1
   40162b: push   edx
   40162c: call   0x401530            ; XOR s1 dengan s2
   ```
3. **Pemberantasan Pemeriksaan Anti-Debug (Static Emulation / Patching):**
   Alih-alih menyalakan debugger dinamis pada mesin Windows dan mem-patch instruksi `je` atau register `EAX`, logika transformasi matematika dapat direplikasi secara statis dan deterministik:
   ```python
   def apply_shift(buf, count):
       for _ in range(count):
           for i in range(len(buf)):
               shift_val = bin(i % 255).count('1')
               buf[i] = ord('a') + ((buf[i] - ord('a') + shift_val) % 26)

   # Total shift saat anti-debug dilewati: 7 + 11 = 18 iterasi
   apply_shift(s1, 18)
   flag = bytes(a ^ b for a, b in zip(s1, s2))
   print(flag.decode())
   ```
4. **Hasil Ekstraksi Flag:**
   ```text
   academy{d3bug_f0r_th3_Win_0x100_411bc019}
   ```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{d3bug_f0r_th3_Win_0x100_411bc019}`
- **Verifikasi:** Endpoint REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 429, "flag": "academy{d3bug_f0r_th3_Win_0x100_411bc019}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Deteksi & Mitigasi Anti-Analysis pada Malware Triage:** Pada modul Malware Analysis di LKS Cyber Security, analis kerap menghadapi rutinitas anti-debugging dasar seperti pembacaan PEB (`IsDebuggerPresent`), timing probe (`rdtsc`), dan deteksi software breakpoint (`0xCC`). Pemahaman menyeluruh mengenai alur kendali assembly memungkinkan analis menentukan titik percabangan (*conditional branch*) penting dan melakukan bypassing melalui debugger script (e.g. ScyllaHide x64dbg) maupun patching instruksi NOP/JMP.
- **Pemberian Proteksi Integritas pada Perangkat Lunak:** Dalam pengembangan perangkat lunak komersial/defensif, pemeriksaan integritas kode runtime (code checksumming) dan deteksi debugger harus dikombinasikan dengan validasi berbasis kriptografi kuat pada server (remote attestation) agar tidak dapat dibongkar hanya dengan static emulation atau patching biner lokal.
