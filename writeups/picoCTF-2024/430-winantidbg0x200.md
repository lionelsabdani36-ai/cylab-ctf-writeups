# Writeup: WinAntiDbg0x200 (Challenge ID: 430)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Windows Anti-Debugging & PE Binary Analysis
- **Difficulty:** Medium
- **Author:** Nandan Desai
- **Event:** picoCTF 2024
- **Points:** 300
- **Flag:** `academy{0x200_debug_f0r_Win_cf686cdb}`

---

## Problem Statement & Scope
Tantangan menyajikan berkas biner PE32 Windows (`WinAntiDbg0x200.exe`) beserta berkas terenkripsi `config.bin` yang dilindungi kata sandi ZIP (`academy`). Program ini merupakan kelanjutan dari seri anti-debugging WinAntiDbg, menerapkan teknik proteksi multi-proses tingkat lanjut untuk mendeteksi kehadiran debugger pada proses utama melalui proses anak (*child process*). Penguji diminta mengidentifikasi mekanisme deteksi anti-debugger tersebut dan mengekstrak flag resmi yang disembunyikan.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Mekanisme Anti-Debugging Multi-Process (`DebugActiveProcess`):**
   Pada sistem operasi Windows, arsitektur subsistem debugging Win32 hanya mengizinkan **satu debugger** aktif melampirkan diri (*attach*) ke sebuah target Process ID pada satu waktu.
   - Program utama mendeteksi PID miliknya sendiri via `GetCurrentProcessId()`.
   - Program utama memanggil `CreateProcessW` untuk meluncurkan salinan dirinya sendiri sebagai proses anak dengan argumen baris perintah `"%s <parent_pid>"`.
   - Proses anak membaca PID induk dan memanggil `kernel32!DebugActiveProcess(parent_pid)`:
     - Jika proses induk sedang didebug oleh alat analisis dinamis (e.g. x64dbg, IDA Pro, WinDbg), panggilan `DebugActiveProcess` akan gagal (`FALSE`), dan proses anak keluar dengan kode keluar `0xBEEF`.
     - Jika tidak ada debugger yang menempel pada induk, `DebugActiveProcess` berhasil (`TRUE`), dan anak keluar dengan kode keluar `0`.
   - Proses induk memantau proses anak via `WaitForSingleObject` dan membaca kode keluarnya dengan `GetExitCodeProcess`. Kode `0xBEEF` memicu percabangan kegagalan (`### Oops! The debugger was detected...`).

2. **Struktur Data Penyimpanan Konfigurasi (`config.bin`):**
   Format penyimpanan biner `config.bin`:
   - Offset `0x00`: Ukuran buffer 32-bit little-endian ($N = 37$ byte / `0x25`).
   - Offset `0x04`: Buffer teks inisial $s_1$ ($37$ karakter alfabet huruf kecil).
   - Offset `0x2A`: Pemisah biner / null byte.
   - Offset `0x2B`: Buffer ciphertext biner $s_2$ ($37$ byte mentah).

3. **Perhitungan Kumulatif Rotasi Karakter Berbasis Hamming Weight (Popcount):**
   Fungsi transformasi `0x401090` melakukan rotasi alfabet modulo 26 menggunakan nilai *population count* (jumlah bit 1) dari indeks modulo 255:
   $$s_1[i] = \text{'a'} + \left((s_1[i] - \text{'a'} + \text{popcount}(i \pmod{255})) \pmod{26}\right)$$
   Dalam alur eksekusi tanpa deteksi debugger, fungsi `0x401090` dipanggil bertahap di beberapa titik:
   - **Tahap 1 (Main Pre-Spawn):** 3 iterasi pada alamat `0x401814`.
   - **Tahap 2 (Spawn Setup):** 5 iterasi pada alamat `0x4011DB` dalam fungsi pembantu spawning `0x4011D0`.
   - **Tahap 3 (Post-Wait):** 4 iterasi pada alamat `0x40129D` setelah `WaitForSingleObject`.
   - **Tahap 4 (Post-Close):** 4 iterasi pada alamat `0x4012C9` setelah pembersihan handle proses.
   - **Tahap 5 (Post-Check):** 1 iterasi pada alamat `0x401849` setelah verifikasi kode keluar proses anak dan `IsDebuggerPresent`.
   
   Total iterasi kumulatif:
   $$\text{Total Iterations} = 3 + 5 + 4 + 4 + 1 = 17 \text{ iterasi}$$

4. **Dekripsi Aliran Kriptografi Sederhana (Stream XOR):**
   Setelah ke-17 iterasi rotasi selesai pada buffer $s_1$, fungsi `0x401180` melakukan operasi XOR langsung antara buffer $s_1$ dengan buffer ciphertext $s_2$:
   $$\text{Flag}[i] = s_1[i] \oplus s_2[i]$$

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Statis Impor & Alur Multi-Proses:**
   Melalui pembongkaran biner dengan `objdump -d`, ditemukan rantai panggilan pembentukan proses anak pada `0x4011D0`:
   ```assembly
   4011d9: push   0x5
   4011db: call   0x401090            ; Rotasi 5 iterasi
   ...
   401271: call   *CreateProcessW     ; Meluncurkan anak dengan PID induk
   401295: call   *WaitForSingleObject
   40129b: push   0x4
   40129d: call   0x401090            ; Rotasi 4 iterasi
   4012ad: call   *GetExitCodeProcess ; Membaca status anak
   4012c7: push   0x4
   4012c9: call   0x401090            ; Rotasi 4 iterasi
   4012d1: cmpl   $0xbeef, -0x8(%ebp) ; Periksa apakah anak gagal attach
   ```
2. **Inspeksi Logika Deteksi Debugger pada Proses Utama (`0x401814`):**
   ```assembly
   401812: push   0x3
   401814: call   0x401090            ; Rotasi awal 3 iterasi
   40181c: call   0x4011d0            ; Jalankan pemeriksaan anak
   401824: test   dl, dl              ; dl = status deteksi
   401826: jne    0x401832            ; Lompat ke peringatan jika terdeteksi
   401828: call   *IsDebuggerPresent  ; Pemeriksaan lokal sekunder
   40182e: test   eax, eax
   401830: je     0x401847            ; Jika aman, lanjut ke Tahap 5
   401847: push   0x1
   401849: call   0x401090            ; Rotasi akhir 1 iterasi
   401857: call   0x401180            ; XOR s1 dengan s2
   ```
3. **Eksekusi Solusi Statis Terpandu:**
   Daripada mem-bypass `DebugActiveProcess` melalui hook DLL injection atau driver emulator pada runtime Windows, seluruh alur transformasi matematika disimulasikan menggunakan Python:
   - Baca panjang $N=37$, $s_1$, dan $s_2$ dari `config.bin`.
   - Eksekusi 17 putaran `apply_shift(s1)`.
   - Lakukan XOR $s_1 \oplus s_2$.
4. **Hasil Ekstraksi:**
   ```text
   academy{0x200_debug_f0r_Win_cf686cdb}
   ```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{0x200_debug_f0r_Win_cf686cdb}`
- **Verifikasi Platform:** REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 430, "flag": "academy{0x200_debug_f0r_Win_cf686cdb}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pemahaman Taktik Evasion Multi-Proses:** Pada skenario kompetisi LKS Cyber Security bidang Reverse Engineering / Malware Analysis, malware modern sering kali memanfaatkan relasi parent-child atau self-debugging untuk mencegah reverse engineer menempelkan debugger. Analis harus mengenali pola pemanggilan `DebugActiveProcess` atau `CreateProcess` dengan PID sendiri sebagai indikator proteksi eksklusif.
- **Rekomendasi Defensif:** Mekanisme anti-debugging murni berbasis aplikasi klien (*client-side only*) selalu rentan terhadap analisis statis dan emulasi simbolik. Untuk melindungi integritas perangkat lunak kritis, pengembang harus mengadopsi kontrol integritas berbasis hardware (seperti TPM, code virtualization, dan validasi sertifikat jarak jauh).
