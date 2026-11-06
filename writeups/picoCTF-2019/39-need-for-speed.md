# Writeup: Need For Speed (Challenge ID: 39)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering
- **Difficulty:** Hard (diff=3)
- **Author:** Alexander Bushkin
- **Event:** picoCTF 2019
- **Points:** 400
- **Flag:** `academy{Good job keeping bus #1fb8d167 speeding along!}`

---

## Problem Statement & Scope

Tantangan menguji kemampuan analisis biner ELF 64-bit pada lingkungan Linux:
> *"The name of the game is speed. Are you quick enough to solve this problem and keep it above 50 mph?"*

Berkas yang disediakan adalah biner ELF Linux x86-64 bernama `need-for-speed`. Saat biner dijalankan secara normal di terminal, program langsung mencetak pesan:
```text
Keep this thing over 50 mph!
============================

Creating key...
Not fast enough. BOOM!
```
Program segera keluar sebelum sempat menampilkan flag. Tujuan audit adalah menganalisis mekanisme kontrol waktu dan logika komputasi kunci pada biner, memotong batasan waktu (timer/alarm bypass), serta merekonstruksi flag secara reproduktif.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Mekanisme Pewaktu Asinkron Sistem Operasi (POSIX `alarm` & `SIGALRM`):**
   Fungsi `set_timer()` mengonfigurasi penangan sinyal melalui panggilan sistem `signal(SIGALRM, alarm_handler)` dan mengaktifkan pewaktu `alarm(1)`. Setelah tepat satu detik waktu nyata (*real-time seconds*) berlalu, kernel Linux mengirim sinyal `SIGALRM` ke proses, yang memicu eksekusi `alarm_handler()` berisi pemanggilan `exit(0)`.

2. **Komputasi Sengaja Lambat (Artificial Busy-Wait / Anti-Analysis Delay):**
   Fungsi `calculate_key()` mengimplementasikan loop bersarang yang sengaja dirancang memakan siklus CPU tinggi:
   - Loop mendekrementasi nilai integer dari `0xb5f0a580` menuju `0xdaf852c0` sebanyak 8 iterasi berturut-turut.
   - Karena volume iterasi melebihi kapasitas komputasi dalam jendela waktu 1 detik, pewaktu `SIGALRM` selalu terpicu lebih dulu sebelum fungsi selesai mengembalikan nilai ke register `eax`.

3. **Deterministik Kunci & Algoritma Dekripsi Statis:**
   Meskipun loop berjalan lambat, kondisi terminasi loop bersifat deterministik: nilai akhir register yang dikembalikan selalu konstan, yaitu `0xdaf852c0`. Kunci ini kemudian dipakai oleh fungsi `decrypt_flag(key)` untuk mendekripsi buffer teks di segmen memori `.data` (offset berkas `0x3020`) menggunakan operasi XOR bergulir (*rolling XOR keystream*) dengan penambahan inkremental kunci setiap 3 byte.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Metode 1: Dynamic Bypass via GDB

1. Buka biner dalam debugger GNU (`gdb`):
   ```bash
   gdb ./need-for-speed
   ```
2. Pasang breakpoint pada fungsi `set_timer` dan `calculate_key`:
   ```text
   (gdb) break set_timer
   (gdb) break calculate_key
   (gdb) run
   ```
3. Saat eksekusi berhenti di `set_timer`, lewati konfigurasi sinyal alarm dengan langsung mengeksekusi `return`:
   ```text
   (gdb) return
   ```
4. Lanjutkan eksekusi (`continue`) hingga berhenti di awal `calculate_key`. Lewati iterasi lambat dengan langsung mengembalikan nilai deterministik `0xdaf852c0`:
   ```text
   (gdb) return 0xdaf852c0
   (gdb) continue
   ```
5. Program melanjutkan ke `print_flag` dan mencetak bendera:
   ```text
   Creating key...
   Finished
   Printing flag:
   academy{Good job keeping bus #1fb8d167 speeding along!}
   ```

### Metode 2: Emulasi Statis Python Reproduktif

Tanpa menjalankan biner target, alur dekripsi dapat direkonstruksi penuh menggunakan Python dengan membaca byte terenkripsi pada segmen `.data` (offset `0x3020`):

```python
key = 0xdaf852c0
dec = bytearray(enc_bytes)
for i in range(len(dec)):
    k_byte = key.to_bytes(4, "little")[i % 2]
    dec[i] ^= k_byte
    if (i % 3) == 2:
        key = (key + 1) & 0xffffffff
```

Eksekusi skrip `scripts/solve_39_need_for_speed.py` langsung mengekstrak string bendera dalam hitungan milidetik.

---

## Flag & Verifikasi

- **Flag:** `academy{Good job keeping bus #1fb8d167 speeding along!}`
- **Bukti Validasi REST API CyLab:**
  ```json
  {"user": 1072359, "challenge": 39, "flag": "academy{Good job keeping bus #1fb8d167 speeding along!}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Analisis Kendali Eksekusi Biner (LKS Reverse Engineering):**
   Dalam lomba LKS Cyber Security, modul reverse engineering sering memasang proteksi anti-debugging atau batas waktu (misalnya `alarm()`, `ptrace()`, atau loop verifikasi panjang). Peserta harus terbiasa mengidentifikasi fungsi timer pada tabel impor biner, membedah alur assembly menggunakan `objdump` atau `GDB`, dan menentukan apakah komputasi dapat dilewati (*bypassed*) atau diemulasi secara statis.

2. **Mitigasi Defensif (Secure Coding Standard):**
   - Mengandalkan keamanan melalui keterlambatan eksekusi (*security through obscurity/delay*) tidak memberikan jaminan integritas data rahasia.
   - Biner tidak boleh menyimpan data sensitif terenkripsi bersama dengan kunci deterministik yang dapat dipulihkan melalui inspeksi instruksi statis (CWE-321 / CWE-798). Kunci kriptografi harus dikelola melalui modul keamanan perangkat keras (HSM) atau protokol pertukaran kunci yang terotentikasi.
