# Writeup: format string 0 (Challenge ID: 433)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / C Format String Vulnerability & Signal Handler Trigger
- **Difficulty:** Easy
- **Author:** picoCTF Team
- **Event:** picoCTF 2024
- **Points:** 50
- **Flag:** `academy{7h3_cu570m3r_15_n3v3r_SEGFAULT_9582df7b}`

---

## Problem Statement & Scope
Diberikan biner ELF 64-bit dan kode sumber C `format-string-0.c`. Program mensimulasikan pemesanan burger untuk dua pelanggan: Patrick dan Sponge Bob. Peserta diminta memilih burger dengan nama tertentu yang mengeksploitasi kelemahan penentu format (*format string vulnerability*) pada fungsi `printf()` untuk memenuhi syarat ukuran output dan memicu sinyal segmentation fault (`SIGSEGV`) yang akan mencetak isi berkas flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kerentanan Format String pada Bahasa C:**
   Fungsi keluarga `printf()` mengevaluasi argumen pertama sebagai *format control string*. Jika fungsi dipanggil dengan sintaks yang tidak aman seperti `printf(user_input)` alih-alih `printf("%s", user_input)`, karakter persen (`%`) di dalam input akan diinterpretasikan sebagai penentu format (*format specifier*).
2. **Manipulasi Nilai Kembalian Menggunakan Padding Lebar (`%114d`):**
   Penentu format `%114d` memerintahkan `printf` untuk mencetak bilangan bulat dengan lebar minimal 114 karakter (ditambahi spasi padding di awal). Fungsi `printf()` mengembalikan jumlah karakter yang berhasil dicetak. Nilai 114 melampaui ambang batas `2 * BUFSIZE` (64 karakter), sehingga alur program berhasil berpindah ke fungsi `serve_bob()`.
3. **Pemicuan Crash Memori Melalui Dereferensi Pointer Tidak Valid (`%s`):**
   Penentu format `%s` menginstruksikan `printf` untuk mengambil alamat memori dari stack/register dan mencetak string yang ditunjuk oleh alamat tersebut hingga menemukan karakter null (`\0`). Ketika tidak ada argumen pointer sah yang disediakan pada pemanggilan fungsi, `printf` mendereferensi nilai sampah acak dari stack. Membaca alamat yang berada di luar ruang alamat virtual yang dipetakan akan memicu pengecualian perangkat keras *Segmentation Fault* (`SIGSEGV`).
4. **Penanganan Sinyal Kustom (`sigsegv_handler`):**
   Program mendaftarkan fungsi penangan sinyal:
   ```c
   void sigsegv_handler(int sig) {
       printf("\n%s\n", flag);
       exit(1);
   }
   ```
   Sehingga pemicuan crash memori terkontrol langsung menghasilkan pembacaan flag dari memori.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Luncurkan instance lab container:
   `PUT /api/challenges/433/instance/`
2. Hubungkan ke instance melalui netcat:
   ```bash
   nc xebec.cylabacademy.net 12951
   ```
3. **Langkah 1 — Pelanggan Patrick:**
   Pilih burger yang mengandung padding format besar:
   ```text
   Gr%114d_Cheese
   ```
   Fungsi `printf` mencetak 114 karakter spasi dan angka acak. Kondisi `count > 2 * BUFSIZE` terpenuhi dan program memanggil `serve_bob()`.
4. **Langkah 2 — Pelanggan Sponge Bob:**
   Pilih burger yang mengandung penentu format string berbahaya:
   ```text
   Cla%sic_Che%s%steak
   ```
5. Fungsi `printf("Cla%sic_Che%s%steak")` mencoba mendereferensi pointer stack yang tidak valid untuk parameter `%s`, memicu `SIGSEGV`.
6. Penangan sinyal `sigsegv_handler` menangkap sinyal dan mencetak flag ke terminal:
   ```text
   ClaCla%sic_Che%s%steakic_Che(null)
   academy{7h3_cu570m3r_15_n3v3r_SEGFAULT_9582df7b}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{7h3_cu570m3r_15_n3v3r_SEGFAULT_9582df7b}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Gunakan Format String Statis:** Jangan pernah meneruskan string variabel pengguna langsung sebagai parameter pertama fungsi keluarga `printf`. Selalu tentukan penentu format secara eksplisit:
  ```c
  // Sangat Berbahaya:
  printf(choice);

  // Aman:
  printf("%s", choice);
  ```
- **Aktifkan Peringatan Kompiler GCC/Clang:** Gunakan flag `-Wformat -Wformat-security -Werror=format-security` saat kompilasi. Kompiler modern akan menolak membangun biner yang mengandung potensi kerentanan format string.
