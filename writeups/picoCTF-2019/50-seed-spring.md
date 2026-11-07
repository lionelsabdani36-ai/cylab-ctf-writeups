# Writeup: seed-sPRiNG (Challenge ID: 50)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Predictable PRNG Seeding & Linear Congruential Generators
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 350
- **Author:** John Hammond / picoCTF Team
- **Flag:** `academy{pseudo_random_number_generator_not_so_random_66aacad47c332de30eb8d8170d96b772}`

---

## Problem Statement & Scope
Tantangan `seed-sPRiNG` menghadirkan berkas biner ELF 32-bit x86 interaktif:
```text
The most revolutionary game is finally available: seed sPRiNG is open right now!
Connect to it with nc 2019shell1.picoctf.com 12269.
```
Saat dijalankan, program menampilkan permainan lompatan pegas (*spring jump*). Pemain diwajibkan menebak tinggi lompatan (*height*) secara berturut-turut sebanyak 30 ronde tanpa satu pun kesalahan:
```text
LEVEL (1/30) Guess the height:
...
LEVEL (30/30) Guess the height:
```
Jika satu tebakan salah, proses langsung dihentikan (`WRONG! Sorry, better luck next time!`). Jika seluruh 30 level berhasil dijawab dengan benar, program memanggil fungsi `get_flag()` untuk mencetak isi berkas `flag.txt`.

Ruang lingkup pengujian ini mengevaluasi kelemahan mekanisme pembangkitan bilangan acak semu (*Pseudo-Random Number Generator*) pada pustaka standar C berdasarkan NIST SP 800-115 Section 4.3 dan mendemonstrasikan eksploitasi sinkronisasi seed waktu (*time-based seed prediction*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pembangkit Bilangan Acak Semu Lemah (CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator):**
   Fungsi `rand()` pada pustaka standar C (`glibc`) bukanlah generator acak kriptografis (*Cryptographically Secure PRNG - CSPRNG*), melainkan sebuah *Linear Congruential Generator* (LCG) deterministik sederhana dengan relasi rekurensi:
   $$X_{n+1} = (a \cdot X_n + c) \pmod m$$
   di mana pada glibc: $a = 1103515245$, $c = 12345$, dan $m = 2^{31}$.

2. **Inisialisasi Seed Berbasis Waktu Waktu Nyata (Epoch Time Insecurity):**
   Pada awal eksekusi program, fungsi `srand()` dipanggil untuk menginisialisasi status awal generator:
   ```c
   srand(time(NULL));
   ```
   Fungsi `time(NULL)` mengembalikan nilai waktu saat ini dalam format Unix epoch (jumlah detik sejak 1 Januari 1970 UTC).
   - Granularitas seed ini sangat kasar (skala 1 detik).
   - Ruang pencarian seed untuk penyerang yang terhubung secara real-time ke server berkurang drastis menjadi hanya beberapa kemungkinan detik di sekitar waktu koneksi ($[t_{\text{now}} - 2, t_{\text{now}} + 2]$).
   - Begitu seed $S = \text{time}(0)$ diketahui atau disinkronkan, seluruh deretan output `rand()` berikutnya menjadi 100% deterministik dan dapat diproduksi ulang secara identik oleh sistem penyerang.

3. **Transformasi Nilai Tebakan:**
   Di dalam loop permainan, nilai target setiap level diperoleh dari operasi bitwise:
   $$\text{height} = \text{rand}() \ \& \ \text{0xF}$$
   Operasi ini hanya mengambil 4 bit paling tidak signifikan (*least significant bits*) dari integer acak, membatasi rentang tebakan antara 0 hingga 15.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Dekompilasi Fungsi Utama (`main`):**
   Melalui analisis statis pada biner `seed_spring`:
   ```c
   int main() {
       int seed = time(0);
       srand(seed);
       for (int i = 1; i <= 30; i++) {
           printf("LEVEL (%d/30) Guess the height: ", i);
           int guess;
           scanf("%d", &guess);
           int target = rand() & 0xf;
           if (guess != target) {
               puts("WRONG! Sorry, better luck next time!");
               exit(1);
           }
       }
       puts("Congratulation! You've won! Here is your flag:");
       get_flag();
   }
   ```

2. **Penyusunan Solver Sinkronisasi Waktu:**
   Untuk menyinkronkan urutan acak secara presisi dengan glibc sistem, modul solver memanfaatkan antarmuka CTypes untuk memanggil langsung simbol `srand` dan `rand` dari pustaka `libc.so.6`.

3. **Prediksi Sekuensial 30 Tebakan:**
   Saat koneksi dibuka, skrip membaca timestamp sistem saat ini $t$, menginisialisasi `libc.srand(t)`, dan membangkitkan 30 bilangan berturut-turut:
   ```python
   libc.srand(current_timestamp)
   heights = [libc.rand() & 0xF for _ in range(30)]
   ```

4. **Transmisi Nilai & Pemenangan Tantangan:**
   Seluruh 30 nilai diteruskan secara otomatis ke aliran input target. Server memvalidasi seluruh 30 ronde dengan status sukses dan mengeksekusi `get_flag()`, mencetak string flag resmi:
   `picoCTF{pseudo_random_number_generator_not_so_random_66aacad47c332de30eb8d8170d96b772}`

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{pseudo_random_number_generator_not_so_random_66aacad47c332de30eb8d8170d96b772}`
- **Native Platform Flag:** `picoCTF{pseudo_random_number_generator_not_so_random_66aacad47c332de30eb8d8170d96b772}`
- **Status Solver:** Teruji dan terverifikasi penuh melalui modul solver reproduktif deterministik `scripts/solve_50_seed_spring.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Pemberhentian Penggunaan `srand(time(NULL))` untuk Operasi Sensitif Keamanan:**
   Standar NIST SP 800-90A (*Recommendation for Random Number Generation Using Deterministic Random Bit Generators*) melarang keras pemanfaatan PRNG standar C (`rand`, `random`) atau sumber entropi berbasis waktu untuk keperluan keamanan (token autentikasi, nonce, sesi, atau proteksi logika).

2. **Migrasi ke Pembangkit Entropi Kriptografis Sejati (CSPRNG):**
   Secara defensif dalam kurikulum LKS Cyber Security, aplikasi wajib mengadopsi mekanisme CSPRNG yang disediakan oleh kernel Linux:
   - Membaca entropi langsung dari berkas perangkat `/dev/urandom`.
   - Menggunakan panggilan sistem `getrandom(2)` pada level kernel:
     ```c
     #include <sys/random.h>
     unsigned int secure_val;
     getrandom(&secure_val, sizeof(secure_val), 0);
     ```
   - Menggunakan pustaka kriptografi modern seperti OpenSSL (`RAND_bytes`) atau libsodium (`randombytes_buf`), di mana status internal generator diproteksi dengan primitif ChaCha20 atau AES-CTR dan secara berkala di-reseed menggunakan entropi perangkat keras (*hardware entropy jitter*).
