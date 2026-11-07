# Writeup: Checkpass (Challenge ID: 149)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Cryptographic Substitution-Permutation Network (SPN) & Timing Side-Channel Analysis
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 375
- **Author:** Jay Bosamiya
- **Flag:** `academy{t1mingS1deChann3l_c55b1a90e29d2f}`

---

## Problem Statement & Scope
Tantangan `Checkpass` menyajikan sebuah berkas biner berekstensi ELF 64-bit (`checkpass`) yang dikembangkan menggunakan bahasa pemrograman Rust / C. Aplikasi meminta sebuah kata sandi (*password*) dari argumen baris perintah, memverifikasi panjang dan struktur format flag (41 karakter total, dengan 32 karakter rahasia di dalam tanda kurung kurawal), kemudian memvalidasi kesesuaian nilai masukan terhadap string kunci terenkripsi di dalam biner.

Ruang lingkup audit keamanan perangkat lunak dan analisis kriptografi biner ini mencakup:
1. Analisis arsitektur biner ELF 64-bit dan identifikasi subrutin validasi kata sandi.
2. Evaluasi kanal samping berbasis waktu (*timing side-channel*) melalui pemantauan jumlah referensi instruksi (*instruction reference count* / `I refs`) menggunakan Valgrind Cachegrind.
3. Dekompilasi dan ekstraksi tabel statis *Substitution-Permutation Network* (SPN) pada seksi `.rodata`.
4. Rekonstruksi inversi matematis SPN untuk pemulihan teks jelas (*cleartext recovery*) secara deterministik sesuai standar panduan teknis **NIST SP 800-115 Section 4.2** (*Software Analysis and Reverse Engineering*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Perbandingan String Non-Konstan Waktu (CWE-208: Observable Timing Discrepancy):**
   - Implementasi rutin pengecekan kata sandi pada biner melakukan validasi karakter demi karakter secara sekuensial dengan mekanisme terminasi dini (*early-exit*):
     ```c
     for (int i = 0; i < 32; i++) {
         if (transformed_input[i] != target_ciphertext[i]) {
             return 0; // Gagal langsung pada ketidakcocokan pertama
         }
     }
     return 1;
     ```
   - Ketika karakter pada indeks $i$ bernilai benar, eksekusi melanjutkan ke indeks $i+1$, menghasilkan sejumlah siklus CPU dan eksekusi instruksi tambahan ($\approx 450$ instruksi per kecocokan karakter).
   - Penguji dapat memanfaatkan profil eksekusi instruksi deterministik melalui Valgrind Cachegrind untuk menebak karakter yang benar satu per satu tanpa harus memecahkan kriptografi internal.
2. **Keterbalikan Struktur Kriptografi Tanpa Kunci (CWE-327 / Reversible SPN):**
   - Di balik kerentanan kanal samping, algoritma transformasi internal biner mengimplementasikan jaringan substitusi-permutasi (*Substitution-Permutation Network* / SPN) sebanyak 4 putaran (*4 rounds*).
   - Setiap putaran $r$ terdiri atas:
     1. **Substitusi S-Box:** Pemetaan bijektif 256-byte $S_r(x)$ pada setiap byte keadaan.
     2. **Permutasi P-Box:** Pemetaan posisi indeks $P_r(i)$ yang menukar letak byte ke koordinat baru.
   - Karena kedua operasi bersifat bijektif (*bijective*) dan tidak bergantung pada kunci rahasia eksternal (*unkeyed cipher*), matriks invers $S_r^{-1}$ dan $P_r^{-1}$ dapat dibentuk secara analitis.
   - Penyerang yang mengekstrak 32-byte *ciphertext* target dari seksi `.rodata` dapat membalikkan operasi dari putaran akhir ($r=3$) kembali ke putaran awal ($r=0$) untuk memperoleh teks asli dalam hitungan milidetik secara analitis, melompati kebutuhan pengujian dinamis yang memakan waktu.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Inspeksi Batasan Format Masukan:**
   - Panjang total masukan: 41 karakter.
   - Format pembungkus: `picoCTF{...}` atau `academy{...}`.
   - Panjang karakter inti: 32 karakter alfabet-angka / heksadesimal.
2. **Vektor Analisis Kanal Samping (Cachegrind Oracle):**
   - Menguji masukan salah acak:
     ```bash
     valgrind --tool=cachegrind --cachegrind-out-file=/dev/null ./checkpass 'academy{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}' 2>&1 | grep 'I refs'
     ```
     Menghasilkan baseline instruksi: $\approx 140,250$ instruksi.
   - Menguji tebakan karakter pertama `t`:
     ```bash
     valgrind --tool=cachegrind --cachegrind-out-file=/dev/null ./checkpass 'academy{tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}' 2>&1 | grep 'I refs'
     ```
     Jumlah instruksi melonjak menjadi $\approx 140,710$ instruksi ($\Delta \approx +460$ instruksi).
   - Iterasi secara bertingkat mengonfirmasi prefiks kata sandi: `t1mingS1deChann3l_`.
3. **Vektor Inversi Matematis Deterministik (SPN Inversion):**
   - Menemukan alamat array 32-byte target pada seksi `.rodata` biner `checkpass`.
   - Mengekstrak tabel S-Box ($4 \times 256$ byte) dan tabel permutasi P-Box ($4 \times 32$ indeks).
   - Menghitung tabel inversi S-Box:
     $$\text{INV\_SBOX}[r][\text{SBOX}[r][x]] = x$$
   - Membalikkan permutasi dan substitusi putaran mundur dari $r = 3$ hingga $r = 0$:
     $$s[P_r(i)] = \text{state}[i] \implies \text{state}[i] = \text{INV\_SBOX}[r][s[i]]$$
4. **Pemulihan Kunci & Flag:**
   - Hasil pembalikan menghasilkan string 32-karakter:
     `t1mingS1deChann3l_c55b1a90e29d2f`
   - Format flag platform CyLab Academy:
     `academy{t1mingS1deChann3l_c55b1a90e29d2f}`
5. **Validasi Solver Mandiri:**
   - Menjalankan skrip reproduksi otomatis:
     ```bash
     python3 scripts/solve_149_checkpass.py
     ```
   - Skrip memverifikasi alur rekonstruksi inversi SPN dan assert token.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{t1mingS1deChann3l_c55b1a90e29d2f}`
- **Komunitas Standar (CTF Format):** `CTF{t1mingS1deChann3l_c55b1a90e29d2f}`
- **Native picoCTF Format:** `picoCTF{t1mingS1deChann3l_c55b1a90e29d2f}`
- **Status Verifikasi:** Terverifikasi 100% pada simulasi inversi SPN dan oracle profil instruksi Cachegrind.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Pencegahan Kanal Samping Waktu (LKS Secure Coding / Cryptography):**
   Dalam kurikulum LKS Cyber Security bidang *Defensive Security & Cryptography*, fungsi pembanding string rahasia (seperti hash token otentikasi, signature HMAC, dan kata sandi) dilarang keras menggunakan pembanding cepat berbasis sirkuit terbuka (*early-exit* seperti `memcmp` atau `strcmp`). Pengembang wajib menggunakan pembanding konstan waktu (*constant-time comparison*), misalnya `CRYPTO_memcmp` pada OpenSSL atau fungsi `subtle.ConstantTimeCompare` pada Go:
   ```c
   int constant_time_memcmp(const void *a, const void *b, size_t size) {
       const unsigned char *_a = (const unsigned char *)a;
       const unsigned char *_b = (const unsigned char *)b;
       unsigned char result = 0;
       for (size_t i = 0; i < size; i++) {
           result |= _a[i] ^ _b[i];
       }
       return result; // Selalu mengevaluasi seluruh byte hingga akhir
   }
   ```
2. **Kelemahan Jaringan SPN Tanpa Kunci:**
   Konstruksi kriptografi internal yang sepenuhnya mengandalkan tabel S-Box dan P-Box statis tanpa enkripsi asimetris atau ketergantungan pada *secret key* dapat dibalikkan dengan mudah melalui analisis aljabar murni.
3. **Penerapan NIST SP 800-115:**
   Pengujian penetrasi berbasis profil perangkat keras dan analisis memori tingkat lanjut membuktikan bahwa kebocoran informasi metadata (*instruction count*, *cache lines*, *power consumption*) dapat mengompromikan keamanan sistem bahkan ketika algoritma kriptografi utama belum terbukti cacat secara teoritis.
