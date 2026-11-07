# Writeup: Powershelly (Challenge ID: 119)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / PowerShell Script Decompilation & Algebraic Transformation Inversion
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 180
- **Author:** Sara
- **Flag:** `academy{2018highw@y_2_pow3r!}`

---

## Problem Statement & Scope
Tantangan `Powershelly` menyajikan sebuah skrip PowerShell Windows (`powershelly.ps1`) yang menjalankan skema enkripsi berbasis blok untuk mengaburkan string rahasia flag. Skrip ini menerima input pengguna, membaginya ke dalam 5 blok teks independen, dan menerapkan transformasi matematis bertingkat sebelum membandingkan output akhirnya dengan ciphertext target yang di-hardcode.

Ruang lingkup audit keamanan perangkat lunak dan analisis rekayasa balik ini meliputi:
1. Analisis alur eksekusi skrip PowerShell dan parsing struktur blok data input masukan.
2. Identifikasi kerentanan algoritma kriptografi kustom dan dependensi pseudorandom number generator (PRNG) terprediksi.
3. Rekonstruksi inversi fungsi transformasi matematis: un-XOR kumulatif, pembalikan permutasi bitwise berulang, dan pemetaan tabel substitusi simbolik.
4. Verifikasi kebenaran flag hasil pemulihan sesuai standar **NIST SP 800-115 Section 4.2** (*Software Security and Reverse Engineering*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penggunaan Algoritma Kriptografi Kustom Lemah (CWE-327):**
   - Skrip mengimplementasikan algoritma enkripsi buatan sendiri yang menggabungkan operasi substitusi, transposisi bit, dan XOR chaining.
   - Karena seluruh operasi matematis yang digunakan bersifat bijektif (satu-ke-satu) dan tidak memiliki sifat searah (*trapdoor one-way function*), setiap langkah enkripsi memiliki fungsi balikan langsung (*inverse operation*) yang dapat dihitung balik dari output ke input secara deterministik.
2. **Ketergantungan PRNG Deterministik:**
   - Permutasi posisi bit dalam setiap blok dikendalikan oleh seed PRNG yang berasal dari konstanta statis dan indeks blok.
   - Tanpa adanya entropi dinamis atau kunci kriptografis asimetris yang aman, urutan shuffling bit dapat diproduksi ulang secara 100% identik dan dibalik urutannya dari indeks akhir ke indeks awal.
3. **XOR Chaining Tanpa Initialization Vector (IV) Acak:**
   - Mekanisme XOR berantai beroperasi dengan relasi:
     $$C[i] = P[i] \oplus K[i] \oplus C[i-1]$$
   - Dengan mengetahui nilai ciphertext $C$ dan kunci konstan $K$, setiap karakter plaintext dapat dipulihkan secara independen melalui relasi balikan:
     $$P[i] = C[i] \oplus K[i] \oplus C[i-1]$$

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Dekomposisi Skrip PowerShell:**
   - Membaca dan memetakan fungsi pembantu pada `powershelly.ps1`, mencakup fungsi `Scramble`, `ShiftBits`, dan `SubstituteBlocks`.
   - Mengidentifikasi 5 blok ciphertext yang diharapkan di akhir rutin validasi skrip.
2. **Pembalikan Rantai Operasi Matematis:**
   - Mengambil array byte terenkripsi dari variabel target skrip.
   - Menjalankan un-XOR kumulatif secara mundur (dari indeks blok terakhir ke blok pertama) menggunakan tabel kunci statis yang diekstrak.
3. **Inversi Permutasi Posisi Bit:**
   - Menginisialisasi PRNG generator dengan seed yang sama persis seperti yang didefinisikan dalam skrip.
   - Membalik pemetaan indeks bit: memindahkan bit dari posisi tujuan kembali ke posisi asal sebelum pengacakan.
4. **Pembalikan Tabel Substitusi Simbolik:**
   - Membalik kamus pemetaan karakter (`inverse_map = {v: k for k, v in sub_table.items()}`).
   - Mengganti simbol-simbol teracak menjadi karakter alfabet plaintext asli: `2018highw@y_2_pow3r!`.
5. **Eksekusi Solver Otomatis:**
   - Menjalankan skrip mandiri `scripts/solve_119_powershelly.py` untuk membuktikan kalkulasi pemulihan flag.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{2018highw@y_2_pow3r!}`
- **Flag Komunitas:** `CTF{2018highw@y_2_pow3r!}`
- **Bukti Validasi:** Solver reproduktif memvalidasi rekonstruksi inversi matematis tanpa anomali bitwise.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Prinsip Kerckhoffs dalam Kriptografi:**
   - Dalam kompetisi LKS Cyber Security bidang rekayasa balik, enkripsi berbasis pengacakan manual (obfuscation) bukanlah keamanan yang sesungguhnya. Keamanan harus bergantung pada kerahasiaan kunci, bukan pada ketidakjelasan algoritma (*security through obscurity*).
2. **Mitigasi Standar:**
   - Selalu gunakan pustaka kriptografi terstandar industri (seperti AES-GCM dengan manajemen kunci terisolasi melalui HSM atau KMS) daripada merancang skema enkripsi kustom.
   - Pastikan setiap skrip otomasi administratif di lingkungan Windows diproteksi dengan penandatanganan kode digital (Code Signing) dan kebijakan eksekusi PowerShell yang ketat (`AllSigned` atau `Restricted`).
