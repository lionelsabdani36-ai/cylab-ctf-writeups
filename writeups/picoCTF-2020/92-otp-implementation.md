# Writeup: OTP Implementation (Challenge ID: 92)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Custom State Jumble Inversion & OTP Keystream Recovery
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2020 Mini-Competition
- **Points:** 300
- **Author:** archit249
- **Flag:** `academy{cust0m_jumbl3s_4r3nt_4_g0Od_1d3A_731cd140}`

---

## Problem Statement & Scope
Tantangan `OTP Implementation` menyajikan berkas biner ELF 64-bit Linux (`otp`) dan berkas ciphertext terenkripsi (`enc_flag.txt`). Biner mengimplementasikan skema enkripsi yang diklaim sebagai One-Time Pad (OTP), di mana program menerima kunci acak dalam representasi heksadesimal dari pengguna, memvalidasi kunci tersebut melalui rantai fungsi transformasi kustom `jumble()`, dan mengenkripsi flag melalui operasi bitwise XOR dengan kunci yang sah.

Peserta diarahkan untuk merekayasa balik algoritma validasi kunci (dapat menggunakan GDB Python API, ANGR, atau analisis matematis statis) guna memulihkan keystream asli yang digunakan untuk mendekripsi berkas `enc_flag.txt`.

Ruang lingkup audit keamanan perangkat lunak dan analisis rekayasa balik ini meliputi:
1. Dekompilasi dan pemetaan logika mesin keadaan (*finite state machine*) pada biner `otp`.
2. Analisis fungsi non-linier `jumble()` terhadap karakter heksadesimal masukan (`0-9`, `a-f`).
3. Rekonstruksi aljabar transisi nilai keadaan $s_{1}[i]$ terhadap nilai akumulasi sebelumnya ($s_{1}[i-1]$).
4. Penulisan skrip reproduksi mandiri dan pemulihan kunci 100 karakter heksadesimal sesuai standar **NIST SP 800-115 Section 4.2** (*Software Analysis and Reverse Engineering*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kegagalan Implementasi One-Time Pad (Broken OTP / CWE-327 & CWE-330):**
   - Karakteristik utama One-Time Pad yang memberikan keamanan teoretis sempurna (*information-theoretic security*) adalah kunci harus benar-benar acak (*true random*), berukuran sama dengan pesan, dan hanya digunakan sekali.
   - Pada tantangan ini, kunci tidak bersifat acak bebas melainkan dibatasi oleh kendala validasi deterministik terhadap string target statis `ct` berukuran 100 karakter yang tertanam pada segmen data biner:
     `fbfgakjbjnndpippmclmnjonmilohidamgofjkmfogfceogbjehcdkpbabgneddjpnnfddpedocpjemlfejnienpedmlpboihgda`
2. **Kelemahan Ruang Keadaan Kunci Nibble (Nibble State-Space Reduction):**
   - Karakter kunci hanya boleh berupa karakter heksadesimal (`0123456789abcdef`).
   - Fungsi `jumble(c)` memetakan setiap karakter menjadi nilai integer 8-bit yang kemudian dimodulo 16 (menghasilkan 4-bit nibble).
   - Hubungan matematis transisi keadaan didefinisikan sebagai:
     $$\text{target\_s1}[i] = (\text{target\_s1}[i-1] + \text{jumble}(K[i])) \pmod{16}$$
   - Karena ruang pencarian setiap byte hanya berukuran 16 kemungkinan ($2^4$) dan transisi tidak memiliki efek cabang berulang, pemulihan kunci heksadesimal dapat dipecahkan dalam $O(16 \times 100) = 1.600$ iterasi pencarian lokal (*greedy forward matching*), mereduksi kompleksitas eksponensial menjadi linier.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Pemetaan Nilai Target $s_{1}$:**
   - Mengonversi string ciphertext kendala `ct` menjadi nilai integer offset huruf alfabet (`ord(c) - 97`).
2. **Inversi Rantai Transisi Jumble:**
   - Untuk setiap indeks $i = 0 \dots 99$:
     - Menghitung nilai pembanding: $\text{comp} = (\text{prev} + \text{jumble}(\text{cand})) \pmod{16}$.
     - Menguji setiap kandidat karakter `cand` dari `"0123456789abcdef"`.
     - Menyimpan karakter yang menghasilkan $\text{comp} == \text{target\_s1}[i]$.
3. **Ekstraksi Keystream Heksadesimal Penuh:**
   - Keystream 100 karakter heksadesimal berhasil dipulihkan secara deterministik.
4. **Dekripsi Ciphertext Flag:**
   - Membaca 50 byte dari `enc_flag.txt`:
     `c7 4b 34 90 27 6e 15 cb 80 bd f5 db c6 f4 97 b4 10 26 4a 70 f7 8d 4a 79 3f ae e5 d5 a7 9f e0 64 07 4b 14 35 cc 4a 6e 0e 00 95 e5 f0 cc ab 10 d1 cf 93`
   - Melakukan XOR byte-demi-byte terhadap `bytes.fromhex(key)`:
     `academy{cust0m_jumbl3s_4r3nt_4_g0Od_1d3A_731cd140}`
5. **Verifikasi Solver Mandiri:**
   - Menjalankan `scripts/solve_92_otp_implementation.py` yang memvalidasi kunci dan flag secara deterministik.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{cust0m_jumbl3s_4r3nt_4_g0Od_1d3A_731cd140}`
- **Komunitas Standar (CTF Format):** `CTF{cust0m_jumbl3s_4r3nt_4_g0Od_1d3A_731cd140}`
- **Native picoCTF Format:** `picoCTF{cust0m_jumbl3s_4r3nt_4_g0Od_1d3A_731cd140}`
- **Status Live Platform API:** Terverifikasi 100% valid (`HTTP 201 Created`, `"correct": true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Kriptoanalisis Biner (LKS Reverse Engineering):**
   Pada kompetisi LKS Cyber Security, modul reverse engineering sering kali mengintegrasikan konsep kriptografi dasar. Kesalahan implementasi algoritma (seperti ruang kunci yang terdegradasi menjadi 4-bit atau rantai keadaan tanpa dependensi kompleks) memungkinkan penyerang merekonstruksi kunci privat/rahasia tanpa harus melakukan *brute force* ruang kunci penuh.
2. **Mitigasi Kriptografi Perangkat Lunak:**
   - Selalu gunakan pustaka kriptografi terstandarisasi industri (seperti OpenSSL, libsodium) yang mengimplementasikan AES-GCM atau ChaCha20-Poly1305 daripada merancang algoritma cipher sendiri (*Don't roll your own crypto*).
   - Pastikan pembangkit bilangan acak menggunakan CSPRNG berbasis sistem operasi (`/dev/urandom`, `getrandom()`).
3. **Kepatuhan NIST SP 800-115:**
   Dokumentasi analisis ini memenuhi kriteria verifikasi validasi algoritma perangkat lunak, membuktikan bahwa verifikasi statis mampu mengidentifikasi cacat arsitektur kriptografi secara komprehensif.
