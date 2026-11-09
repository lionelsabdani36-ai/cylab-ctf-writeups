# Writeup: Crack the Power (Challenge ID: 522)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Textbook RSA Low Public Exponent & Integer Root Extraction
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** Yahaya Meddy
- **Event:** picoMini by CMU-Africa
- **Flag (Resmi CyLab):** `academy{t1ny_e_227220c9}`
- **Flag Platform Asli:** `picoCTF{t1ny_e_227220c9}`
- **Flag Komunitas:** `CTF{t1ny_e_227220c9}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), RFC 8017 / PKCS #1 v2.2 (RSA Cryptography Standard), NIST SP 800-56B Rev. 2 (Key-Establishment Schemes), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), & CWE-310 (Cryptographic Issues).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Applied Cryptography & Public-Key Cryptanalysis*, peserta diuji dalam menganalisis implementasi algoritma asimetris RSA dan mengeksploitasi cacat pemilihan parameter publik (*cryptographic parameter misconfiguration*):
- **Skenario Tantangan:** Diberikan berkas pesan terenkripsi `message.txt` yang memuat modulus besar $n$, eksponen publik kecil $e = 20$, dan nilai ciphertext $c$.
- **Deskripsi Soal:** *"We received an encrypted message. The modulus is built from primes large enough that factoring them isn’t an option, at least not today. See if you can make sense of the numbers and reveal the flag. Download the message."*
- **Petunjuk Resmi:**
  1. *"When certain values in the encryption setup are smaller than usual, it opens up unexpected shortcuts to recover the plaintext."*
  2. *"Consider whether you can invert the encryption without factoring `n`."*
  3. *"Read more about Coppersmith's attack [here](https://en.wikipedia.org/wiki/Coppersmith's_attack)."*
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis ukuran modulus RSA $n$ ($\approx 4096$ bit) yang menolak metode faktorisasi prima konvensional ($p \cdot q$).
  2. Evaluasi hubungan antara panjang bit pesan $m$, eksponen enkripsi $e = 20$, dan modulus $n$.
  3. Pemanfaatan celah *unreduced modular exponentiation* ($m^e < n$) untuk melakukan ekstraksi akar pangkat $e$ bulat langsung atas ring bilangan bulat $\mathbb{Z}$.
  4. Implementasi algoritma biseksi integer murni tanpa komputasi floating point, serta verifikasi token via CyLab REST API.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Prinsip Operasi Matematika RSA dan Cacat Textbook RSA (RFC 8017):**
   Pada kriptosistem RSA standar, proses enkripsi plaintext $m$ menjadi ciphertext $c$ dilakukan melalui operasi perpangkatan modulo:
   $$c \equiv m^e \pmod n$$
   Keamanan skema ini bergantung pada fungsi satu arah terperangkap (*trapdoor one-way function*), di mana pembalikan $c \to m$ tanpa kunci privat $d$ atau faktorisasi modulus $n$ dipandang komputasional tidak layak (*computationally infeasible*), **dengan asumsi operasi reduksi modulo $\pmod n$ benar-benar membungkus nilai integer $m^e$**.

2. **Kondisi Bebas Modulo / Unreduced Power ($m^e < n$ over $\mathbb{Z}$):**
   Tantangan menggunakan parameter:
   - Panjang modulus $n$: 4096 bit ($n > 2^{4095}$).
   - Eksponen enkripsi publik: $e = 20$.
   - Panjang plaintext flag: 24 karakter ASCII ($\approx 192$ bit). Nilai maksimum integer plaintext $m < 2^{192}$.
   Ketika pesan dipangkatkan dengan $e = 20$:
   $$m^{20} < (2^{192})^{20} = 2^{3840}$$
   Karena $2^{3840} \ll 2^{4095} < n$, maka nilai $m^e$ **jauh lebih kecil daripada modulus $n$**. Akibatnya, operasi pembagian sisa modulo $n$ tidak pernah terjadi:
   $$c = m^e \pmod n \iff c = m^e \quad (\text{dalam ring bilangan bulat murni } \mathbb{Z})$$

3. **Inversi Deterministik via Akar Pangkat Bulat (Integer Root Bisection):**
   Karena tidak terjadi reduksi modular, penyerang tidak perlu mengetahui faktor prima $p, q$ ataupun menghitung invers totien $\phi(n)$. Plaintext $m$ dapat dipulihkan secara deterministik hanya dengan menghitung akar ke-$e$ dari ciphertext $c$:
   $$m = \sqrt[20]{c} = c^{1/20}$$
   Dalam Python, pemanggilan langsung fungsi floating-point `c ** (1/20)` atau `math.pow()` akan memicu galat `OverflowError: int too large to convert to float` karena nilai $c$ melebihi batas presisi eksponen 64-bit IEEE 754 ($> 1.79 \times 10^{308}$). Oleh karena itu, peserta wajib menggunakan algoritma pencarian biner bilangan bulat (*integer bisection algorithm*) untuk memulihkan nilai $m$ dalam kompleksitas $O(\log_2 c)$.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Berkas Parameter `message.txt`:**
   Unduh dan baca parameter enkripsi yang diberikan:
   ```bash
   curl -s https://challenge-files.cylabacademy.net/library/.../message.txt | head -n 5
   ```
   Diperoleh:
   - Modulus $n$: bilangan desimal sepanjang 1234 digit (4096 bit).
   - Eksponen $e$: 20.
   - Ciphertext $c$: bilangan desimal sepanjang 1148 digit (3813 bit).

2. **Verifikasi Kondisi $m^e < n$:**
   Periksa panjang bit ciphertext terhadap modulus:
   ```python
   print(c.bit_length(), n.bit_length())
   # Output: 3813 4096
   ```
   Karena $\mathtt{bit\_length}(c) < \mathtt{bit\_length}(n)$, dikonfirmasi 100% bahwa ciphertext $c$ belum pernah melewati operasi modulo $n$ ($c = m^{20}$).

3. **Penyusunan Algoritma Pencarian Biner Akar Bulat:**
   Implementasikan fungsi pencarian biner bulat murni:
   ```python
   def integer_root(y, k):
       low = 0
       high = 1 << ((y.bit_length() + k - 1) // k + 1)
       while low < high:
           mid = (low + high) // 2
           if pow(mid, k) < y:
               low = mid + 1
           else:
               high = mid
       return low
   ```

4. **Ekstraksi Plaintext dan Dekode ASCII:**
   Hitung $m = \text{integer\_root}(c, 20)$:
   ```python
   m = integer_root(c, 20)
   assert pow(m, 20) == c
   flag = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8')
   print(flag)
   # academy{t1ny_e_227220c9}
   ```

5. **Eksekusi Solver Otomatis & Verifikasi API CyLab:**
   Jalankan skrip reproduksi mandiri `scripts/solve_522_crack_the_power.py`:
   ```bash
   python3 scripts/solve_522_crack_the_power.py
   ```
   Output eksekusi terminal:
   ```text
   === [CyLab Academy] Solusi Modul #522: Crack the Power ===
   [*] Mengunduh parameter RSA dari https://challenge-files.cylabacademy.net/library/.../message.txt...
   [*] Parameter RSA berhasil diurai: bit_length(n)=4096, e=20, bit_length(c)=3813
   [+] Akar pangkat bulat sempurna ditemukan! m^20 == c (m^e < n).
   [+] Plaintext berhasil dipulihkan: academy{t1ny_e_227220c9}
   [+] Flag berhasil direkonstruksi: academy{t1ny_e_227220c9}
   [+] Integritas token terverifikasi 100%: academy{t1ny_e_227220c9}
   ```
   Submisi token ke `POST /api/submissions/` mengembalikan HTTP 201 Created dengan atribut `{"correct": true}`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{t1ny_e_227220c9}`
- **Flag Native picoCTF:** `picoCTF{t1ny_e_227220c9}`
- **Flag Komunitas:** `CTF{t1ny_e_227220c9}`
- **Verifikasi REST API:** `POST https://learn.cylabacademy.org/api/submissions/` -> HTTP 201 Created (`{"user": 1072359, "challenge": 522, "correct": true, "historical": false}`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

Pada uji kompetensi LKS Cyber Security Nasional bidang *Cryptography Implementation & Defensive Key Management*:
1. **Penerapan Skema Padding Terstandarisasi (Optimal Asymmetric Encryption Padding - OAEP):**
   Enkripsi RSA tidak boleh pernah dioperasikan dalam mode mentah (*textbook RSA*). Pengembang wajib menerapkan skema padding deterministik probabilistik seperti RSA-OAEP (PKCS #1 v2.2 / RFC 8017 Section 7.1) dengan fungsi hash modern (SHA-256). Skema ini memperluas representasi plaintext hingga mendekati ukuran penuh modulus $n$, sehingga menjamin terjadinya operasi modulo dan mengeliminasi serangan akar langsung maupun serangan Coppersmith.
2. **Pemilihan Eksponen Publik Standar ($e = 65537$):**
   Gunakan eksponen publik standar Fermat prime ke-4 $F_4 = 65537$ ($2^{16} + 1$). Eksponen ini memiliki efisiensi komputasi tinggi (hanya memiliki dua bit '1' dalam representasi biner) sekaligus mencegah serangan berbasis eksponen rendah ($e=3, e=5, e=20$).
3. **Validasi Panjang Pesan Minimum dan Pemeriksaan Batas Modulus:**
   Setiap modul kriptografi harus memverifikasi bahwa ukuran blok data setelah dipadatkan memenuhi persyaratan keamanan minimum NIST SP 800-56B Rev. 2 sebelum melakukan operasi modular exponentiation.
