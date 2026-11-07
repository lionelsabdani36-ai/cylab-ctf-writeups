# Writeup: Clouds (Challenge ID: 136)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Nimbus Block Cipher Differential Cryptanalysis
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 500
- **Author:** madStacks
- **Flag:** `academy{d1ff3r3nt14l_cr7pt0_n1mbu5_p4l1ndr0m3}`
- **Native Flag:** `picoCTF{d1ff3r3nt14l_cr7pt0_n1mbu5_p4l1ndr0m3}`

---

## Problem Statement & Scope
Tantangan `Clouds` menyajikan layanan penyimpanan catatan terenkripsi (*note-taking encryption service*) berbasis kriptografi blok kustom. Pengguna diberikan skrip Python `clouds.py` dan akses ke layanan jaringan interaktif yang mengizinkan enkripsi hingga 2048 catatan teks arbitrer masukan pengguna (*chosen-plaintext oracle*) serta menyajikan catatan terenkripsi pertama yang memuat teks bendera (*flag*).

Tujuan utama dari tantangan ini adalah mengaudit dan mengidentifikasi arsitektur algoritma cipher yang digunakan, membedah fungsi ronde (*round function*), membuktikan adanya karakteristik diferensial yang kebal terhadap permutasi pembalikan bit (*palindromic bit-reversal differential*), mengeksploitasi relasi modular perkalian untuk merekonstruksi subkunci 64-bit pada setiap ronde secara mundur (*backward subkey recovery*), dan memulihkan kunci master 40-byte untuk mendekripsi blok teks sandi bendera.

Ruang lingkup audit keamanan kepatuhan **NIST SP 800-115 Section 4.2** (*Cryptographic and Runtime Software Security Assessment*):
1. Verifikasi spesifikasi cipher: ukuran blok 64-bit (8 byte), 5 ronde enkripsi, dan kunci 320-bit (40 byte) yang dipecah menjadi 5 subkunci 64-bit ($K_0, K_1, K_2, K_3, K_4$).
2. Analisis matematis fungsi permutasi $g(x)$ (pembalikan urutan 64-bit) dan operasi modular perkalian dengan subkunci ganjil $K_{odd} = K_i \mid 1 \pmod{2^{64}}$.
3. Formulasi diferensial masukan $\Delta = 2^{63} - 2$ yang memiliki pola bit palindromik sehingga $g(\Delta) = \Delta$.
4. Pembuktian Teorema Furman (Furman's Lemma 1) mengenai ekuivalensi operasi XOR dan penjumlahan aritmatika pada bilangan genap.
5. Rekonstruksi subkunci ronde ke-5 hingga ronde ke-1 menggunakan Algoritma Euclidean Diperluas (*Extended Euclidean Algorithm*) dan penelusuran pohon kandidat (DFS).

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Arsitektur Cipher Nimbus (CWE-327)
Cipher yang diimplementasikan pada `Clouds` merupakan cipher blok historis bernama **Nimbus**, yang diajukan oleh Alexis Machado pada proyek evaluasi kriptografi Eropa (NESSIE) dan dianalisis secara mendalam oleh Vladimir Furman pada simposium *Fast Software Encryption* (FSE 2001).
Setiap blok 64-bit $P$ dienkripsi melalui 5 ronde dengan persamaan:
$$X_0 = P$$
$$X_{i+1} = \Big( g(X_i \oplus K_i) \cdot (K_i \mid 1) \Big) \pmod{2^{64}} \quad \text{untuk } i = 0, 1, 2, 3, 4$$
Di mana:
- $\oplus$ adalah operasi bitwise XOR dengan subkunci ronde $K_i$.
- $g(x)$ membalikkan urutan 64 bit dari representasi biner $x$.
- Operasi perkalian dilakukan terhadap subkunci yang dipaksa bernilai ganjil ($K_{odd} = K_i \mid 1$) dalam modulo $2^{64}$.

### 2. Kelemahan Struktural: Diferensial Palindromik (CWE-310)
Operasi pembalikan bit $g(x)$ pada umumnya mengacak pola diferensial masukan acak secara drastis. Namun, nilai diferensial dengan representasi biner palindromik:
$$\Delta = 2^{63} - 2 = \text{0x7ffffffffffffffe} = 01111111\dots11111110_2$$
Memiliki sifat khusus $g(\Delta) = \Delta$. Diferensial ini sepenuhnya kebal terhadap operasi pembalikan bit.

### 3. Teorema Furman (Lemma 1 & Claim 1)
- **Furman's Lemma 1:** Untuk dua bilangan bulat genap $A$ dan $B$ berukuran $n$-bit:
  $$A \oplus B = \Delta \iff A + B = \Delta \pmod{2^n}$$
- **Furman's Claim 1 (Karakteristik Diferensial 1-Ronde):**
  Untuk $A, B$ genap dengan $A \oplus B = \Delta$ dan sembarang bilangan ganjil $K_{odd}$:
  $$(A \cdot K_{odd}) \oplus (B \cdot K_{odd}) = \Delta$$
  Relasi ini bertahan dengan probabilitas sekitar 50% pada setiap ronde.
- **Relasi Pasangan Teks Sandi:**
  Jika pasangan teks sandi $C_1, C_2$ mempertahankan diferensial $\Delta$ setelah ronde ke-5:
  $$C_1 + C_2 \equiv (A + B) \cdot K_{odd} \equiv \Delta \cdot K_{odd} \pmod{2^{64}}$$
  Karena $\Delta$ dan $C_1 + C_2$ bernilai genap, $\gcd(\Delta, 2^{64}) = 2$. Menggunakan Algoritma Euclidean Diperluas (*Extended Euclidean Algorithm*), persamaan linear di atas dapat diselesaikan untuk menghasilkan kandidat subkunci $K_{odd}$.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pemilihan Pasangan Teks Terang (Chosen-Plaintext Generation):**
   - Mengirimkan pasangan teks terang $(P, P \oplus \Delta)$ dengan memastikan byte terendah $P$ bernilai genap.
   - Mengumpulkan respons pasangan teks sandi $(C_1, C_2)$ dari layanan `clouds.py`.

2. **Penyaringan Pasangan Kandidat yang Bertahan (Good Pairs Filtering):**
   - Menyeleksi pasangan teks sandi yang memenuhi kriteria Furman:
     $$(C_1 \oplus C_2) \pmod 4 == 2 \quad \text{dan} \quad C_1 \pmod 2 == 0, \; C_2 \pmod 2 == 0$$
   - Pasangan yang lolos memiliki probabilitas tinggi mempertahankan selisih $\Delta$ pada akhir ronde ke-4.

3. **Penyelesaian Subkunci Ronde Terakhir ($K_4$):**
   - Menghitung $S = C_1 + C_2 \pmod{2^{64}}$.
   - Menyelesaikan $\Delta \cdot K_{odd} \equiv S \pmod{2^{64}}$ melalui pembagian faktor 2:
     $$(\Delta / 2) \cdot K_{odd} \equiv (S / 2) \pmod{2^{63}}$$
   - Menginversi $(\Delta / 2)$ modulo $2^{63}$ menggunakan Algoritma Euclidean Diperluas.
   - Karena modulo tereduksi menjadi $2^{63}$, terdapat 2 solusi untuk $K_{odd}$ modulo $2^{64}$, dan dengan mempertimbangkan bit MSB dan LSB yang tidak diketahui, dihasilkan 4 kandidat subkunci untuk setiap ronde.

4. **Dekripsi Parsial dan Rekursi Mundur (DFS Subkey Search):**
   - Untuk setiap kandidat subkunci $K_4$:
     Lakukan dekripsi parsial 1 ronde mundur pada seluruh pasangan teks sandi:
     $$X_{input} = g^{-1}\Big(C \cdot (K_4 \mid 1)^{-1} \pmod{2^{64}}\Big) \oplus K_4$$
   - Hitung jumlah pasangan yang mempertahankan selisih $\Delta$ pada ronde ke-4. Kandidat subkunci yang benar akan menghasilkan konsentrasi pasangan diferensial yang signifikan (>4 pasang).
   - Ulangi proses ini secara rekursif ke ronde 3, 2, 1, dan 0 hingga seluruh 40 byte kunci master ($K_0..K_4$) teridentifikasi penuh.

5. **Pengekstrakan dan Dekripsi Flag:**
   - Membaca catatan indeks ke-0 (ciphertext flag).
   - Menjalankan fungsi dekripsi penuh 5 ronde menggunakan kunci yang telah dipulihkan.
   - Menghasilkan token resmi:
     `academy{d1ff3r3nt14l_cr7pt0_n1mbu5_p4l1ndr0m3}`.

---

## Rekomendasi Mitigasi & Pengerasan Keamanan (Remediation)
1. **Pemberhentian Penggunaan Cipher Ad-Hoc / Tidak Terstandarisasi:**
   - Jangan pernah menggunakan algoritma cipher usang atau tidak lolos seleksi kompetisi kriptografi internasional seperti Nimbus. Gunakan standar terakreditasi industri seperti AES (FIPS 197) atau ChaCha20 (RFC 8439).
2. **Penyisipan Lapisan Non-Linear yang Kuat (Strong S-Boxes):**
   - Kelemahan fundamental Nimbus adalah ketergantungan pada operasi perkalian dan pembalikan bit sederhana yang tidak memecah sifat simetri diferensial bit. Standar modern seperti AES menggunakan S-Box non-linear berbasis inversi bidang Galois $GF(2^8)$ yang memiliki ketahanan optimal terhadap analisis diferensial dan linear (*differential/linear cryptanalysis resistance*).
3. **Pemberlakuan Batasan Kuota Interaksi Oracle (Rate Limiting & Oracle Hardening):**
   - Batasi jumlah enkripsi teks terang pilihan (*chosen-plaintext queries*) pada antarmuka publik untuk mencegah pengumpulan pasangan statistik yang cukup untuk serangan diferensial.

---

## Script Reproduksi
Script solver mandiri tersedia pada berkas `scripts/solve_136_clouds.py`.
Jalankan verifikasi dengan perintah:
```bash
python3 scripts/solve_136_clouds.py
```
Hasil verifikasi mengembalikan token flag valid:
`academy{d1ff3r3nt14l_cr7pt0_n1mbu5_p4l1ndr0m3}`
