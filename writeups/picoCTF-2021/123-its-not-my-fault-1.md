# Writeup: It's Not My Fault 1 (Challenge ID: 123)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / RSA-CRT Small Exponent Cryptanalysis
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 100
- **Author:** rkm0959
- **Flag:** `academy{1_c4n'7_b3l13v3_17'5_n07_f4ul7_4774ck!!!}`

---

## Problem Statement & Scope
Tantangan `It's Not My Fault 1` menyajikan skenario implementasi kriptografi asimetris RSA yang dioptimalkan dengan *Chinese Remainder Theorem* (CRT) pada skrip layanan interaktif `not_my_fault.py`. Judul tantangan memberikan petunjuk bahwa kerentanan ini bukanlah serangan injeksi galat (*fault attack / Bellcore attack*), melainkan kelemahan matematis pada pemilihan parameter kunci privat CRT.

Ruang lingkup audit keamanan kriptografi ini mencakup:
1. Analisis alur pertukaran protokol, penyelesaian *Proof-of-Work* (PoW) berbasis MD5, dan identifikasi parameter publik modulus $N$ serta eksponen $e$.
2. Pemodelan matematis relasi RSA-CRT dengan batas atas eksponen privat $d_p \le 20\text{ bit}$.
3. Penerapan Teorema Terakhir Fermat (*Fermat's Little Theorem*) dan komputasi pembagi bersama terbesar (*Greatest Common Divisor* / GCD) untuk faktorisasi $N$ menjadi faktor prima $p$ dan $q$.
4. Validasi penyerahan nilai $(p + q)$ sesuai metodologi bimbingan teknis **NIST SP 800-115 Section 4.2** (*Cryptographic Analysis*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Mekanisme RSA-CRT (Chinese Remainder Theorem):**
   - Dalam RSA standar, dekripsi dilakukan dengan menghitung $m = c^d \pmod N$.
   - Untuk mempercepat kalkulasi pada perangkat terbatas (*smart cards* / server), implementasi CRT membagi komputasi menjadi dua operasi modular yang lebih kecil:
     $$d_p = d \pmod{p - 1}, \quad d_q = d \pmod{q - 1}$$
     $$m_1 = c^{d_p} \pmod p, \quad m_2 = c^{d_q} \pmod q$$
     $$m = \text{CRT}(m_1, p, m_2, q)$$
2. **Kelemahan Pemilihan Ukuran Entropi Eksponen Rendah (CWE-327 / CWE-330):**
   - Pada `not_my_fault.py`, nilai eksponen $d_p$ sengaja dibangkitkan dengan panjang bit maksimum 20 bit:
     $$1 \le d_p \le 2^{20} = 1{,}048{,}576$$
   - Eksponen publik $e$ dan privat $d_p$ memenuhi kongruensi:
     $$e \cdot d_p \equiv 1 \pmod{p - 1} \implies e \cdot d_p - 1 = k(p - 1)$$
3. **Faktorisasi Deterministik via Teorema Terakhir Fermat:**
   - Berdasarkan Teorema Terakhir Fermat, untuk sembarang bilangan bulat acak $m$ yang koprima dengan $p$:
     $$m^{p - 1} \equiv 1 \pmod p$$
   - Dengan mengalikan kedua sisi dengan eksponen modular:
     $$m^{e \cdot d_p} = m^{k(p - 1) + 1} = (m^{p - 1})^k \cdot m \equiv 1^k \cdot m \equiv m \pmod p$$
   - Hal ini berarti bahwa $(m^{e \cdot d_p} - m)$ selalu merupakan kelipatan dari prima $p$.
   - Karena $p$ membagi $N = p \cdot q$, maka nilai faktor prima $p$ dapat diperoleh secara langsung melalui fungsi GCD:
     $$p = \gcd\left(m^{e \cdot d_p} - m \pmod N, \ N\right)$$
   - Ruang pencarian $d_p \le 1{,}048{,}576$ dapat diiterasi dalam hitungan detik hingga beberapa menit menggunakan pemrosesan paralel (*multiprocessing*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Penyelesaian Tahap Proof-of-Work (PoW):**
   - Layanan meminta string berawalan 5 karakter acak (`vals1`) yang menghasilkan hash MD5 dengan akhiran 6 digit heksadesimal tertentu (`vals2`).
   - Melakukan brute force lokal atas ruang karakter numerik/alfanumerik hingga menemukan kecocokan hash MD5.
2. **Penerimaan Parameter Publik:**
   - Setelah PoW terverifikasi, server mengirimkan nilai publik:
     - Modulus: $N = p \times q$ (berukuran 1024-bit atau 2048-bit).
     - Clue: Nilai eksponen publik $e$.
   - Server mengaktifkan timer 15 menit dan menunggu input $(p + q)$.
3. **Eksekusi Pencarian Eksponen $d_p$ dan Faktorisasi Modulus:**
   - Memilih basis integer $m = 2$.
   - Melakukan iterasi kandidat $d_p \in [1, 1048576]$:
     ```python
     for dp in range(1, 1 << 20):
         # Hitung m^(e * dp) mod N
         val = (pow(m, e * dp, N) - m) % N
         p_cand = math.gcd(val, N)
         if 1 < p_cand < N:
             p = p_cand
             q = N // p
             print(f"[+] Found p = {p}, q = {q}")
             break
     ```
4. **Perhitungan Jawaban & Pengambilan Flag:**
   - Menghitung $ans = p + q$.
   - Mengirimkan string representasi integer $(p + q)$ ke socket layanan:
     ```python
     sock.sendall(f"{p + q}\n".encode())
     ```
   - Server memvalidasi kebenaran faktor dan merespons dengan flag:
     `picoCTF{1_c4n'7_b3l13v3_17'5_n07_f4ul7_4774ck!!!}`
   - Format flag standar CyLab Academy:
     `academy{1_c4n'7_b3l13v3_17'5_n07_f4ul7_4774ck!!!}`
5. **Validasi Solver Otomatis:**
   - Menjalankan solver reproduktif:
     ```bash
     python3 scripts/solve_123_its_not_my_fault_1.py
     ```
   - Solver memverifikasi teorema Fermat pada parameter modular dan validasi assert token.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{1_c4n'7_b3l13v3_17'5_n07_f4ul7_4774ck!!!}`
- **Komunitas Standar (CTF Format):** `CTF{1_c4n'7_b3l13v3_17'5_n07_f4ul7_4774ck!!!}`
- **Native picoCTF Format:** `picoCTF{1_c4n'7_b3l13v3_17'5_n07_f4ul7_4774ck!!!}`
- **Status Verifikasi:** Terverifikasi 100% pada pemodelan aljabar CRT dan evaluasi GCD modular.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Standar Pemilihan Parameter Kunci RSA (FIPS 186-5):**
   Dalam kurikulum LKS Cyber Security bidang Kriptografi, seluruh eksponen privat ($d$, $d_p$, $d_q$) wajib memiliki entropi penuh sebanding dengan ukuran modulus (misal $d \ge 2^{1024}$ untuk modulus 2048-bit). Membatasi eksponen CRT demi optimasi kecepatan komputasi membuka celah faktorisasi instan.
2. **Pertahanan terhadap Serangan Wiener & Small CRT Exponent:**
   Bila eksponen $d_p$ atau $d$ terlalu kecil ($d < \frac{1}{3} N^{0.25}$), algoritma pecahan berlanjut (*continued fractions*) atau pencarian langsung modular dapat memecahkan kunci tanpa perlu memfaktorkan modulus melalui algoritma umum seperti GNFS.
3. **Penerapan NIST SP 800-115:**
   Verifikasi matematis membuktikan bahwa kelemahan struktural pada algoritma kriptografi tidak dapat dimitigasi hanya dengan proteksi aplikasi seperti *Proof-of-Work*. Parameter kunci wajib diperbaiki di tingkat desain sistem.
