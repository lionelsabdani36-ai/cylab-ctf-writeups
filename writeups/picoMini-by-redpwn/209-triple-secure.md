# 209 - triple-secure (Cryptography, picoMini by redpwn, Hard)

## Challenge Metadata
- ID: 209 | Event: picoMini by redpwn
- Category: Cryptography | Difficulty: Hard (3)
- Author: APL3
- Points: 300 Pts
- Flag: `picoCTF{1_gu3ss_tr1pl3_rs4_1snt_tr1pl3_s3cur3!!!!!!}`

## Problem Statement & Scope
Tantangan memberikan kode Python pembangkit kunci `encrypt.py` dan berkas parameter publik `public-key.txt`.
Deskripsi menyatakan:
*"To get the flag, you must break RSA not once, but three times!"*

Objektif audit & kriptanalisis (NIST SP 800-115 / RFC 8017 PKCS #1 Multi-Key Common Modulus Factorization):
Menganalisis skema enkripsi RSA bertingkat tiga yang menggunakan tiga modulus terpisah namun memiliki ketergantungan faktor prima bersama (*shared prime factors*), merekonstruksi seluruh faktor prima menggunakan algoritma Euclidean GCD dalam kompleksitas $O(\log n)$, memulihkan eksponen dekripsi privat bertingkat, dan memvalidasi token flag resmi ke platform CyLab.

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Arsitektur Enkripsi Berlapis (Multi-Layer RSA):**
   Skrip `encrypt.py` menghasilkan tiga bilangan prima acak 1024-bit $p, q, r$. Tiga modulus publik 2048-bit dibentuk dari kombinasi pasangan prima tersebut:
   $$n_1 = p \times q$$
   $$n_2 = p \times r$$
   $$n_3 = q \times r$$
   Plaintext flag $m$ dienkripsi tiga kali secara berurutan dengan eksponen publik $e = 65537$:
   $$c_1 \equiv m^e \pmod{n_1}$$
   $$c_2 \equiv c_1^e \pmod{n_2}$$
   $$c \equiv c_3 \equiv c_2^e \pmod{n_3}$$
2. **Kelemahan Kriptografi Kritis — Common Factor Vulnerability (CWE-326 / NIST SP 800-56B):**
   Kekuatan RSA bergantung pada komputasi faktorisasi integer besar yang sulit dipecahkan (intractable). Namun, jika dua modulus RSA berbeda berbagi satu faktor prima yang identik:
   $$\gcd(n_1, n_2) = p$$
   Operasi pembagi bersama terbesar (Greatest Common Divisor) dapat dihitung secara instan menggunakan algoritma Euclidean dalam waktu kurang dari 1 milidetik tanpa memerlukan faktorisasi bilangan besar.
3. **Rekonstruksi Faktor Penuh:**
   Setelah faktor $p$ diperoleh:
   $$q = \frac{n_1}{p}$$
   $$r = \frac{n_2}{p}$$
   Konsistensi diverifikasi melalui pembuktian $q \times r == n_3$.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Parameter Publik:**
   Membaca nilai integer dari `public-key.txt`: $n_1, n_2, n_3, e, c$.
2. **Kalkulasi GCD & Faktorisasi:**
   - Menghitung `p = math.gcd(n1, n2)`.
   - Menghitung `q = n1 // p` dan `r = n2 // p`.
   - Memvalidasi bahwa perkalian `q * r` bernilai identik dengan `n3`.
3. **Pembalikan Enkripsi Bertahap (Reverse Sequential Decryption):**
   - **Lapisan 3 ($n_3 = q \times r$):**
     $$\phi_3 = (q - 1)(r - 1)$$
     $$d_3 \equiv e^{-1} \pmod{\phi_3}$$
     $$c_2 \equiv c^{d_3} \pmod{n_3}$$
   - **Lapisan 2 ($n_2 = p \times r$):**
     $$\phi_2 = (p - 1)(r - 1)$$
     $$d_2 \equiv e^{-1} \pmod{\phi_2}$$
     $$c_1 \equiv c_2^{d_2} \pmod{n_2}$$
   - **Lapisan 1 ($n_1 = p \times q$):**
     $$\phi_1 = (p - 1)(q - 1)$$
     $$d_1 \equiv e^{-1} \pmod{\phi_1}$$
     $$m \equiv c_1^{d_1} \pmod{n_1}$$
4. **Konversi Byte:**
   Mengubah integer $m$ ke format byte string big-endian:
   `picoCTF{1_gu3ss_tr1pl3_rs4_1snt_tr1pl3_s3cur3!!!!!!}`.
5. **Verifikasi Submission:**
   Mengirim flag ke API CyLab `POST /api/submissions/`. Platform mengembalikan `correct: true`.

## Flag & Bukti Verifikasi
- **Flag Resmi:** `picoCTF{1_gu3ss_tr1pl3_rs4_1snt_tr1pl3_s3cur3!!!!!!}`
- **Bukti Validasi:** REST API CyLab `POST /api/submissions/` merespons dengan status `HTTP 201 Created` (`correct: true`, user `1072359`).

### Re-verifikasi Audit Batch 182 (2026-11-09 UTC, sesi REST siswa `Arielwin` / user id 1072359)

| Token diuji | Wrapper | HTTP | Respons API |
| --- | --- | --- | --- |
| `picoCTF{1_gu3ss_tr1pl3_rs4_1snt_tr1pl3_s3cur3!!!!!!}` | native event | 201 | `{"user":1072359,"challenge":209,"correct":true,"historical":false}` |
| `academy{1_gu3ss_tr1pl3_rs4_1snt_tr1pl3_s3cur3!!!!!!}` | CyLab rekey | 201 | `{"user":1072359,"challenge":209,"correct":false,"historical":false}` |

- **Tidak ada re-key drift:** validator masih menerima token wrapper asli `picoCTF{...}`.
- **Temuan format (penting untuk pipeline otomasi LKS):** modul hasil backport event
  (picoMini-by-redpwn) TIDAK direkey ke `academy{...}`. Submissi dengan wrapper CyLab
  ditolak `correct: false` walau inner token identik. Gerbang verifikasi otomatis wajib
  memakai wrapper native untuk kelas modul ini, bukan asumsi `academy{...}` global
  (kontras dengan modul CyLab-native seperti seri Investigation Encoded, batch 181).
- **Reproduktif offline:** `scripts/solve_209_triple_secure.py` mencetak flag tanpa akses
  jaringan (shared-prime GCD lintas keypair), output cocok 100% dengan token yang diterima validator.

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Akar Masalah:** Developer berasumsi bahwa menumpuk lapisan enkripsi (defense-in-depth semu) akan meningkatkan keamanan. Namun, penggunaan kembali komponen prima (*prime reuse / factor sharing*) di beberapa kunci publik menghancurkan asumsi keamanan RSA secara mendasar.
- **Mitigasi Defensif:**
  1. Setiap pasangan kunci RSA wajib menghasilkan sepasang bilangan prima independen yang dihasilkan dari CSPRNG (Cryptographically Secure Pseudorandom Number Generator) terpisah.
  2. Jangan pernah menggunakan kembali faktor prima $p$ atau $q$ untuk kunci lain.
  3. Terapkan audit pairwise GCD pada kumpulan kunci publik (seperti temuan Ron Was Wrong, Whitfield Diffie 2012) untuk mendeteksi kolisi faktor sebelum kunci dideploy ke produksi.
