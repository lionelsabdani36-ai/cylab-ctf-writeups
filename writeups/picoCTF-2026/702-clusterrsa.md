# Writeup: ClusterRSA (Challenge ID: 702)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Multi-prime RSA & Clustered Modulus Factorization
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** CyLab Cryptography Team
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{mul71_rsa_411fc267}`
- **Flag Komunitas:** `CTF{mul71_rsa_411fc267}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), NIST SP 800-56B Rev. 2 (Recommendation for Pair-Wise Key-Establishment Schemes Using Integer Factorization Cryptography), RFC 8017 (PKCS #1 v2.2: RSA Cryptography Specifications - Multi-Prime RSA), CWE-326 (Inadequate Encryption Strength), & CWE-310 (Cryptographic Issues).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis LKS Cyber Security `ClusterRSA`, peserta diuji dalam menganalisis kelemahan perancangan sistem kriptografi asimetris RSA yang mengimplementasikan modulus multi-prima (*multi-prime RSA*) dengan sebaran faktor prima yang berdekatan (*clustered primes*):
- **Skenario Lingkungan:** Diberikan berkas artefak `message.txt` yang memuat parameter kriptografi kunci publik dan pesan terenkripsi:
  1. Modulus $N$ berukuran 333-bit:
     ```text
     n = 8749002899132047699790752490331099938058737706735201354674975134719667510377522805717156720453193651
     ```
  2. Eksponen publik standar: $e = 65537$ ($2^{16} + 1$).
  3. Ciphertext desimal:
     ```text
     ct = 6077311710730157058547975173005494694880887687368910290510611316416980539628903279743851720077932545
     ```
- **Batasan & Arsitektur Lab:**
  1. Modulus $N$ tidak dibentuk dari 2 bilangan prima berukuran seimbang 1024/2048-bit, melainkan tersusun atas 4 faktor prima berukuran kecil ($\sim 83$ bit per prima).
  2. Keempat faktor prima saling berdekatan nilainya (*clustered*) di sekitar nilai $\sqrt[4]{N}$.
  3. Skema enkripsi tidak menggunakan padding acak terstandarisasi (OAEP), melainkan textbook modular exponentiation: $ct \equiv m^e \pmod N$.
- **Sasaran Pengujian:**
  1. Melakukan faktorisasi modulus komposit multi-prima $N$ menjadi 4 bilangan prima $p_1, p_2, p_3, p_4$ memanfaatkan layanan basis data faktorisasi publik (FactorDB) atau algoritma Lenstra ECM.
  2. Menghitung fungsi totient Euler yang diperluas untuk multi-prime RSA: $\phi(N) = \prod_{i=1}^4 (p_i - 1)$.
  3. Menurunkan eksponen privat $d = e^{-1} \pmod{\phi(N)}$.
  4. Mendekripsi ciphertext $ct$, memverifikasi roundtrip enkripsi $m^e \equiv ct \pmod N$, dan memvalidasi token bukti ke REST API CyLab Academy (`POST /api/submissions/`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Prinsip Keamanan Asimetris RSA (NIST SP 800-56B Rev. 2):**
   Keamanan algoritma RSA bertumpu pada kesulitan komputasi masalah faktorisasi bilangan bulat besar (*integer factorization problem*). Modulus RSA standar dibentuk dari perkalian dua bilangan prima besar yang dipilih secara acak independen:
   $$N = p \cdot q$$
   Untuk menjamin tingkat keamanan 112-bit (ekuivalen AES-128), NIST mensyaratkan panjang modulus minimal 2048-bit dengan masing-masing faktor prima berukuran minimal 1024-bit.

2. **Dekomposisi Multi-Prime RSA (RFC 8017 / PKCS #1 v2.2) (CWE-326):**
   RFC 8017 Section 3 memperbolehkan penggunaan multi-prime RSA di mana $N = \prod_{i=1}^u r_i$ dengan $u \ge 3$ untuk mempercepat operasi dekripsi melalui Chinese Remainder Theorem (CRT). Namun, membagi panjang total modulus ke dalam beberapa prima kecil mendegradasi resistensi terhadap algoritma faktorisasi modern:
   - Kompleksitas faktorisasi metode *Elliptic Curve Method* (ECM) bergantung pada ukuran faktor prima terkecil, bukan ukuran total modulus $N$.
   - Pada tantangan ini, $N$ berukuran 333-bit dibagi menjadi 4 faktor prima:
     $$\text{Panjang } p_i \approx \frac{333}{4} \approx 83.25\text{ bit}$$
   - Bilangan prima berukuran 83-bit dapat difaktorkan dalam hitungan milidetik oleh implementasi ECM modern atau langsung dicocokkan pada repositori faktorisasi publik (FactorDB).

3. **Anomali Kluster Faktor Prima (*Prime Proximity Defect*):**
   Seluruh 4 faktor prima memiliki selisih nilai yang sangat kecil:
   $$p_1 = 9671406556917033397931773$$
   $$p_2 = 9671406556917033398314601 \quad (\Delta = 382828)$$
   $$p_3 = 9671406556917033398439721 \quad (\Delta = 125120)$$
   $$p_4 = 9671406556917033398454847 \quad (\Delta = 15126)$$
   Kedekatan ekstrim ini mengindikasikan kegagalan generator bilangan acak kriptografis (PRNG defect), di mana pencarian bilangan prima dilakukan dengan sekuens incremental sederhana di sekitar titik awal yang sama.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Faktorisasi Modulus $N$ via FactorDB REST API:**
   Mengirimkan kueri nilai $N$ ke endpoint FactorDB (`http://factordb.com/api?query=...`):
   ```python
   factors = [
       9671406556917033397931773,
       9671406556917033398314601,
       9671406556917033398439721,
       9671406556917033398454847
   ]
   assert factors[0] * factors[1] * factors[2] * factors[3] == n
   ```

2. **Perhitungan Fungsi Totient Euler $\phi(N)$:**
   Untuk komposit bebas kuadrat dengan 4 faktor prima, nilai fungsi totient dihitung sebagai:
   $$\phi(N) = (p_1 - 1)(p_2 - 1)(p_3 - 1)(p_4 - 1)$$
   ```python
   phi = 1
   for p in factors:
       phi *= (p - 1)
   ```

3. **Penurunan Kunci Privat $d$ dan Dekripsi Plaintext:**
   Menghitung modular multiplicative inverse dari $e$ modulo $\phi(N)$ menggunakan algoritma Extended Euclidean:
   ```python
   d = pow(e, -1, phi)
   m = pow(ct, d, n)
   flag = m.to_bytes((m.bit_length() + 7) // 8, "big").decode("utf-8")
   ```
   Keluaran teks menghasilkan flag: `academy{mul71_rsa_411fc267}`.

4. **Verifikasi Roundtrip Matematis:**
   Menguji validitas integritas matematis dengan mengenkripsi kembali nilai $m$:
   ```python
   assert pow(m, e, n) == ct
   ```

5. **Submisi Token Live ke REST API CyLab:**
   Mengeksekusi skrip solver mandiri `scripts/solve_702_clusterrsa.py` dengan parameter submisi resmi:
   ```bash
   python3 scripts/solve_702_clusterrsa.py --submit
   ```
   Server CyLab Academy memvalidasi token dengan respons HTTP 201 Created:
   ```json
   {"user": 1072359, "challenge": 702, "flag": "academy{mul71_rsa_411fc267}", "correct": true, "historical": false}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{mul71_rsa_411fc267}`
- **Flag Komunitas:** `CTF{mul71_rsa_411fc267}`
- **Status Validasi:** Terverifikasi 100% via REST API `POST https://learn.cylabacademy.org/api/submissions/` (HTTP 201 Created, `correct: true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Relevansi Kurikulum LKS Cyber Security (Kriptanalisis RSA & Audit Parameter Kunci):**
   - Peserta LKS harus memahami bahwa panjang modulus publik $N$ bukanlah satu-satunya parameter penentu keamanan; ukuran masing-masing faktor prima merupakan batas ketahanan terhadap serangan faktorisasi ECM.
   - Menguasai pemanfaatan utilitas otomatisasi analisis bilangan bulat besar (FactorDB, SageMath, PARI/GP) untuk menyelesaikan skenario audit kunci kriptografi.

2. **Rekomendasi Mitigasi Defensif (NIST SP 800-56B Rev. 2):**
   - **Tegakkan Batas Minimum Panjang Kunci:** Modulus RSA untuk penggunaan operasional wajib berukuran minimal 2048-bit (disarankan 3072-bit atau 4096-bit).
   - **Gunakan Tepat Dua Faktor Prima Seimbang:** Hindari arsitektur multi-prime untuk sistem dengan kebutuhan keamanan tinggi; pastikan $p$ dan $q$ adalah bilangan prima acak independen dengan selisih $|p - q| > 2^{nlen/2 - 100}$ guna mencegah serangan Fermat.
   - **Wajibkan Skema Padding Modern (RSA-OAEP):** Jangan pernah mengimplementasikan enkripsi RSA tanpa padding (textbook RSA). Terapkan skema Optimal Asymmetric Encryption Padding (OAEP, RFC 8017) untuk mencegah serangan matematis homomorfik dan manipulasi ciphertext.
