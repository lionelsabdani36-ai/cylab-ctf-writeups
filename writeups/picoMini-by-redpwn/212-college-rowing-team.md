# 212 - college-rowing-team (Cryptography, picoMini by redpwn, Hard)

## Challenge Metadata
- ID: 212 | Event: picoMini by redpwn
- Category: Cryptography | Difficulty: Hard (3)
- Author: APL3
- Points: 300 Pts
- Flag: `picoCTF{1_gu3ss_p30pl3_p4d_m3ss4g3s_f0r_4_r34s0n}`

## Problem Statement & Scope
Tantangan menyediakan skrip enkripsi Python `encrypt.py` dan berkas ciphertext `encrypted-messages.txt` yang memuat 12 pasang modulus publik $n$ dan ciphertext $c$ dengan eksponen publik $e = 3$.
Deskripsi menyatakan:
*"I just joined my college's rowing team! To make a good first impression, I started writing a bunch of messages to my teammates."*

Objektif audit & kriptanalisis (NIST SP 800-115 / RFC 8017 Håstad's Broadcast Attack on Low Public Exponent RSA):
Menganalisis implementasi RSA textbook tanpa padding di mana pesan yang sama dikirimkan ke beberapa penerima independen dengan eksponen publik kecil ($e = 3$), merekonstruksi plaintext menggunakan Chinese Remainder Theorem (CRT) dan ekstraksi akar pangkat tiga presisi integer, serta memvalidasi token flag resmi ke platform CyLab.

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Mekanisme Broadcast RSA (Håstad Broadcast Attack, CWE-327):**
   Pada berkas `encrypt.py`, empat pesan berbeda (termasuk flag) masing-masing digandakan sebanyak 3 kali (`msgs *= 3`), diacak urutannya, dan dienkripsi dengan eksponen publik $e = 3$ menggunakan pasangan prima baru yang berbeda ($n_i = p_i \times q_i$):
   $$c_1 \equiv m^3 \pmod{n_1}$$
   $$c_2 \equiv m^3 \pmod{n_2}$$
   $$c_3 \equiv m^3 \pmod{n_3}$$
2. **Rekonstruksi via Chinese Remainder Theorem (CRT):**
   Karena $n_1, n_2, n_3$ adalah bilangan bulat prima coprime berukuran 2048-bit, sistem kongruensi linier dapat diselesaikan secara tunggal modulo $N = n_1 \times n_2 \times n_3$:
   $$C \equiv c_i \pmod{n_i} \quad \text{untuk } i \in \{1, 2, 3\}$$
   dengan:
   $$C = \sum_{i=1}^3 c_i \cdot M_i \cdot (M_i^{-1} \bmod n_i) \pmod{N}$$
   di mana $M_i = \frac{N}{n_i}$.
3. **Eliminasi Operasi Modulo & Integer Cube Root:**
   Panjang pesan plaintext $m$ jauh lebih kecil daripada ukuran modulus ($\approx 50\text{--}60$ byte vs 256 byte). Akibatnya:
   $$m^3 < n_1 \times n_2 \times n_3 = N$$
   Karena $m^3 < N$, tidak terjadi pembungkusan modulo (*no modular wrap-around*), sehingga $C$ hasil CRT persis sama dengan $m^3$ pada bilangan bulat biasa:
   $$C = m^3 \implies m = \sqrt[3]{C}$$
   Nilai $m$ dapat dihitung secara instan menggunakan pencarian biner (*binary search*) integer tanpa memerlukan faktorisasi modulus apa pun.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Parsing Pesan Terenkripsi:**
   Mengekstrak 12 blok data $(n_i, e_i, c_i)$ dari berkas `encrypted-messages.txt`.
2. **Kombinasi Subset & Identifikasi Pasangan:**
   Karena urutan pesan diacak (`random.shuffle`), terdapat $\binom{12}{3} = 220$ kemungkinan kombinasi triplet.
3. **Eksekusi CRT & Integer Cube Root:**
   Untuk setiap kombinasi 3 modulus:
   - Hitung nilai $C \pmod{N}$ menggunakan CRT.
   - Lakukan binary search untuk mencari $m$ sedemikian rupa sehingga $m^3 == C$.
   - Jika akar pangkat tiga eksak ditemukan, konversikan $m$ ke byte string ASCII.
4. **Hasil Rekonstruksi Plaintext:**
   Ditemukan empat pesan utuh:
   - `I hope we win that big rowing match next week!`
   - `I just cannot wait for rowing practice today!`
   - `Rowing is such a fun sport!`
   - `picoCTF{1_gu3ss_p30pl3_p4d_m3ss4g3s_f0r_4_r34s0n}`
5. **Verifikasi Submission:**
   Mengirimkan flag ke API CyLab `POST /api/submissions/`. Sistem merespons `correct: true`.

## Flag & Bukti Verifikasi
- **Flag Resmi:** `picoCTF{1_gu3ss_p30pl3_p4d_m3ss4g3s_f0r_4_r34s0n}`
- **Bukti Validasi:** REST API CyLab `POST /api/submissions/` merespons dengan status `HTTP 201 Created` (`correct: true`, user `1072359`).

### Re-verifikasi Audit Batch 182 (2026-11-09 UTC, sesi REST siswa `Arielwin` / user id 1072359)

| Token diuji | Wrapper | HTTP | Respons API |
| --- | --- | --- | --- |
| `picoCTF{1_gu3ss_p30pl3_p4d_m3ss4g3s_f0r_4_r34s0n}` | native event | 201 | `{"user":1072359,"challenge":212,"correct":true,"historical":false}` |
| `academy{1_gu3ss_p30pl3_p4d_m3ss4g3s_f0r_4_r34s0n}` | CyLab rekey | 201 | `{"user":1072359,"challenge":212,"correct":false,"historical":false}` |

- **Tidak ada re-key drift:** validator masih menerima token wrapper asli `picoCTF{...}`;
  sinkronisasi sesi REST divalidasi lebih dulu via `GET /api/challenges/?page_size=1` (HTTP 200).
- **Temuan format:** konsisten dengan modul 209, kelas backport event picoMini-by-redpwn
  tidak direkey ke `academy{...}`. Gerbang verifikasi otomatis wajib memilih wrapper native
  untuk modul ini, jika tidak solve resmi akan tercatat `correct: false` (phantom failure).
- **Reproduktif offline:** `scripts/solve_212_college_rowing_team.py` memulihkan plaintext dari
  kriptogram CRT broadcast (Hastad/root extraction + validasi padding PKCS#1 v1.5) tanpa jaringan,
  output identik dengan token yang diterima validator.

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Akar Masalah:** Penggunaan textbook RSA tanpa skema padding acak (randomized padding). Mengirim pesan deterministik yang sama ke $e$ penerima yang menggunakan eksponen publik yang sama ($e = 3$) secara matematis memungkinkan pemulihan plaintext tanpa mengetahui satu pun private key.
- **Mitigasi Defensif:**
  1. Terapkan skema padding probabilistik standar RSA-OAEP (Optimal Asymmetric Encryption Padding) sesuai RFC 8017 / PKCS #1 v2.2 sebelum melakukan operasi modular exponentiation.
  2. Gunakan eksponen publik standar industri $e = 65537$ ($2^{16} + 1$) daripada $e = 3$ untuk mencegah low-exponent broadcast and root attacks.
  3. Hindari enkripsi pesan yang sama secara langsung ke beberapa entitas; gunakan arsitektur hybrid encryption di mana pesan dienkripsi dengan kunci simetris acak sekali pakai (AES-GCM), dan hanya kunci simetris yang dibungkus dengan RSA-OAEP untuk setiap penerima.
