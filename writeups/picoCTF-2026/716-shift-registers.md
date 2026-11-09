# Writeup: shift registers (Challenge ID: 716)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Linear Feedback Shift Register (LFSR) Keyspace Exhaustion
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** picoCTF
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{l1n3ar_f33dback_sh1ft_r3g}`
- **Flag Komunitas:** `CTF{l1n3ar_f33dback_sh1ft_r3g}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), NIST SP 800-132 (Recommendation for Key Derivation: Entropy Integrity), FIPS 140-3 (Security Requirements for Cryptographic Modules: PRNG State Space), & CWE-326 (Inadequate Encryption Strength).

---

## Problem Statement & Scope

Pada modul bimbingan teknis persiapan lomba LKS `shift registers`, peserta diuji dalam menganalisis batas kekuatan pembangkit bilangan acak semu (PRNG) berbasis register geser dan keruntuhan entropi kunci (*entropy collapse*):
- Skenario lingkungan: Diberikan dua berkas artefak kriptografis:
  1. Skrip enkripsi stream cipher berbasis LFSR: `shift_registers.py`.
  2. Berkas keluaran ciphertext heksadesimal: `output.txt` (berukuran 34 byte / 68 karakter heksadesimal).
- Pernyataan tantangan:
  > *"I learned about lfsr today in school so i decided to implement it in my program. It must be safe right?"*
- Sasaran pengujian:
  1. Meneliti kode implementasi generator keystream pada skrip `shift_registers.py`.
  2. Mengidentifikasi cacat arsitektur pemotongan bit (*bit masking truncation*) yang menghancurkan ruang keadaan (*state space*).
  3. Memodelkan fungsi pergeseran LFSR Galois/Fibonacci 8-bit dalam bahasa Python.
  4. Melakukan *keyspace exhaustion* (brute-force) terhadap seluruh 256 kandidat nilai awal register dalam waktu < 5 ms.
  5. Memvalidasi token plaintext resmi yang terisolasi pada endpoint REST API CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Penyempitan Entropi Kunci Kritis (*Key Space Collapse*, CWE-326):**
   Pengembang berusaha menghasilkan kunci acak yang kuat dengan memanggil pustaka kriptografi standar:
   ```python
   key = get_random_bytes(126)  # 126 byte = 1008 bit entropi potensial
   ```
   Namun, pada tahap inisialisasi status internal register geser:
   ```python
   lfsr = key & 0xFF  # Hanya mengambil 1 byte terendah (8-bit)
   ```
   Operasi bitwise AND `& 0xFF` memangkas 1000 bit entropi acak yang telah dibangkitkan. Akibatnya, seluruh ruang keadaan awal (*initial state*) menyusut drastis menjadi hanya:
   $$|S| = 2^8 = 256 \text{ kemungkinan}$$

2. **Dinamika Register Geser Berumpan Balik Linear (LFSR):**
   LFSR adalah struktur pergeseran bit yang memperbarui statusnya menggunakan fungsi boolean linear di atas medan hingga $\mathbb{F}_2$.
   Polinomial umpan balik pada tantangan ini didefinisikan oleh tap bit 7, 5, 4, dan 3:
   $$\text{Feedback} = b_7 \oplus b_5 \oplus b_4 \oplus b_3$$
   Pembaruan status register dilakukan melalui pergeseran kanan dengan menyuntikkan bit umpan balik pada posisi tertinggi:
   $$\text{State}_{t+1} = (\text{Feedback} \ll 7) \mid (\text{State}_t \gg 1)$$
   Karena register hanya memiliki lebar 8 bit, panjang siklus periodisitas maksimum bernilai paling banyak $2^8 - 1 = 255$ keadaan (jika polinomial primitif). Generator keystream ini sepenuhnya tidak memiliki sifat non-linearitas (seperti S-Box atau fungsi boolean berderajat tinggi), sehingga gagal memenuhi kriteria keamanan stream cipher modern.

3. **Kompleksitas Pencarian Menyeluruh (Exhaustive Sweep):**
   Dengan hanya 256 titik awal yang mungkin:
   - Pencarian brute-force hanya membutuhkan 256 simulasi dekripsi sepanjang 34 byte ($256 \times 34 = 8.704$ operasi XOR bita).
   - Seluruh ruang kunci dapat dievaluasi dalam waktu kurang dari 5 milidetik pada CPU modern tanpa akselerasi perangkat keras.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pemeriksaan Skrip Sumber `shift_registers.py`:**
   Membaca alur pembangkitan keystream dan proses enkripsi:
   ```python
   def steplfsr(lfsr):
       b7 = (lfsr >> 7) & 1
       b5 = (lfsr >> 5) & 1
       b4 = (lfsr >> 4) & 1
       b3 = (lfsr >> 3) & 1
       feedback = b7 ^ b5 ^ b4 ^ b3
       return (feedback << 7) | (lfsr >> 1)
   ```
   Dikonfirmasi bahwa nilai `lfsr` diperbarui per siklus dan digunakan langsung sebagai byte keystream untuk mengenkripsi flag karakter per karakter via XOR:
   ```python
   for c in flag:
       lfsr = steplfsr(lfsr)
       ciphertext.append(ord(c) ^ lfsr)
   ```

2. **Ekstraksi Ciphertext:**
   Ciphertext dari `output.txt` berukuran 34 byte:
   `30cbb50e507774fdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9`

3. **Pencarian Menyeluruh (Brute-Force 256 Seed Awal):**
   Menguji setiap integer $\text{init} \in [0, 255]$:
   - Menginisialisasi register: `state = init`.
   - Mengiterasi sepanjang 34 byte ciphertext:
     `state = steplfsr(state)`
     `plaintext_byte = ciphertext_byte ^ state`
   - Memfilter kandidat teks hasil dekripsi yang memuat substring penanda flag resmi `academy{`.

4. **Isolasi Plaintext & Pemulihan Flag:**
   - Pada iterasi ke-162 (`init = 0xA2` atau 162 desimal), filter mendeteksi string ASCII yang dapat dibaca manusia (*human-readable*):
     `academy{l1n3ar_f33dback_sh1ft_r3g}`.
   - Tidak ada seed lain dalam interval $[0, 255]$ yang menghasilkan teks yang bermakna, memastikan keunikan solusi.

5. **Validasi Submisi ke REST API CyLab Academy:**
   Mengirimkan token ke endpoint `POST /api/submissions/` dengan payload JSON `{"challenge": 716, "flag": "academy{l1n3ar_f33dback_sh1ft_r3g}"}`:
   ```bash
   python3 scripts/solve_716_shift_registers.py --submit
   ```
   Server mengembalikan kode status HTTP `201 Created` dengan konfirmasi validasi `correct: true`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{l1n3ar_f33dback_sh1ft_r3g}`
- **Flag Komunitas:** `CTF{l1n3ar_f33dback_sh1ft_r3g}`
- **Log Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 716,
    "flag": "academy{l1n3ar_f33dback_sh1ft_r3g}",
    "correct": true,
    "historical": false
  }
  ```
  Status respons HTTP: `201 Created` mengonfirmasi token valid dan tercatat secara definitif pada platform.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Rekomendasi Remediasi & Hardening (Defensive Perspective):**
   - **Pemeliharaan Entropi Penuh & KDF Standar (NIST SP 800-132):** Jangan pernah memotong material kunci acak menjadi sub-panjang yang sempit. Jika material kunci perlu disesuaikan dengan parameter cipher, gunakan algoritma derivasi kunci formal seperti HKDF (RFC 5869) atau PBKDF2 dengan salt yang kuat dan parameter iterasi yang memadai.
   - **Larangan Penggunaan LFSR Polos Tanpa Filter Non-Linear:** LFSR murni tidak boleh digunakan sebagai cipher aliran mandiri (*stand-alone stream cipher*). Untuk enkripsi aliran yang aman, gunakan algoritma berstandar industri seperti ChaCha20 (RFC 8439) atau AES-GCM (NIST SP 800-38D). Jika arsitektur berbasis LFSR diterapkan (misalnya pada perangkat keras terbatas), wajib dilengkapi dengan generator non-linear berlapis (*non-linear filter / combiner*) dan panjang status register minimal 128 bit (seperti eSTREAM Trivium atau Grain-128a).
   - **Jaminan Minimum State Space (FIPS 140-3):** Setiap implementasi modul kriptografi wajib menjamin ruang pencarian minimal $2^{128}$ bit (atau $2^{256}$ bit untuk ketahanan jangka panjang / post-quantum) untuk mengeliminasi kerentanan terhadap serangan *brute-force* atau *table lookup*.

2. **Relevansi Modul LKS Cyber Security:**
   - **Kriptoanalisis Algoritma Acak Semu (PRNG Reverse Engineering):** Peserta LKS Cyber Security harus mampu menganalisis kelemahan implementasi pembangkit bilangan acak, mengenali titik kegagalan pemotongan entropi, dan mengotomasi brute-force ruang kunci menggunakan skrip Python deterministik.
   - **Pemodelan Struktur Keadaan Bit (Bitwise Modeling):** Melatih peserta dalam memanipulasi operasi tingkat bit (*bitwise shifts*, *masks*, *XOR accumulators*) untuk merekonstruksi logika algoritma kriptografi kustom.
