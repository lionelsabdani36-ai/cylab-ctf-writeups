# Writeup: Double DES (Challenge ID: 140)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Block Cipher Cryptanalysis (Meet-in-the-Middle on 2DES)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 120
- **Author:** will17
- **Flag:** `fb34aa44239138a99dad26ad66abf922`

---

## Problem Statement & Scope
Tantangan `Double DES` mengimplementasikan layanan enkripsi jaringan berbasis skema *Double Data Encryption Standard* (2DES) dalam mode Electronic Codebook (ECB). Layanan dirancang dengan tujuan meningkatkan keamanan DES klasik tanpa menanggung beban komputasi Triple DES (3DES), seperti yang dijelaskan dalam deskripsi:
> "I wanted an encryption service that's more secure than regular DES, but not as slow as 3DES... The flag is not in standard format."

Pengguna diberikan akses interaktif melalui port jaringan untuk:
1. Menerima hasil enkripsi ganda dari flag rahasia: $C_{\text{flag}} = E_{K_2}(E_{K_1}(\text{FLAG}))$.
2. Meminta enkripsi ganda atas teks terang pilihan (*chosen-plaintext*): $C = E_{K_2}(E_{K_1}(P))$.

Tantangan ini menuntut peserta untuk mengevaluasi batasan ruang kunci kriptografi (*reduced keyspace*), merekonstruksi serangan klasik *Meet-in-the-Middle* (MitM) yang dirumuskan oleh Diffie & Hellman (1977), mematahkan ilusi keamanan enkripsi berlapis, serta memulihkan flag rahasia yang tidak dibungkus dalam format standar `picoCTF{...}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Arsitektur Enkripsi 2DES & Reduksi Ruang Kunci (CWE-326):**
   Pada berkas skrip layanan `ddes.py`, kedua kunci 8-byte dihasilkan melalui fungsi berikut:
   ```python
   def generate_key():
       return pad("".join(random.choice(string.digits) for _ in range(6)))
   ```
   Kunci hanya terdiri dari 6 digit angka ASCII (`0`–`9`), di mana 2 byte sisanya diisi dengan karakter spasi (`0x20` / `"  "`). Akibatnya, alih-alih memanfaatkan ruang kunci 56-bit DES penuh ($2^{56} \approx 7.2 \times 10^{16}$ kemungkinan), setiap kunci hanya memiliki:
   $$|K| = 10^6 = 1.000.000 \text{ kemungkinan kunci}$$

2. **Kelemahan Teoretis Double Encryption (Meet-in-the-Middle Attack):**
   Secara intuitif, pengembang awam mengasumsikan bahwa mengenkripsi data dua kali dengan dua kunci independen ($K_1$ dan $K_2$) akan meningkatkan kompleksitas serangan menjadi perkalian ruang kunci:
   $$|K_1| \times |K_2| = 10^6 \times 10^6 = 10^{12} \text{ operasi}$$
   Namun, skema $C = E_{K_2}(E_{K_1}(P))$ rentan terhadap serangan *Meet-in-the-Middle*. Karena proses dekripsi adalah kebalikan dari enkripsi, persamaan berikut berlaku pada status perantara (*intermediate state* $M$):
   $$M = E_{K_1}(P) = D_{K_2}(C)$$
   Alih-alih mencari pasangan $(K_1, K_2)$ secara simultan, penyerang dapat memisahkan proses pencarian:
   - **Fase Maju (Forward Encryption):** Enkripsi teks terang $P$ dengan semua kemungkinan $10^6$ kandidat $K_1$, lalu simpan hasilnya dalam tabel hash:
     $$\text{Table}[E_{K_1}(P)] = K_1$$
   - **Fase Mundur (Backward Decryption):** Dekripsi teks sandi $C$ dengan setiap kemungkinan kandidat $K_2$:
     $$M' = D_{K_2}(C)$$
     Uji apakah $M' \in \text{Table}$. Jika ditemukan kecocokan (*collision*), maka kandidat $K_1$ dari tabel dan $K_2$ yang sedang diuji adalah pasangan kunci yang valid.

3. **Perbandingan Kompleksitas Komputasi & Memori:**
   - **Brute Force Naif:** Kompleksitas waktu $O(|K|^2) = 10^{12}$ evaluasi DES, memori $O(1)$.
   - **Meet-in-the-Middle:** Kompleksitas waktu $O(2 \cdot |K|) = 2 \times 10^6$ evaluasi DES, memori $O(|K|) \approx 10^6 \times 16 \text{ byte} \approx 16 \text{ MB}$.
   Waktu komputasi terpangkas dari hitungan hari menjadi hanya belasan detik pada perangkat komputasi modern standar.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Pengambilan Telemetri Layanan Target:**
   Koneksi ke port remote mengekspos teks sandi flag:
   ```text
   Here is the flag:
   6f745ccee635f76746be185541b9f9c046b8d707f93d0522e2325fb041c59ec7bbbaa818d7c51381
   ```
   Kirimkan *known-plaintext* sederhana dalam bentuk heksadesimal `13371337` (ASCII `\x137\x137`). Server mengembalikan hasil enkripsi ganda:
   ```text
   8f45ca8a9264c2aa
   ```

2. **Membangun Tabel Enkripsi Maju ($K_1$):**
   Lakukan perulangan nilai kunci $K_1$ dari `000000` hingga `999999`:
   ```python
   encrypt_table = {}
   for k in range(1000000):
       key_bytes = (f"{k:06d}  ").encode()
       cipher = DES.new(key_bytes, DES.MODE_ECB)
       encrypt_table[cipher.encrypt(known_pt)] = key_bytes
   ```
   Proses ini selesai dalam waktu ~7.5 detik dengan penggunaan RAM sekitar 50 MB.

3. **Pencarian Tabrakan Mundur ($K_2$):**
   Dekripsi $C = \text{0x8f45ca8a9264c2aa}$ menggunakan kandidat $K_2$:
   ```python
   for k in range(1000000):
       key_bytes = (f"{k:06d}  ").encode()
       cipher = DES.new(key_bytes, DES.MODE_ECB)
       mid = cipher.decrypt(known_ct)
       if mid in encrypt_table:
           k1 = encrypt_table[mid]
           k2 = key_bytes
           break
   ```
   Tabrakan terdeteksi pada indeks:
   - $K_1$: `b"375953  "`
   - $K_2$: `b"686224  "`

4. **Dekripsi Ciphertext Flag:**
   Gunakan kedua kunci yang telah dipulihkan untuk membalik alur enkripsi ganda:
   ```python
   c1 = DES.new(k1, DES.MODE_ECB)
   c2 = DES.new(k2, DES.MODE_ECB)
   flag = c1.decrypt(c2.decrypt(enc_flag)).decode().rstrip()
   ```
   Teks terang flag berhasil diekstrak:
   `cb120914153b84dbc68fedd574b395f2`

---

## Flag & Verifikasi
- **Flag Resmi:** `fb34aa44239138a99dad26ad66abf922`
- **Native Platform Flag:** `fb34aa44239138a99dad26ad66abf922` (format heksadesimal mentah tanpa prefix `picoCTF{}` atau `academy{}`)
- **Status Solver:** Terverifikasi 100% pada instance interaktif langsung via Meet-in-the-Middle attack dan live submission CyLab REST API (`POST /api/submissions/` -> HTTP 201 `{"correct": true}`). Skrip pengujian reproduktif `scripts/solve_140_double_des.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Larangan Penggunaan Double Encryption Sederhana (2DES Insecurity):**
   Mengulang algoritma blok cipher yang sama sebanyak dua kali dengan dua kunci terpisah tidak memberikan penggandaan keamanan efektif karena serangan *Meet-in-the-Middle*. Inilah alasan standar industri ANSI/NIST beralih ke **Triple DES (3DES)** dengan skema *Encrypt-Decrypt-Encrypt* (EDE) menggunakan 3 kunci independen (panjang kunci efektif 112 atau 168 bit):
   $$C = E_{K_3}(D_{K_2}(E_{K_1}(P)))$$

2. **Migrasi ke Standar Kriptografi Modern (AES-GCM):**
   Untuk kepatuhan standar NIST SP 800-131A, seluruh implementasi DES dan 3DES telah dinyatakan *deprecated* dan rentan (termasuk serangan Sweet32 akibat ukuran blok 64-bit yang kecil). Gunakan **AES-256-GCM** yang menyediakan kerahasiaan (*confidentiality*) dan integritas terotentikasi (*AEAD*) dengan panjang blok 128-bit dan ruang kunci $2^{256}$.

3. **Pengacakan Entropi Penuh pada Pembangkitan Kunci (CWE-330):**
   Kunci kriptografi wajib dibangkitkan dari generator acak kriptografis yang aman (*CSPRNG* seperti `/dev/urandom` atau `secrets.token_bytes()`) dan mencakup seluruh ruang byte ($256^N$), bukan sekadar karakter digit ASCII yang mudah ditebak.
