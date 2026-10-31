# Writeup: cryptomaze (Challenge ID: 703)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / LFSR Key Derivation & AES ECB
- **Difficulty:** Medium (Difficulty 2)
- **Author:** Sabine Gisagara
- **Event:** picoCTF 2026
- **Points:** 100
- **Flag:** `academy{scr8mbledt_flvg_cc02eb30}`

---

## Problem Statement & Scope
Diberikan berkas artefak `output.txt` yang memuat konfigurasi generator Linear Feedback Shift Register (LFSR) 64-bit beserta rekaman ciphertext terenkripsi AES. Berkas menyertakan secara eksplisit:
1. Keadaan awal LFSR 64-bit (*Initial State array* beranggotakan 64 elemen biner).
2. Indeks tap umpan balik (*Feedback Taps*: `[63, 61, 60, 58]`).
3. Ciphertext bendera dalam format heksadesimal berukuran 48 byte.

Tantangan menuntut rekonstruksi aliran bit keluaran LFSR untuk menurunkan kunci simetris AES-128 dan mendekripsi blok ciphertext mode ECB.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pemaparan Parameter State Generator (*Complete State Exposure*):**
   Kekuatan kriptografis dari skema derivasi kunci bergantung pada kerahasiaan *seed* atau *state* awal. Dalam tantangan ini, seluruh keadaan internal register 64-bit dan posisi polinomial umpan balik dipublikasikan secara terbuka pada file output.
2. **Determinisme Linear LFSR:**
   Operasi pergeseran dan perhitungan bit umpan balik LFSR sepenuhnya deterministik dan dapat direproduksi secara matematis:
   $$\text{feedback}_t = \bigoplus_{i \in \{63, 61, 60, 58\}} \text{state}_t[i]$$
   Pergeseran bit ke kiri dengan bit keluaran pertama yang diekstraksi dari $\text{state}_t[0]$ menghasilkan deretan 128 bit pseudorandom yang dapat diturunkan secara langsung tanpa ketidakpastian.
3. **Penggunaan AES Mode ECB (*Electronic Codebook*):**
   Meskipun AES merupakan standar enkripsi blok yang kokoh, enkripsi dalam mode ECB tidak mengimplementasikan vektor inisialisasi (IV) atau chaining antar blok. Begitu kunci 16-byte (128 bit) terkonstruksi dari paket bit LFSR, dekripsi setiap blok 16-byte dapat dilakukan secara independen.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Konfigurasi LFSR:**
   - Panjang register: 64 bit
   - Taps: `[63, 61, 60, 58]`
   - Panjang keystream yang dibutuhkan: 128 bit (16 byte untuk kunci AES-128)
2. **Simulasi Stepping LFSR:**
   Untuk setiap siklus clock dari 0 hingga 127:
   - Hitung nilai XOR dari elemen pada indeks tap:
     $$\text{fb} = \text{state}[63] \oplus \text{state}[61] \oplus \text{state}[60] \oplus \text{state}[58]$$
   - Keluarkan bit terdepan: $\text{bit} = \text{state}[0]$
   - Geser register ke kiri: buang $\text{state}[0]$ dan tambahkan $\text{fb}$ di posisi akhir.
3. **Pengemasan Kunci AES (Bit-to-Byte Conversion):**
   Kelompokkan 128 bit keluaran ke dalam 16 byte (MSB-first):
   ```python
   key_bytes = bytearray()
   for i in range(0, 128, 8):
       chunk = bits[i:i+8]
       val = 0
       for b in chunk:
           val = (val << 1) | b
       key_bytes.append(val)
   ```
4. **Dekripsi AES ECB:**
   Inisialisasi cipher AES dalam mode ECB dengan kunci 16-byte hasil rekonstruksi, lalu dekripsi ciphertext heksadesimal 48 byte:
   ```python
   cipher = AES.new(bytes(key_bytes), AES.MODE_ECB)
   plaintext = cipher.decrypt(bytes.fromhex(ct_hex))
   ```
5. **Penanganan Padding PKCS#7:**
   Hasil dekripsi menghasilkan blok data berakhiran padding byte `\x0f` (15 byte padding). Melepaskan padding mengungkapkan flag:
   `academy{scr8mbledt_flvg_cc02eb30}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{scr8mbledt_flvg_cc02eb30}`
- **Metode Verifikasi:** `POST /api/submissions/` dengan payload `{"challenge": 703, "flag": "academy{scr8mbledt_flvg_cc02eb30}"}` pada REST API CyLab Security Academy. Respons server: `HTTP 201 Created` dengan `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pemisahan Manajemen Kunci (*Cryptographic Key Isolation*):** Parameter inisialisasi LFSR atau pseudorandom number generator (PRNG) tidak boleh diekspos ke lingkungan klien atau output artefak publik.
- **Kepatuhan KDF Standar:** Jangan menggunakan deretan bit mentah dari LFSR sebagai kunci kriptografi AES. Gunakan Key Derivation Function (KDF) yang aman seperti PBKDF2 (NIST SP 800-132) atau HKDF (RFC 5869).
- **Hindari Mode ECB:** Mode operasi ECB dilarang dalam standar keamanan komunikasi modern karena kebocoran pola dan ketiadaan proteksi integritas. Gunakan mode AEAD seperti AES-GCM (NIST SP 800-38D).
