# Writeup: Compress and Attack (Challenge ID: 127)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Side-Channel & Compression Oracles (CRIME / BREACH Attack)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 130
- **Author:** Jake Beley
- **Flag:** `academy{sheriff_you_solved_the_crime}`

---

## Problem Statement & Scope
Tantangan `Compress and Attack` mengevaluasi keamanan arsitektur sistem kriptografi gabungan (*hybrid pipeline*) yang melakukan kompresi data sebelum enkripsi. Layanan interaktif diakses melalui soket TCP yang mengeksekusi skrip Python `compress_and_attack.py`.

Skenario layanan:
1. Server membaca string rahasia `flag` dari sistem file lokal.
2. Server meminta masukan teks dari pengguna (`usr_input`).
3. Server menggabungkan rahasia dan masukan: `flag + usr_input`, lalu mengompresinya menggunakan pustaka `zlib`.
4. Hasil kompresi dienkripsi menggunakan penyandi aliran (*stream cipher*) Salsa20 dengan kunci rahasia acak 256-bit baru pada setiap iterasi.
5. Server mengirimkan kembali nilai `nonce`, ciphertext mentah, serta **panjang ciphertext** (`len(encrypted_text)`).

Tujuan audit teknis ini adalah membuktikan bagaimana informasi panjang ciphertext yang bocor (*length side-channel*) dapat dieksploitasi untuk merekonstruksi seluruh isi teks rahasia karakter demi karakter tanpa memecahkan algoritma enkripsi Salsa20.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Mekanisme Algoritma Kompresi DEFLATE / LZ77 (RFC 1951):**
   Pustaka `zlib` mengimplementasikan format kompresi DEFLATE. Inti dari algoritma ini adalah pencarian substring berulang menggunakan jendela geser (*sliding window LZ77*). Apabila sebuah sekuens byte muncul lebih dari satu kali dalam payload yang dikompresi, kemunculan berikutnya digantikan oleh pasangan pointer referensi:
   $$(\text{distance}, \text{length})$$
   Penggantian ini secara drastis mengurangi ukuran byte payload dibandingkan menyimpan sekuens mentah berulang.

2. **Karakteristik Penyandi Aliran Salsa20 (RFC 7539):**
   Salsa20 adalah stream cipher yang menghasilkan aliran kunci semu (*keystream*) $K$. Ciphertext $C$ dibentuk melalui operasi bitwise XOR sederhana antara plaintext $P$ dan keystream:
   $$C = P \oplus K$$
   Konsekuensi mutlak dari operasi ini adalah preservasi panjang data secara identik:
   $$\text{len}(C) \equiv \text{len}(P)$$
   Tidak ada penambahan padding blok seperti halnya pada block cipher (misal AES-CBC).

3. **Kerentanan Oracle Kompresi (CWE-385: Covert Timing / Side-Channel, CVE-2012-4929 / CRIME, CVE-2013-3587 / BREACH):**
   Ketika masukan yang dikontrol oleh penyerang digabungkan bersama data rahasia ke dalam satu buffer kompresi sebelum dienkripsi:
   - Jika tebakan penyerang **cocok** dengan kelanjutan karakter rahasia, redundansi bertambah dan DEFLATE menghasilkan panjang payload yang lebih pendek.
   - Jika tebakan penyerang **salah**, entropi data meningkat dan panjang payload bertambah (+1 byte atau memicu batas representasi token baru).
   Panjang ciphertext yang dipancarkan secara transparan oleh server menjadi saluran sampingan (*oracle side-channel*) yang mendegradasi ruang pencarian dari eksponensial $O(|\Sigma|^N)$ menjadi linier $O(|\Sigma| \times N)$.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Struktur Layanan:**
   Potongan kode server `compress_and_attack.py`:
   ```python
   def compress(text):
       return zlib.compress(bytes(text.encode("utf-8")))

   def encrypt(plaintext):
       secret = os.urandom(32)
       cipher = Salsa20.new(key=secret)
       return cipher.nonce + cipher.encrypt(plaintext)

   def main():
       while True:
           usr_input = input("Enter your text to be encrypted: ")
           compressed_text = compress(flag + usr_input)
           encrypted = encrypt(compressed_text)
           print(len(encrypted[8:]))
   ```

2. **Penentuan Prefix Awal (Anchor):**
   Format flag standar picoCTF selalu diawali dengan string konstan:
   $$\text{current} = \text{"picoCTF\{"}$$

3. **Penyusunan Oracle Probing Loop Karakter demi Karakter:**
   Untuk menentukan karakter berikutnya pada indeks $i$:
   - Bentuk himpunan karakter kandidat $\Sigma = \text{a-z, A-Z, 0-9, \_}\}$.
   - Untuk setiap $c \in \Sigma$, kirimkan query dengan teks: `current + c`.
   - Catat panjang ciphertext `L(c) = len(encrypt(compress(flag + current + c)))`.
   - Karakter $c^*$ yang menghasilkan nilai $L(c^*)$ paling minimal dipilih sebagai karakter valid berikutnya:
     $$c^* = \arg\min_{c \in \Sigma} L(c)$$
   - Tambahkan $c^*$ ke `current`: $\text{current} \leftarrow \text{current} + c^*$.

4. **Eksekusi Pemulihan Otomatis:**
   Melalui eksekusi berulang terhadap oracle, karakter flag diekstraksi secara sekuensial:
   ```text
   picoCTF{ -> picoCTF{s -> picoCTF{sh -> picoCTF{she -> ... -> picoCTF{sheriff_you_solved_the_crime}
   ```
   Server mengonfirmasi pemulihan penuh saat karakter penutup `}` tercapai.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{sheriff_you_solved_the_crime}`
- **Native Platform Flag:** `picoCTF{sheriff_you_solved_the_crime}`
- **Status Solver:** Teruji dan terverifikasi penuh melalui model simulasi dan eksploitasi oracle deterministik `scripts/solve_127_compress_and_attack.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Pemisahan Konteks Kompresi Data Sensitif:**
   Standar keamanan TLS (RFC 7525) dan NIST SP 800-52 merekomendasikan penonaktifan fitur kompresi TLS (*TLS-level compression*) secara permanen untuk memitigasi serangan CRIME. Data yang memuat token rahasia (seperti sesi HTTP cookie, header Authorization, atau flag) tidak boleh dikompresi bersama data masukan pengguna dalam satu konteks kompresi.

2. **Penerapan Padding Acak (Masking & Length Blinding):**
   Apabila kompresi mutlak diperlukan pada lapisan aplikasi (seperti pada HTTP body gzip/brotli untuk memitigasi serangan BREACH):
   - Pisahkan rahasia dari konten reflektif pengguna.
   - Tambahkan padding data acak dengan panjang variabel (*random length padding*) pada output kompresi sebelum proses enkripsi untuk menyamarkan korelasi panjang byte (*decorrelation of length metadata*).
   - Gunakan token CSRF dinamis per-request berorientasi masking (XOR masking pada setiap respons HTTP).
