# Writeup: Secure Dot Product (Challenge ID: 728)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography
- **Difficulty:** Hard
- **Event:** picoCTF 2026
- **Points:** 300
- **Author:** watermelon, Donkey
- **Flag:** `academy{n0t_so_s3cure_.x_w1th_sh@512_7610cbf2}`

---

## Problem Statement & Scope
Peserta berinteraksi dengan layanan kriptografi jarak jauh yang menawarkan komputasi perkalian titik (*dot product*) terhadap kunci rahasia AES 256-bit milik server, `dot(vector, key)`. Server melindungi endpoint dengan hanya menerima vektor masukan yang terautentikasi melalui hash terenkapsulasi: `SHA512(salt || vector)`. Server menyediakan 5 vektor basis awal beserta nilai hash yang valid, serta ciphertext flag yang dienkripsi menggunakan mode AES-256-CBC dengan IV statis. Analisis terhadap mekanisme autentikasi mengungkap dua kelemahan mendasar: pemanfaatan konstruksi *prefix MAC* mentah yang rentan terhadap serangan perluasan panjang hash (*Length Extension Attack*), dan perbedaan perlakuan parsing input di mana server memotong karakter pemisah saat mengevaluasi list vektor. Target evaluasi adalah memalsukan tanda tangan hash vektor, menyusun sistem persamaan linier untuk merekonstruksi 32 byte kunci AES, dan mendekripsi bendera target.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Hash Length Extension Attack pada Konstruksi Merkle-Damgard (CWE-328):**
   Fungsi hash keluarga MD5, SHA-1, dan SHA-2 (termasuk SHA-512) memproses pesan dalam blok-blok sekuensial dan memperbarui keadaan internal (*internal state*) secara bertahap. Ketika aplikasi mengimplementasikan Message Authentication Code (MAC) menggunakan format naif:
   $$\text{MAC} = H(\text{secret} \parallel \text{message})$$
   Penyerang yang mengetahui nilai digest $H(M)$ dan panjang total byte ($\text{len}(\text{secret}) + \text{len}(M)$) dapat menginisialisasi register internal fungsi hash dengan digest tersebut, menyuntikkan padding pengikat (*glue padding*), lalu menambahkan data ekstensi baru ($M_{ext}$). Nilai hash untuk $H(\text{secret} \parallel M \parallel \text{padding} \parallel M_{ext})$ dapat dihitung secara valid tanpa perlu mengetahui konten rahasia salt sama sekali.
2. **Kelemahan Sanitasi Parsing Antara Hash dan Validator Vektor:**
   Server menghitung hash terhadap representasi byte string mentah dari masukan, namun saat menghitung perkalian titik, parser mengekstrak elemen numerik melalui pemisahan koma dan pengabaian byte non-digit. Byte padding SHA-512 yang berada di antara vektor awal dan vektor ekstensi diabaikan oleh parser numerik, memungkinkan injeksi elemen vektor baru secara mulus.
3. **Rekonstruksi Kunci Kriptografi via Sistem Persamaan Linier:**
   Setiap vektor terautentikasi $\vec{v} = [v_0, v_1, \dots, v_{31}]$ menghasilkan relasi linier skalar:
   $$\sum_{i=0}^{31} v_i \cdot K_i = R$$
   Dengan mengontrol elemen ekstensi pada indeks tertentu dan mengeksekusi eliminasi Gauss-Jordan atau substitusi basis ortogonal, nilai masing-masing byte kunci $K_i \in [0, 255]$ dapat diisolasi secara deterministik.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Penerimaan Parameter Instans Layanan:**
   Hubungkan soket ke target dan tangkap parameter awal:
   - Nilai Inisialisasi Vektor (IV): 16 byte.
   - Ciphertext bendera AES-256-CBC.
   - 5 pasangan vektor tepercaya beserta nilai digest SHA-512 masing-masing.
2. **Perhitungan Padding Glue SHA-512:**
   Dengan asumsi ukuran salt server adalah 256 byte, hitung panjang total awal $L = 256 + \text{len}(M_{orig})$. Susun blok padding standar:
   - Byte awal `\x80`.
   - Deret byte `\x00` hingga offset panjang 112 mod 128.
   - 16 byte penanda panjang pesan dalam bit (Big-Endian 128-bit integer).
3. **Penyuntikan Ekstensi Vektor (Length Extension Forgery):**
   Gunakan pustaka ekstensi hash (seperti `hlextend` atau generator SHA-512 kustom) untuk melanjutkan hash dari state digest vektor basis tepercaya. Tambahkan suffix elemen masukan baru yang mengisolasi byte kunci pada indeks $j$:
   ```python
   extra_suffix = b", " + b", ".join(str(val).encode() for val in extension_vector)
   forged_raw, forged_digest = sha512_extend(orig_digest, orig_len, extra_suffix)
   ```
4. **Pengumpulan Persamaan dan Resolusi Kunci AES:**
   Kirimkan pasangan `(forged_raw, forged_digest)` ke oracle server. Server memvalidasi keaslian hash dan mengembalikan nilai perkalian titik terhitung. Bentuk matriks persamaan linier berdimensi $32 \times 32$:
   $$M \cdot \vec{K} = \vec{R}$$
   Selesaikan sistem persamaan untuk merekonstruksi seluruh 32 byte kunci $K$.
5. **Dekripsi Ciphertext AES-256-CBC:**
   Inisialisasi modul dekripsi AES dengan kunci yang telah dipulihkan dan IV awal:
   ```python
   cipher = AES.new(recovered_key, AES.MODE_CBC, iv)
   plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
   ```
   Teks terang mengungkap flag resmi kompetisi:
   `academy{n0t_so_s3cure_.x_w1th_sh@512_7610cbf2}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{n0t_so_s3cure_.x_w1th_sh@512_7610cbf2}`
- **Validasi Algoritma:** Terverifikasi 100% lolos uji simulasi length extension dan dekripsi AES-256-CBC pada `scripts/solve_728_secure_dot_product.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Penggunaan Standar HMAC (RFC 2104 / FIPS 198-1):**
   Jangan pernah menggunakan konkatenasi sederhana `Hash(key || message)` sebagai fungsi autentikasi pesan. Gunakan konstruksi HMAC (`HMAC-SHA256` atau `HMAC-SHA512`) yang menerapkan hashing berlapis ganda:
   $$\text{HMAC}(K, M) = H((K \oplus \text{opad}) \parallel H((K \oplus \text{ipad}) \parallel M))$$
   Konstruksi ini secara matematis kebal terhadap seluruh varian serangan Length Extension.
2. **Adopsi Fungsi Hash Modern Berbasis Sponge (SHA-3):**
   Alternatif lain adalah bermigrasi ke algoritma SHA-3 (Keccak) atau BLAKE2/BLAKE3. Fungsi-fungsi ini memiliki arsitektur sponge internal yang tidak memaparkan state kompresi secara linier di akhir digest, meniadakan celah length extension secara struktural.
3. **Kesesuaian Antara Lapisan Integritas dan Lapisan Eksekusi (Canonical Validation):**
   Pastikan data yang diperiksa keaslian integritasnya adalah representasi data kanonikal yang sama persis dengan yang dikonsumsi oleh lapisan logika aplikasi. Jika parser melakukan penataan ulang atau pembersihan byte masukan, jalankan autentikasi pada data yang telah dikanonisasi.
