# Writeup: bloat.py (Challenge ID: 256)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Python AST Obfuscation & Stream XOR Deobfuscation
- **Difficulty:** Medium (diff=2)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{d30bfu5c4710n_f7w_d77083fe}`

---

## Problem Statement & Scope

Diberikan sebuah skrip Python terobfuskasi `bloat.flag.py` dan berkas bendera terenkripsi `flag.txt.enc` yang dapat diunduh dari pustaka pustaka berkas CyLab:
- `bloat.flag.py`: `https://challenge-files.cylabacademy.net/library/29555ba70e983dd8216407779bca6085b7eeab85c0c2a3a16d6b1c757a9eaa9c/bloat.flag.py`
- `flag.txt.enc`: `https://challenge-files.cylabacademy.net/library/29555ba70e983dd8216407779bca6085b7eeab85c0c2a3a16d6b1c757a9eaa9c/flag.txt.enc`

Ketika dijalankan, skrip meminta masukan kata sandi dari pengguna:
`Please enter correct password for flag: `
Jika kata sandi salah, program menampilkan pesan kegagalan dan berhenti (`sys.exit(0)`).
Jika kata sandi benar, program melakukan dekripsi terhadap berkas `flag.txt.enc` dan mencetak bendera ke konsol.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Obfuskasi Literal String Melalui Pengindeksan Larik Karakter (CWE-200 / CWE-798 / NIST SP 800-115 § 4.2):**
   - Skrip `bloat.flag.py` tidak menyimpan string teks secara terbuka, melainkan mendefinisikan sebuah larik alfabet statis:
     ```python
     a = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ "
     ```
   - Seluruh konstanta teks kritis, termasuk kata sandi dan kunci kriptografi, dibangun secara dinamis melalui operasi konkatenasi indeks:
     - Logika Verifikasi Kata Sandi (`arg133`):
       `a[71]+a[64]+a[79]+a[79]+a[88]+a[66]+a[71]+a[64]+a[77]+a[66]+a[68]`
       Memetakan indeks `[71, 64, 79, 79, 88, 66, 71, 64, 77, 66, 68]` ke string:
       `"happychance"`
     - Logika Kunci Enkripsi / Dekripsi (`arg111`):
       `a[81]+a[64]+a[79]+a[82]+a[66]+a[64]+a[75]+a[75]+a[72]+a[78]+a[77]`
       Memetakan indeks `[81, 64, 79, 82, 66, 64, 75, 75, 72, 78, 77]` ke string:
       `"rapscallion"`

2. **Kelemahan Skema Enkripsi Simetris Repeating-Key XOR (CWE-327):**
   - Fungsi `arg122` mengimplementasikan cipher aliran XOR sederhana dengan kunci berulang:
     ```python
     def arg122(arg432, arg423):
         arg433 = arg423
         i = 0
         while len(arg433) < len(arg432):
             arg433 = arg433 + arg423[i]
             i = (i + 1) % len(arg423)        
         return "".join([chr(ord(arg422) ^ ord(arg442)) for (arg422,arg442) in zip(arg432,arg433)])
     ```
   - Operasi XOR bersifat involutif (`P = C ^ K`). Kunci `"rapscallion"` (11 bita) diulang hingga menyamai panjang berkas terenkripsi `flag.txt.enc` (35 bita).

3. **Pemisahan Logika Pemeriksaan Kredensial dan Alur Kunci (CWE-670 / CWE-259):**
   - Fungsi `arg133` memeriksa kecocokan kata sandi yang dimasukkan pengguna, namun fungsi pembuka bendera `arg111` sama sekali tidak memanfaatkan kata sandi tersebut sebagai input penurunan kunci (*key derivation*).
   - Kunci dekripsi `"rapscallion"` di-hardcode secara independen di dalam fungsi `arg111`. Dengan demikian, analisis kode statis memungkinkan penyerang melewati seluruh prompt masukan pengguna dan mendekripsi berkas secara deterministik langsung dari ciphertext.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh kedua berkas target:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/29555ba70e983dd8216407779bca6085b7eeab85c0c2a3a16d6b1c757a9eaa9c/bloat.flag.py
   wget https://challenge-files.cylabacademy.net/library/29555ba70e983dd8216407779bca6085b7eeab85c0c2a3a16d6b1c757a9eaa9c/flag.txt.enc
   ```
2. Analisis kode sumber statis pada `bloat.flag.py`:
   - Buka interpreter Python dan evaluasi string alfabet `a`.
   - Hitung nilai password:
     ```python
     pwd = "".join(a[i] for i in [71, 64, 79, 79, 88, 66, 71, 64, 77, 66, 68])
     # Hasil: 'happychance'
     ```
   - Hitung nilai kunci XOR:
     ```python
     key = "".join(a[i] for i in [81, 64, 79, 82, 66, 64, 75, 75, 72, 78, 77])
     # Hasil: 'rapscallion'
     ```
3. Lakukan dekripsi stream XOR terhadap byte berkas `flag.txt.enc`:
   - Panjang berkas: 35 bita.
   - Heksadesimal: `13021117060c15170d5c5e1007054600555b5d5901311456072c07565b5c515c08171c`
   - Kunci yang diperluas: `rapscallionrapscallionrapscallionra`
   - Hasil dekripsi byte-per-byte: `academy{d30bfu5c4710n_f7w_d77083fe}`.
4. Jalankan skrip solver mandiri `scripts/solve_256_bloat.py`:
   ```bash
   python3 scripts/solve_256_bloat.py
   ```
   Output:
   ```text
   [*] Auditing Module 256: bloat.py
   [*] Stage 1: Deobfuscating Static Constants -> Password: 'happychance', Key: 'rapscallion'
   [*] Stage 2: Decrypting 35-byte embedded ciphertext stream...
       [+] Decoded Stream: academy{d30bfu5c4710n_f7w_d77083fe}
   [+] Output Flag: academy{d30bfu5c4710n_f7w_d77083fe}
   ```
5. Verifikasi penyerahan bendera ke REST API CyLab (`POST /api/submissions/`). Respons: `HTTP 201 Created` dengan status `correct: true`.

---

## Flag & Verifikasi

- **Platform Verified Flag:** `academy{d30bfu5c4710n_f7w_d77083fe}`
- **Matriks Wrapper Acceptance:**
  - `academy{d30bfu5c4710n_f7w_d77083fe}`: **ACCEPTED (HTTP 201 Created, correct: true)**
  - `picoCTF{d30bfu5c4710n_f7w_d77083fe}`: **REJECTED (HTTP 201 Created, correct: false)**
- **Audit Bukti HTTP Live:**
  ```json
  {
    "user": 1072359,
    "challenge": 256,
    "flag": "academy{d30bfu5c4710n_f7w_d77083fe}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi Rekayasa Balik & SAST LKS Cyber Security:**
   - Kemampuan melakukan *Static Application Security Testing* (SAST) pada skrip bahasa tingkat tinggi (Python).
   - Mengatasi teknik obfuskasi variabel dan fungsi dengan memetakan aliran data langsung ke ekspresi logika penentu.
   - Menguasai sifat-sifat matematika operasi XOR biner dalam pemecahan cipher stream.
2. **Mitigasi Defensif & Hardening (NIST SP 800-115 § 4.2 / § 5):**
   - Hindari menyimpan kredensial atau kunci kriptografi di dalam source code aplikasi yang didistribusikan ke publik (CWE-798).
   - Jika data harus dilindungi dengan kata sandi pengguna, gunakan fungsi penurunan kunci yang tahan serangan brute-force (*memory-hard Key Derivation Function*) seperti Argon2id atau PBKDF2 dengan *salt* unik dan *work factor* memadai.
   - Gantikan skema XOR sederhana dengan cipher terotentikasi berstandar industri (AES-GCM / ChaCha20-Poly1305) untuk menjamin integritas dan kerahasiaan data sekaligus.
