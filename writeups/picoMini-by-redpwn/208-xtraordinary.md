# Writeup: XtraORdinary (Challenge ID: 208)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography
- **Difficulty:** Hard (3)
- **Author:** Boolean
- **Event:** picoMini by redpwn
- **Points:** 150
- **Flag:** `picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}`

---

## Deskripsi Tantangan
> Check out my new, never-before-seen method of encryption! I totally invented it myself. I added so many for loops that I don't even know what it does. It's extraordinarily secure!
> Download artifacts:
> - `encrypt.py`: Skrip enkripsi Python dengan deretan nested loops berulang.
> - `output.txt`: Berkas keluaran ciphertext dalam format hex string.
>
> Hint:
> 1. (None provided)

---

## Analisis Kerentanan & Konsep Teknis (Root Cause Theory)
1. **Sifat Aljabar Operasi Bitwise XOR ($\oplus$):**
   - Operasi bitwise eXclusive OR (XOR) memiliki sifat aljabar matematis fundamental:
     1. Komutatif: $A \oplus B = B \oplus A$
     2. Asosiatif: $(A \oplus B) \oplus C = A \oplus (B \oplus C)$
     3. Identitas: $A \oplus 0 = A$
     4. Involusi (*Self-Inverse*): $A \oplus A = 0 \implies A \oplus B \oplus B = A$
2. **Ilusi Kompleksitas Algoritmik (Security through Obscurity):**
   - Skrip `encrypt.py` mencoba menciptakan "keamanan buatan" dengan menyusun lima lapis nested loop yang mengulang eksekusi `ctxt = encrypt(ctxt, random_str)` ribuan kali berdasarkan angka acak `randint`.
   - Namun, karena sifat involusi XOR:
     - Melakukan operasi XOR dengan string $S$ sebanyak jumlah genap ($2k$) menghasilkan pembatalan total: $S \oplus S \dots \oplus S = 0$.
     - Melakukan operasi XOR dengan string $S$ sebanyak jumlah ganjil ($2k + 1$) tepat ekuivalen dengan melakukan operasi XOR satu kali ($S$).
3. **Penyusutan Ruang Keadaan (*State Space Reduction*):**
   - Dari daftar `random_strs` yang didefinisikan:
     1. `b'my encryption method'`
     2. `b'is absolutely impenetrable'`
     3. `b'and you will never'`
     4. `b'ever'` (diulang 6 kali dalam daftar)
     5. `b'break it'`
   - Hanya ada 5 string unik yang berbeda!
   - Karena setiap string unik hanya memiliki 2 kemungkinan kontribusi efektif ($\text{aktif} = 1$ atau $\text{batal} = 0$), maka total seluruh permutasi lapisan masking XOR yang mungkin terjadi di akhir eksekusi hanyalah:
     $$2^5 = 32 \text{ kemungkinan kombinasi mask}$$
4. **Known-Plaintext Attack (KPA) pada Repeating-Key XOR:**
   - Diketahui bahwa flag diawali dengan pola standar `picoCTF{` (panjang 8 karakter).
   - Relasi enkripsi awal adalah $\text{ctxt}_0 = \text{flag} \oplus \text{key}$.
   - Setelah menguji 32 kombinasi mask, nilai `cur = ctxt ^ mask` akan menghasilkan $\text{cur} = \text{flag} \oplus \text{key}$.
   - Dengan mengevaluasi $\text{key}[0:7] = \text{cur}[0:7] \oplus \texttt{b"picoCTF"}$, ditemukan bahwa pada kombinasi mask tertentu nilai kunci membentuk kata bermakna:
     $$\text{key} = \texttt{b"Africa!"}$$

---

## Rekonstruksi Pengujian Step-by-Step
1. **Analisis Statis Kode Sumber `encrypt.py`:**
   - Memeriksa alur enkripsi: `flag` di-XOR dengan `secret-key.txt` (menggunakan repeating key modulo panjang kunci).
   - Mengekstrak 5 string unik dari array `random_strs`.
2. **Implementasi Brute-Force 32 Kombinasi Subset:**
   - Membaca ciphertext 39-byte dari `output.txt`.
   - Mengiterasi seluruh kombinasi subset dari 5 string unik menggunakan `itertools.combinations`.
3. **Pemulihan Kunci Rahasia (*Key Recovery*):**
   - Pada subset mask `(b'my encryption method', b'is absolutely impenetrable', b'break it')`, karakter awal kunci didekripsi menjadi `b"Africa!"`.
   - Panjang kunci `Africa!` adalah 7 byte.
4. **Dekripsi Penuh & Validasi Teks Flag:**
   - Menggunakan kunci `Africa!`, seluruh ciphertext 39-byte berhasil didekripsi menjadi teks ASCII valid:
     `picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}`
5. **Verifikasi REST API CyLab:**
   - Mengirimkan token ke endpoint `POST /api/submissions/` dengan payload:
     `{"challenge": 208, "flag": "picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}"}`
   - Respons server mengonfirmasi validitas dengan status `HTTP 201 Created` (`correct: true`).

---

## Flag & Verifikasi
- **Token Resmi:** `picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}`
- **API Response:** `{"user": 1072359, "challenge": 208, "flag": "picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}", "correct": true, "historical": false}`
- **Solver Script:** `scripts/solve_208_xtraordinary.py`

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Prinsip Kerckhoffs & Kegagalan Obfuscation:**
  - Keamanan sistem kriptografi tidak boleh bertumpu pada kerumitan alur kode (*complexity/obscurity*), melainkan harus bertumpu sepenuhnya pada kerahasiaan kunci (*secrecy of the key*). Menambahkan loop bertingkat tanpa mengubah sifat dasar aljabar tidak menambah entropi sistem sama sekali.
- **Kelemahan Fatal Reused Key Stream / Repeating XOR:**
  - Operasi stream cipher atau XOR sederhana yang menggunakan kunci berulang (*multi-byte XOR*) rentan terhadap analisis frekuensi, serangan *crib dragging*, dan *known-plaintext attack*.
  - Enkripsi simetris modern wajib menggunakan cipher blok terstandarisasi dengan mode aman (AES-GCM / ChaCha20) dengan IV/nonce yang unik untuk setiap sesi enkripsi.
