# Writeup: XtraORdinary (Challenge ID: 208)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Multilayer Repeating-Key XOR & Involution Reduction (CWE-327)
- **Difficulty:** Medium (diff=2)
- **Event:** picoMini by redpwn
- **Points:** 150
- **Author:** Boolean
- **Flag Resmi:** `picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}`
- **Audit Batch:** Batch 188 (10 November 2026) - Live Verified HTTP 201 (`correct: true`)

---

## Problem Statement & Scope
Tantangan `XtraORdinary` menyajikan skenario kriptografi kustom bertingkat:
*"Check out my new, never-before-seen method of encryption! I totally invented it myself. I added so many for loops that I don't even know what it does. It's extraordinarily secure!"*. Peserta diberikan dua artefak:
1. `encrypt.py`: Skrip sumber enkripsi Python yang mengaplikasikan kunci berulang diikuti oleh serangkaian perulangan bersarang acak.
2. `output.txt`: Berkas ciphertext dalam format heksadesimal sepanjang 39 byte.

Peserta ditugaskan untuk menganalisis sifat aljabar operasi bitwise XOR, membuktikan penyusutan ruang keadaan eksponensial menjadi himpunan bagian berhingga, memulihkan kunci privat berulang via serangan teks terang diketahui (*Known-Plaintext Attack*, KPA), dan mendekripsi token bendera rahasia.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Sifat Aljabar Operasi Bitwise XOR ($\oplus$):**
   Operasi bitwise XOR bersifat komutatif, asosiatif, memiliki elemen identitas ($A \oplus 0 = A$), dan merupakan sebuah involusi (*self-inverse*):
   $$A \oplus B \oplus B = A \oplus 0 = A$$
2. **Kegagalan Paradigma Keamanan Berbasis Kerumitan (CWE-327 / Obscurity):**
   Pada skrip `encrypt.py`, setelah teks bendera di-XOR dengan `key` berulang, ciphertext dialirkan melalui struktur loop bertingkat yang memilih string dari array `random_strs`:
   ```python
   random_strs = [
       b'my encryption method',
       b'is absolutely impenetrable',
       b'and you will never',
       b'ever', b'ever', b'ever', b'ever', b'ever', b'ever',
       b'break it'
   ]
   ```
   Meskipun kode terlihat rumit dengan ribuan iterasi, pengulangan operasi XOR dengan sebuah string $S$ sebanyak jumlah genap ($2k$) menghasilkan nilai pembatalan sempurna ($S \oplus S = 0$). Sementara itu, pengulangan sebanyak jumlah ganjil ($2k+1$) setara murni dengan satu kali operasi XOR ($S$).
3. **Penyusutan Ruang Keadaan (*State Space Reduction*):**
   Dari seluruh elemen `random_strs`, hanya ada 5 string unik yang berbeda:
   1. $s_1$: `b'my encryption method'`
   2. $s_2$: `b'is absolutely impenetrable'`
   3. $s_3$: `b'and you will never'`
   4. $s_4$: `b'ever'`
   5. $s_5$: `b'break it'`
   Setiap string unik hanya memiliki dua nilai status efektif: di-XOR sebanyak 0 kali atau 1 kali. Akibatnya, seluruh lapisan pengaburan loop eksternal menyusut secara matematis menjadi hanya:
   $$2^5 = 32 \text{ kemungkinan kombinasi mask}$$
4. **Known-Plaintext Attack (KPA) pada Repeating-Key XOR:**
   Format bendera acara dipastikan diawali dengan prefiks 8-byte `picoCTF{`. Untuk setiap kemungkinan dari 32 mask, peserta menghitung:
   $$K[0..6] = C'[0..6] \oplus \text{b'picoCTF'}[0..6]$$
   Di antara 32 kandidat, kombinasi mask $\{s_2, s_3, s_4\}$ secara unik mengungkap kunci berulang berbahasa Inggris yang valid: `Africa!`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Ciphertext:**
   Ciphertext heksadesimal dibaca dari `output.txt`:
   ```text
   57657535570c1e1c612b3468106a18492140662d2f5967442a2960684d28017931617b1f3637
   ```
   (Panjang 39 byte).
2. **Evaluasi 32 Kombinasi Mask via `itertools.combinations`:**
   Iterasi seluruh subset dari 5 string acak unik dan terapkan operasi XOR terhadap ciphertext.
3. **Pencocokan Prefiks Kunci:**
   Uji nilai `K[0..6]` terhadap representasi ASCII printable:
   Kunci kandidat ditemukan bernilai `b'Africa!'` (panjang 7 byte).
4. **Dekripsi Penuh:**
   Terapkan kunci `Africa!` secara berulang ke seluruh 39 byte ciphertext bertransformasi:
   ```text
   picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}
   ```
5. **Otomasi Skrip Solver:**
   Alur dekripsi otomatis dipetakan secara deterministik pada `scripts/solve_208_xtraordinary.py`.

---

## Flag & Verifikasi
- **Flag Resmi:** `picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}`
- **Wrapper Validator:** Native event wrapper (`picoCTF{...}`)
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_208_xtraordinary.py`.

### Re-verifikasi Audit Batch 188 (2026-11-10 UTC, sesi REST siswa `Arielwin` / user id 1072359)

| Token diuji | Wrapper | HTTP | Respons API |
| :--- | :--- | :--- | :--- |
| `picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}` | native event | 201 | `{"user":1072359,"challenge":208,"flag":"picoCTF{w41t_s0_1_d1dnt_1nv3nt_x0r???}","correct":true,"historical":false}` |
| `academy{w41t_s0_1_d1dnt_1nv3nt_x0r???}` | CyLab rekey | 201 | `{"user":1072359,"challenge":208,"flag":"academy{w41t_s0_1_d1dnt_1nv3nt_x0r???}","correct":false,"historical":false}` |

- **Temuan format validator:** Modul backport event `picoMini by redpwn` tidak direkey ke prefix `academy{...}`. Submisi wajib menggunakan native wrapper `picoCTF{...}`.
- **Reproduktifitas offline:** Solver `scripts/solve_208_xtraordinary.py` memecahkan kunci 32 state dalam hitungan milidetik secara offline.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Prinsip Kerckhoffs & Kegagalan Obfuscation (NIST SP 800-115 §5.3):**
   Keamanan sistem kriptografi tidak boleh disandarkan pada kerumitan alur kode (*security through obscurity*). Menambah loop bertingkat tanpa mengubah sifat dasar aljabar operator tidak menambah entropi sistem sama sekali.
2. **Kelemahan Fatal Reused Key Stream / Repeating XOR (CWE-327):**
   Operasi stream cipher atau multi-byte XOR yang menggunakan kunci berulang rentan terhadap analisis frekuensi, serangan *crib dragging*, dan *known-plaintext attack*.
3. **Penggunaan Algoritma Standar Modern (Remediation & Hardening):**
   Gunakan cipher blok terstandarisasi industri dengan mode authenticated encryption (AES-GCM / ChaCha20-Poly1305) dan nonce/IV unik per pesan:
   ```python
   from cryptography.hazmat.primitives.ciphers.aead import AESGCM
   key = AESGCM.generate_key(bit_length=256)
   aesgcm = AESGCM(key)
   nonce = os.urandom(12)
   ciphertext = aesgcm.encrypt(nonce, plaintext, None)
   ```
