# Writeup: spelling-quiz (Challenge ID: 210)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Classical Substitution Cipher & Word-Pattern Frequency Analysis (CWE-326 / CWE-327)
- **Difficulty:** Medium (diff=2)
- **Event:** picoMini by redpwn
- **Points:** 100
- **Author:** flogarth
- **Flag Resmi:** `picoCTF{perhaps_the_dog_jumped_over_was_just_tired}`
- **Audit Batch:** Batch 189 (10 November 2026) - Live Verified HTTP 201 (`correct: true`)

---

## Problem Statement & Scope
Tantangan `spelling-quiz` menyajikan sebuah arsip `public.zip` yang berisikan skrip enkripsi Python `encrypt.py`, berkas teks terenkripsi `flag.txt`, dan korpus kata kamus ejaan yang sangat besar `study-guide.txt` (terdiri atas 272.543 baris kata bahasa Inggris unik). Skrip enkripsi mengimplementasikan substitusi monoalfabet acak dengan mengacak urutan alfabet 26 huruf Latin huruf kecil `[a-z]` menggunakan `random.shuffle()`, lalu memetakan setiap karakter secara satu-ke-satu (*bijection mapping*). Berkas `study-guide.txt` dan `flag.txt` dienkripsi secara berurutan menggunakan kamus permutasi yang persis sama. Peserta dituntut untuk merekonstruksi pemetaan substitusi alfabet dari ciphertext korpus kamus dan mendekripsi token bendera rahasia yang terenkripsi.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kelemahan Inheren Substitusi Monoalfabet (CWE-326 - Inadequate Cryptographic Strength):**
   Substitusi monoalfabet sederhana tidak memberikan difusi (*diffusion*) maupun konfusi (*confusion*) yang memadai (prinsip Shannon). Pemetaan satu-ke-satu mempertahankan invarian struktural bahasa:
   - **Invarian Panjang Kata (*Word Length Invariance*):** Panjang kata sebelum dan sesudah enkripsi identik.
   - **Invarian Pola Isomorf (*Word-Pattern / Shape Invariance*):** Posisi karakter berulang dalam satu kata tidak berubah (contoh: kata `perhaps` memiliki pola indeks `(0, 1, 2, 3, 4, 0, 5)` karena huruf `p` muncul pada indeks 0 dan 5). Pada ciphertext, kata ini menjadi `brcfxba` dengan pola indeks yang identik `(0, 1, 2, 3, 4, 0, 5)` pada huruf `b`.
   - **Invarian Frekuensi N-gram:** Distribusi frekuensi huruf tunggal, digram, dan trigram mencerminkan karakteristik statistik bahasa alami (bahasa Inggris).
2. **Penggunaan Kunci Berulang pada Korpus Massal (CWE-327 - Broken/Risky Cryptographic Algorithm):**
   Mengenkripsi kamus ejaan 272k kata dengan kunci yang sama menciptakan situasi *Known-Plaintext Attack* (KPA) dan *Crib Analysis* berskala masif. Ruang kunci $26! \approx 4 \times 10^{26}$ tampak besar di atas kertas, namun tereduksi secara instan menjadi komputasi deterministik $O(N)$ melalui propagasi kendala (*constraint satisfaction problem* / CSP).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Skrip Enkripsi `encrypt.py`:**
   ```python
   alphabet = list('abcdefghijklmnopqrstuvwxyz')
   random.shuffle(alphabet)
   dictionary = dict(zip(alphabet, list('abcdefghijklmnopqrstuvwxyz')))
   ```
   Kunci substitusi `dictionary` di-generate sekali saat inisialisasi dan digunakan untuk mengenkripsi `study-guide.txt` serta `flag.txt`.
2. **Inspeksi Ciphertext Flag:**
   Berkas `flag.txt` berisi string terenkripsi:
   ```text
   brcfxba_vfr_mid_hosbrm_iprc_exa_hoav_vwcrm
   ```
   Karakter underscore `_` tidak dienkripsi dan memisahkan ciphertext menjadi 8 token kata:
   - `brcfxba` (panjang 7, pola `0, 1, 2, 3, 4, 0, 5`)
   - `vfr` (panjang 3, pola `0, 1, 2`)
   - `mid` (panjang 3, pola `0, 1, 2`)
   - `hosbrm` (panjang 6, pola `0, 1, 2, 3, 4, 5`)
   - `iprc` (panjang 4, pola `0, 1, 2, 3`)
   - `exa` (panjang 3, pola `0, 1, 2`)
   - `hoav` (panjang 4, pola `0, 1, 2, 3`)
   - `vwcrm` (panjang 5, pola `0, 1, 2, 3, 4`)
3. **Propagasi Kendala & Deduksi Kata (Word-Pattern Attack):**
   - Kata pertama `brcfxba` memiliki pola `(0, 1, 2, 3, 4, 0, 5)`. Pencocokan terhadap korpus kata bahasa Inggris membatasi kandidat secara drastis, mengarah secara definitif ke kata `perhaps`.
   - Dari pemetaan parsial ini diperoleh:
     - `b -> p`
     - `r -> e`
     - `c -> r`
     - `f -> h`
     - `x -> a`
     - `a -> s`
   - Kata kedua `vfr`: karena `f -> h` dan `r -> e`, token `vfr` memiliki akhiran `-he`. Kata 3-huruf yang berakhiran `-he` dalam bahasa Inggris adalah `the`, sehingga `v -> t`.
   - Kata keenam `exa`: karena `x -> a` dan `a -> s`, token `exa` memiliki bentuk `_as`. Kata yang valid adalah `was`, sehingga `e -> w`.
   - Kata ketujuh `hoav`: berakhiran `-st` (`a -> s`, `v -> t`). Bersama dengan `mid` (`dog`) dan `hosbrm` (`jumped`), pola kalimat idiomatis bahasa Inggris *"perhaps the dog jumped over was just tired"* terkonfirmasi 100% konsisten tanpa kontradiksi pemetaan karakter.
4. **Ekstraksi Plaintext dan Pembentukan Token:**
   Menerapkan seluruh pemetaan substitusi terhadap token menghasilkan teks terang:
   `perhaps_the_dog_jumped_over_was_just_tired`.

---

## Flag & Verifikasi
- **Flag Resmi:** `picoCTF{perhaps_the_dog_jumped_over_was_just_tired}`
- **Wrapper Validator:** Native event wrapper (`picoCTF{...}`)
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_210_spelling_quiz.py`.

### Re-verifikasi Audit Batch 189 (2026-11-10 UTC, sesi REST siswa `Arielwin` / user id 1072359)

| Token diuji | Wrapper | HTTP | Respons API |
| :--- | :--- | :--- | :--- |
| `picoCTF{perhaps_the_dog_jumped_over_was_just_tired}` | native event | 201 | `{"user":1072359,"challenge":210,"flag":"picoCTF{perhaps_the_dog_jumped_over_was_just_tired}","correct":true,"historical":false}` |
| `academy{perhaps_the_dog_jumped_over_was_just_tired}` | CyLab rekey | 201 | `{"user":1072359,"challenge":210,"flag":"academy{perhaps_the_dog_jumped_over_was_just_tired}","correct":false,"historical":false}` |

- **Temuan format validator:** Validator CyLab secara konsisten menerima wrapper asli event `picoCTF{...}` dan menolak wrapper rekey `academy{...}` dengan status `correct: false`.
- **Reproduktifitas offline:** Solver `scripts/solve_210_spelling_quiz.py` mengeksekusi deduksi kriptanalisis pola isomorf dan validasi token secara mandiri tanpa dependensi eksternal.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Prinsip Keamanan Semantik (IND-CPA & Shannon Secrecy):**
   Cipher klasik (Caesar, Vigenère, Monoalphabetic Substitution) sama sekali tidak memenuhi kriteria *Indistinguishability under Chosen-Plaintext Attack* (IND-CPA). Dalam modul pertahanan LKS Cyber Security, seluruh data sensitif (at rest maupun in transit) wajib dienkripsi menggunakan skema kriptografi modern terotentikasi (*Authenticated Encryption with Associated Data* / AEAD) seperti AES-256-GCM atau ChaCha20-Poly1305.
2. **Larangan Penggunaan Kunci Bersama untuk Data Heterogen (*Key Separation*):**
   Jangan pernah menggunakan kunci atau keystream yang sama untuk mengenkripsi korpus publik (atau semi-publik) bersamaan dengan data rahasia. Pada skenario ini, `study-guide.txt` berperan sebagai *known-plaintext oracle* yang menghancurkan kerahasiaan `flag.txt`.
3. **Penerapan CSPRNG untuk Inisialisasi Kriptografis:**
   Modul `random` bawaan Python menggunakan Mersenne Twister (MT19937) yang bersifat deterministik dan tidak aman secara kriptografi (*Cryptographically Insecure PRNG*). Jika permutasi atau pembuatan nonce dibutuhkan, sistem wajib menggunakan `secrets` atau `os.urandom()` yang terikat pada generator entropi kernel Linux (`/dev/urandom`).
