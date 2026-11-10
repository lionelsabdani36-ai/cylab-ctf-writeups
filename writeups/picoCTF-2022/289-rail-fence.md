# Writeup: rail-fence (Challenge ID: 289)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography
- **Difficulty:** Medium (Tier 2)
- **Event:** picoCTF 2022
- **Author:** Will Hong
- **Points:** 200
- **Flag:** `academy{WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_D3AB175F}`

---

## Problem Statement & Scope

Tantangan ini menyajikan sebuah ciphertext yang dienkripsi menggunakan sandi transposisi klasik jenis *Rail Fence Cipher* dengan kedalaman 4 rel (4 rails). Peserta diberikan berkas teks `message.txt` dengan isi:

```text
Ta _7N6DD5hlg:W3D_H3C31N__37Fef sHR053F38N43DA1 i33___NB
```

Peserta diinstruksikan untuk mendekripsi pesan tersebut. Pesan hasil dekripsi memuat sebuah frasa yang harus diserahkan dalam format bendera resmi CyLab: `academy{phrase}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Prinsip Transposisi Tanpa Konfusi (Permutation-Only Cipher):**
   Rail Fence Cipher adalah algoritma transposisi monoalfabetik geometris. Sandi ini hanya mengubah urutan posisi karakter (permutasi) tanpa mengubah identitas karakter (zero substitution / zero confusion). Distribusi frekuensi karakter pada ciphertext identik 100% dengan teks asli (plaintext).
2. **Deterministik Lintasan Zig-Zag Gelombang Segitiga (NIST SP 800-115 § 4.2):**
   Karakter teks asli dituliskan secara diagonal ke bawah dan ke atas melintasi $R$ rel secara periodik dengan periode osilasi:
   $$P = 2 \times (R - 1)$$
   Untuk $R = 4$, periode gelombang adalah $P = 2 \times (4 - 1) = 6$.
   Pola indeks rel baris ke-$i$ untuk setiap karakter ke-$t$ ($t \in [0, N-1]$) mengikuti fungsi modulo segitiga:
   $$r(t) = |(t \bmod P) - (R - 1)|$$
3. **Ketiadaan Kunci Rahasia Entropi Tinggi (CWE-327):**
   Ruang kunci (key space) Rail Fence sangat kecil, dibatasi oleh jumlah rel $R \in [2, N-1]$. Dengan $R = 4$ yang telah diketahui, rekonstruksi posisi baris dan kolom dapat diselesaikan secara deterministik dalam kompleksitas $O(N)$ tanpa memerlukan brute-force.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Parameter Sandi dan Panjang Pesan:**
   Panjang ciphertext adalah $N = 56$ karakter dengan $R = 4$ rel.
2. **Pemodelan Trajektori Osilasi:**
   Membangun array pola indeks rel sepanjang 56 karakter dengan arah pergerakan memantul di rel 0 dan rel 3:
   `[0, 1, 2, 3, 2, 1, 0, 1, 2, 3, 2, 1, ...]`
3. **Perhitungan Alokasi Karakter per Rel:**
   Menghitung frekuensi kemunculan masing-masing indeks rel pada pesan 56 karakter:
   - Rel 0: 10 karakter
   - Rel 1: 19 karakter
   - Rel 2: 18 karakter
   - Rel 3: 9 karakter
   Total: $10 + 19 + 18 + 9 = 56$ karakter.
4. **Segmentasi dan Pemetaan Ulang Matriks:**
   Memotong string ciphertext menjadi 4 irisan string sesuai panjang rel:
   - Baris 0: `Ta _7N6DD5` (10 karakter)
   - Baris 1: `hlg:W3D_H3C31N__37F` (19 karakter)
   - Baris 2: `ef sHR053F38N43DA1 ` (18 karakter)
   - Baris 3: `i33___NB` (9 karakter)
5. **Rekonstruksi Teks Terbuka:**
   Membaca karakter satu per satu mengikuti urutan rel trajektori gelombang:
   ```text
   The flag is: WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_D3AB175F
   ```
6. **Normalisasi Token Format CyLab:**
   Mengekstrak frasa setelah awalan `The flag is:` dan membungkusnya ke dalam format resmi:
   `academy{WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_D3AB175F}`.

---

## Flag & Verifikasi

- **Plaintext Extracted Phrase:** `WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_D3AB175F`
- **CyLab Accepted Flag:** `academy{WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_D3AB175F}`
- **Status Submisi REST API:** HTTP 201 Created (`correct: true`, user `1072359`, challenge 289).

Bukti respons live CyLab API:
```json
{
  "user": 1072359,
  "challenge": 289,
  "flag": "academy{WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_D3AB175F}",
  "correct": true,
  "historical": false
}
```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kelemahan Sandi Transposisi Klasik:**
   Sandi permutasi murni tanpa substitusi non-linear (S-Box) rentan terhadap analisis anagram dan pemodelan matematis lintasan geometris. Transposisi sederhana tidak memberikan sifat konfusi sebagaimana disyaratkan oleh prinsip Shannon.
2. **Standar Kriptografi Modern:**
   Gunakan algoritma enkripsi simetris modern yang memenuhi standar NIST SP 800-38D (seperti AES-256-GCM atau ChaCha20-Poly1305) yang mengombinasikan substitusi, permutasi berlapis (SPN), dan otentikasi pesan (AEAD).
3. **Penerapan pada Modul CTF / LKS:**
   Ketika menghadapi tantangan transposisi geometris dengan parameter rel kecil, buat simulasi pelacakan indeks berbasis generator periodik di Python untuk memulihkan pesan secara otomatis tanpa perlu rekonstruksi manual di atas kertas.
