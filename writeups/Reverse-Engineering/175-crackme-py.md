# Writeup: crackme-py (Challenge ID: 175)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Encoding Statis
- **Difficulty:** Easy
- **Author:** picoCTF
- **Event:** picoCTF 2021
- **Points:** 100
- **Flag:** `academy{1m_4_p34nut_a20db6f76f27d8}`

---

## Problem Statement & Scope
Diberikan berkas Python tunggal `crackme_gen.py` yang berisi string rahasia terenkripsi (`bezos_cc_secret`) beserta fungsi dekripsi `decode_secret` yang **tidak pernah dipanggil**. Program yang dijalankan hanya meminta dua angka dan mencetak yang terbesar. Tugas: pulihkan rahasia tanpa menjalankan logika interaktif.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Sand ROT47:** Varian ROT13 yang diperluas ke seluruh rentang ASCII tercetak (94 karakter, dari `!` (33) hingga `~` (126)). Enkripsi: `c[i] = alphabet[(index(c) + 47) % 94]`. Karena 47 × 2 = 94, operasi ini **involusi** — encode dan decode identik.
2. **Rahasia di Sisi Klien:** Kunci/rahasia yang tertanam dalam artefak yang didistribusikan ke peserta (*client-side secret*) selalu dapat diekstrak — tidak ada gunanya "menyembunyikan" dengan menyandikan saja.
3. **Kode Mati (*Dead Code*):** Fungsi `decode_secret` justru memberi tahu analis persis algoritma pembalikannya.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh artefak:
   ```bash
   curl -sL -O https://challenge-files.cylabacademy.net/library/1eb77f4c882ea622da246f47b4359567016b003c1856cdd9c58d7e5d95b/crackme_gen.py
   ```
2. Identifikasi alfabet acuan dan konstanta putar (`rotate_const = 47`) di dalam berkas.
3. Terapkan ROT47 ke `24256>JL`>0c0Abc?FE02a_53e7fe7af5gN`:
   ```python
   alpha = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
   secret = "24256>JL`>0c0Abc?FE02a_53e7fe7af5gN"
   flag = "".join(alpha[(alpha.find(c) + 47) % len(alpha)] for c in secret)
   # -> academy{1m_4_p34nut_a20db6f76f27d8}
   ```
4. Tidak perlu menjalankan program interaktif sama sekali.

---

## Flag & Verifikasi
- **Flag:** `academy{1m_4_p34nut_a20db6f76f27d8}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Cipher Klasik Wajib Dikuasai:** ROT13/ROT47, Caesar, Vigenere, Base64 — selalu uji artefak terhadap semuanya sebelum analisis dalam.
- **Jangan Tanam Rahasia di Artefak Klien:** Kunci API, token, dan flag tidak boleh didistribusikan bersama kode yang bisa dibaca peserta. Validasi harus terjadi di sisi server.
- **Mitigasi:** Jika ofuskasi diperlukan, gunakan enkripsi dengan kunci yang disimpan di server, bukan penyandian reversibel di dalam berkas yang sama.
