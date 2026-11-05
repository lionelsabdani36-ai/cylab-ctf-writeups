# Writeup: substitution0 (Challenge ID: 307)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Monoalphabetic Substitution Cipher Analysis
- **Difficulty:** Medium (diff=2)
- **Author:** Will Hong
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{5UB5717U710N_3V0LU710N_6A8C4822}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan kriptanalisis terhadap sandi substitusi monoalfabetik (*monoalphabetic substitution cipher*):
> *"A message has come in but it seems to be all scrambled. Luckily it seems to have the key at the beginning. Can you crack this substitution cipher? Download the message here."*
> *Hint: Try a frequency attack. An online tool might help.*

Peserta diberikan berkas teks `message.txt` yang memuat baris kunci permutasian alfabet diikuti oleh badan teks cerita yang tersandi dan diakhiri dengan token flag terenkripsi:
```text
DJHMILABFORYVGNKUXQSCPEWZT 

Bixickng Yiaxdgm dxnqi, efsb d axdpi dgm qsdsiyz dfx, dgm jxncabs vi sbi jiisyi ...
Sbi lyda fq: dhdmivz{5CJ5717C710G_3P0YC710G_6D8H4822}
```

Tujuan modul adalah memetakan kembali alfabet sandi ke alfabet standar $A\text{-}Z$ dan merekonstruksi plaintext token flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Prinsip Sandi Substitusi Monoalfabetik:**
   - Sandi substitusi monoalfabetik menggantikan setiap huruf dalam alfabet plaintext $P = \{A, B, \dots, Z\}$ dengan huruf unik dalam alfabet sandi $\mathcal{K} = \{\pi(A), \pi(B), \dots, \pi(Z)\}$, di mana $\pi$ adalah fungsi permutasi bijektif berukuran 26.
   - Meskipun ruang kunci permutasi alfabetik bernilai $26! \approx 4.03 \times 10^{26}$ (sulit untuk *brute-force* acak), sandi ini memiliki kelemahan mendasar: **frekuensi karakter tidak terdistribusi ulang (zero diffusion)**. Karakter dengan frekuensi tinggi dalam bahasa Inggris (seperti 'E', 'T', 'A', 'O', 'I', 'N') mempertahankan proporsi frekuensi yang identik pada ciphertext.

2. **Kelemahan Penyerahan Kunci Dalam Teks Terbuka (Cleartext Key Delivery):**
   - Pada modul ini, penyusun tantangan menyertakan kunci permutasi secara eksplisit pada baris pertama berkas (`DJHMILABFORYVGNKUXQSCPEWZT`).
   - Dengan pemetaan posisi $i \in [0, 25]$:
     $$\text{Ciphertext}[i] \longleftrightarrow \text{Plaintext}[i]$$
     $$D \to A, J \to B, H \to C, M \to D, I \to E, L \to F, \dots, T \to Z$$
   - Hal ini memungkinkan pemulihan teks terbuka secara instan tanpa perlu menjalankan analisis frekuensi statistik heuristik (*heuristic frequency attack*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Artefak Berkas:**
   Unduh dokumen tersandi dari repositori CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/c81cd186dacb4ad82560df3b81fe365fc1c38a1c7dca9a73a9604c5345ab4473/message.txt
   ```

2. **Inspeksi Struktur Berkas:**
   ```bash
   head -n 2 message.txt
   tail -n 2 message.txt
   ```
   Keluaran:
   ```text
   DJHMILABFORYVGNKUXQSCPEWZT 

   Sbi lyda fq: dhdmivz{5CJ5717C710G_3P0YC710G_6D8H4822}
   ```

3. **Substitusi Huruf Menggunakan Linux `tr`:**
   Kunci permutasi baris pertama adalah:
   `DJHMILABFORYVGNKUXQSCPEWZT`
   Karena baris pertama memetakan alfabet sandi ke alfabet standar $A\text{-}Z$, kita susun argumen penggantian `tr`:
   ```bash
   tail -n 1 message.txt | tr 'DJHMILABFORYVGNKUXQSCPEWZTdjhmilabforyvgnkuxqscpewzt' 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
   ```
   Keluaran langsung menampilkan plaintext flag:
   ```text
   The flag is: academy{5UB5717U710N_3V0LU710N_6A8C4822}
   ```

4. **Verifikasi Teks Lengkap via Python:**
   Memetakan seluruh badan teks mengonfirmasi cerita novel Edgar Allan Poe "The Gold-Bug":
   ```python
   key = "DJHMILABFORYVGNKUXQSCPEWZT"
   plain_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
   c2p = {k: v for k, v in zip(key, plain_alpha)}
   c2p.update({k.lower(): v.lower() for k, v in zip(key, plain_alpha)})
   
   flag_cipher = "dhdmivz{5CJ5717C710G_3P0YC710G_6D8H4822}"
   flag_plain = "".join(c2p.get(c, c) for c in flag_cipher)
   print("[+] Plaintext Flag:", flag_plain)
   ```
   Keluaran:
   ```text
   [+] Plaintext Flag: academy{5UB5717U710N_3V0LU710N_6A8C4822}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{5UB5717U710N_3V0LU710N_6A8C4822}`
- **Verifikasi API Platform:** Validasi token melalui endpoint `POST /api/submissions/` menghasilkan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 307, "flag": "academy{5UB5717U710N_3V0LU710N_6A8C4822}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi Inti LKS Cyber Security:** Dalam skenario CTF pertahanan atau forensik kriptografi, peserta harus mampu membedakan sandi substitusi monoalfabetik dengan polialfabetik (seperti Vigenere). Memahami pembuatan tabel translasi (*translation table*) pada CLI Linux menggunakan `tr` atau Python `str.maketrans` mempercepat pemecahan artefak malware yang diobfuskasi dengan substitusi karakter statis.
- **Mitigasi Defensif:**
  1. *Larangan Kriptografi Kustom / Obfuscation (CWE-327):* Jangan mengandalkan sandi substitusi atau tabel permutasi buatan sendiri untuk menyembunyikan data sensitif di aplikasi, karena tabel dapat direkayasa balik (*reverse-engineered*) melalui analisis frekuensi atau dekompilasi statis.
  2. *Pemisahan Kunci dari Media Penyimpanan Data:* Kunci kriptografis tidak boleh disertakan di dalam berkas muatan atau media transmisi yang sama dengan ciphertext. Terapkan protokol pertukaran kunci yang aman seperti Diffie-Hellman / ECDH dengan sertifikat digital X.509.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_307_substitution0.py`.
