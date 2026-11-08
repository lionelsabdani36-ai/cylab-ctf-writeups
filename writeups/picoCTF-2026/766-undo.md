# Writeup: Undo (Challenge ID: 766)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / POSIX Text Processing & Stream Inversion (NIST SP 800-115 §4.2)
- **Difficulty:** Easy (1)
- **Points:** 100
- **Author:** Yahaya Meddy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{Revers1ng_t3xt_Tr4nsf0rm@t10ns_c77d80cc}`
- **Flag Komunitas:** `CTF{Revers1ng_t3xt_Tr4nsf0rm@t10ns_c77d80cc}`

---

## Problem Statement & Scope

Tantangan menguji kemahiran peserta dalam manipulasi aliran teks Linux POSIX standar melalui skenario pembalikan rantai transformasi data berlapis (*layered text transformation reversal*):
> *"Can you reverse a series of Linux text transformations to recover the original flag?"*

Layanan tantangan menyajikan sesi interaktif berbasis soket TCP netcat. Pada setiap tahap, server menampilkan potongan string terdistorsi bersama petunjuk (*hint*) mengenai operasi transformasi yang telah diterapkan pada aliran teks. Peserta dituntut memasukkan perintah utilitas POSIX yang tepat untuk membalikkan (*undo*) efek transformasi tersebut secara bertahap hingga teks asli terungkap seutuhnya.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Aljabar Pembalikan Transformasi Aliran Teks POSIX:**
   Suatu rangkaian transformasi dapat direpresentasikan sebagai komposisi fungsi linier/permutasi $F = T_n \circ \dots \circ T_2 \circ T_1$. Selama setiap fungsi komponen $T_i$ bersifat bijektif (*one-to-one and onto*), fungsi invers $F^{-1}$ dapat dieksekusi secara deterministik dengan menerapkan invers masing-masing operasi dalam urutan terbalik:
   $$F^{-1} = T_1^{-1} \circ T_2^{-1} \circ \dots \circ T_n^{-1}$$

2. **Karakteristik Utilitas Pembalik POSIX.1-2017:**
   - **Base64 Decoding (`base64 -d`):** Membalikkan encoding radiks-64 (RFC 4648) kembali ke representasi byte/karakter ASCII 8-bit.
   - **Sequence Inversion (`rev`):** Merupakan operasi involusi $R(R(S)) = S$, membalikkan urutan indeks karakter string dari posisi $n-1$ hingga 0.
   - **Transliterasi Karakter (`tr 'set1' 'set2'`):** Memetakan satu per satu elemen karakter dari himpunan asal ke himpunan tujuan. Invers dari penggantian karakter $a \to b$ adalah $b \to a$.
   - **Caesar Cipher Modulo 26 (`ROT13`):** Transformasi pergeseran alfabet dengan pergeseran 13 karakter. Karena $\gcd(13, 26) = 13$ dan $13 + 13 = 26 \equiv 0 \pmod{26}$, operasi ROT13 adalah involusi mandiri (*self-inverse*), dieksekusi via `tr 'A-Za-z' 'N-ZA-Mn-za-m'`.

3. **Implikasi Keamanan Arsitektur (CWE-319 / CWE-261 / NIST SP 800-115 §4.2):**
   Obfuskasi berlapis menggunakan encoding dan substitusi karakter sering kali disalahartikan sebagai enkripsi data (*security through obscurity*). Tanpa kunci rahasia (*cryptographic secret key*) dan jaminan integritas kriptografis (*MAC / Authenticated Encryption*), setiap lapisan transformasi rentan terhadap rekonstruksi deterministik oleh penyerang melalui analisis saluran statis (*static text stream analysis*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Tahap 1 — Pembalikan Base64 (`base64 -d`):**
   - *Input Terenkapsulasi:* `KXBwMDhxNzdwLWZhMDFnQHplMHNmYTRlRy1nazNnLXRhMWZlcmlyRShsenJxbnBu`
   - *Perintah POSIX:* `base64 -d`
   - *Output Antara:* `)pp08q77p-fa01g@ze0sfa4eG-gk3g-ta1ferirE(lzrqnpn`

2. **Tahap 2 — Pembalikan Urutan Karakter (`rev`):**
   - *Input Antara:* `)pp08q77p-fa01g@ze0sfa4eG-gk3g-ta1ferirE(lzrqnpn`
   - *Perintah POSIX:* `rev`
   - *Output Antara:* `npnqrzl(Eriref1at-g3kg-Ge4afs0ez@g10af-p77q80pp)`

3. **Tahap 3 — Transliterasi Pemisah Strip ke Garis Bawah (`tr '-' '_'`):**
   - *Input Antara:* `npnqrzl(Eriref1at-g3kg-Ge4afs0ez@g10af-p77q80pp)`
   - *Perintah POSIX:* `tr '-' '_'`
   - *Output Antara:* `npnqrzl(Eriref1at_g3kg_Ge4afs0ez@g10af_p77q80pp)`

4. **Tahap 4 — Normalisasi Delimiter Kurung ke Kurung Kurawal (`tr '()' '{}'`):**
   - *Input Antara:* `npnqrzl(Eriref1at_g3kg_Ge4afs0ez@g10af_p77q80pp)`
   - *Perintah POSIX:* `tr '()' '{}'`
   - *Output Antara:* `npnqrzl{Eriref1at_g3kg_Ge4afs0ez@g10af_p77q80pp}`

5. **Tahap 5 — Involusi Caesar ROT13 (`tr 'A-Za-z' 'N-ZA-Mn-za-m'`):**
   - *Input Antara:* `npnqrzl{Eriref1at_g3kg_Ge4afs0ez@g10af_p77q80pp}`
   - *Perintah POSIX:* `tr 'A-Za-z' 'N-ZA-Mn-za-m'`
   - *Output Final:* `academy{Revers1ng_t3xt_Tr4nsf0rm@t10ns_c77d80cc}`

6. **Eksekusi Solver Otomatis:**
   Skrip reproduktif `scripts/solve_766_undo.py` mengeksekusi pipeline di atas secara deterministik dan memverifikasi token ke REST API CyLab.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{Revers1ng_t3xt_Tr4nsf0rm@t10ns_c77d80cc}`
- **Format Flag Komunitas:** `CTF{Revers1ng_t3xt_Tr4nsf0rm@t10ns_c77d80cc}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 766, "flag": "academy{Revers1ng_t3xt_Tr4nsf0rm@t10ns_c77d80cc}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Pemahaman Fundamental Aliran Pipa Linux (*UNIX Philosophy & Stream Redirection*):**
   Dalam kompetensi LKS Cyber Security bidang Forensik Digital dan Incident Response, peserta dituntut mahir merangkai pipa utilitas baris perintah (`|`) untuk memproses artefak log, mendekode payload malware berlapis, dan mengekstrak indikator kompromi (IoC) secara cepat tanpa bergantung pada perkakas berbasis GUI.
2. **Prinsip "Obfuscation is not Encryption":**
   Sistem pertahanan tidak boleh mengandalkan skema encoding kustom atau permutasi karakter untuk melindungi data sensitif (*plaintext confidentiality*). Seluruh data dalam transit (*data-in-transit*) dan data tersimpan (*data-at-rest*) wajib dienkripsi menggunakan standar kriptografi modern (seperti AES-GCM atau ChaCha20-Poly1305) dengan manajemen kunci terisolasi (KMS/HSM).
3. **Validasi dan Normalisasi Aliran Masukan (NIST SP 800-115 §4.2):**
   Aplikasi harus menerapkan validasi masukan yang ketat sebelum memproses data bertingkat, mencegah eksploitasi deserialisasi atau manipulasi teks yang dapat memicu eksekusi perintah tak terduga (*arbitrary command injection*).
