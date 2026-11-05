# Writeup: Bases (Challenge ID: 67)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Base64 Encoding & Radix Representation
- **Difficulty:** Easy (diff=1)
- **Author:** Sanjay Bastola
- **Event:** picoCTF 2019
- **Points:** 100
- **Flag:** `academy{l3arn_th3_r0p35}`

---

## Problem Statement & Scope

Tantangan menyajikan untaian string acak `bDNhcm5fdGgzX3IwcDM1` dengan petunjuk terkait sistem basis data:
> *"What does this `bDNhcm5fdGgzX3IwcDM1` mean? I think it has something to do with bases. Submit your answer in our flag format. For example, if your answer was 'hello', you would submit 'academy{hello}' as the flag."*

Tujuan pembelajaran dari modul ini adalah menguji pengenalan skema pengodean biner-ke-teks (*binary-to-text encoding*), khususnya RFC 4648 Base64, serta mendidik peserta tentang perbedaan mendasar antara skema encoding (keterbacaan data transmisi) dan enkripsi (kerahasiaan data kriptografis).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Pengodean RFC 4648 (Base64):**
   - Skema pengodean Base64 dirancang untuk merepresentasikan data biner arbitrer dalam 64 karakter ASCII yang aman ditransmisikan melalui saluran berbasis teks (misalnya protokol SMTP, HTTP header, atau JSON).
   - Karakter set standar Base64: `A-Z` (indeks 0–25), `a-z` (indeks 26–51), `0-9` (indeks 52–61), `+` (indeks 62), dan `/` (indeks 63), dengan karakter padding `=`.
   - Setiap grup 3 oktet (24 bit) biner dipartisi menjadi 4 unit 6-bit ($2^6 = 64$ nilai unik).
   - String `bDNhcm5fdGgzX3IwcDM1` memiliki panjang 20 karakter ($20 \equiv 0 \pmod 4$), yang mengindikasikan 15 byte data terenkode tanpa memerlukan padding.

2. **Kekeliruan Asumsi: Encoding Bukan Enkripsi (CWE-312 / CWE-327):**
   - Banyak pengembang pemula mengasumsikan bahwa Base64 memberikan kerahasiaan (*confidentiality*). Pada kenyataannya, Base64 adalah pengodean reversibel publik tanpa kunci rahasia (*zero key entropy*).
   - Menggunakan Base64 untuk melindungi token otentikasi atau data kredensial tanpa lapisan kriptografi kunci simetris/asimetris adalah kerentanan arsitektural fatal.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis String Target:**
   Diberikan token masukan:
   ```text
   bDNhcm5fdGgzX3IwcDM1
   ```
   Karakter terdiri atas huruf kapital, huruf kecil, dan angka tanpa karakter khusus di luar alfabet RFC 4648.

2. **Dekode Menggunakan Utilitas Bash:**
   Gunakan utilitas CLI `base64 -d`:
   ```bash
   echo -n "bDNhcm5fdGgzX3IwcDM1" | base64 -d
   ```
   Keluaran:
   ```text
   l3arn_th3_r0p35
   ```

3. **Verifikasi via Python:**
   ```bash
   python3 -c "import base64; print(base64.b64decode('bDNhcm5fdGgzX3IwcDM1').decode())"
   ```
   Keluaran:
   ```text
   l3arn_th3_r0p35
   ```

4. **Pembentukan Token Flag:**
   Sesuai format resmi kompetisi, bungkus hasil dekode ke dalam `academy{...}`:
   ```text
   academy{l3arn_th3_r0p35}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{l3arn_th3_r0p35}`
- **Verifikasi API:** Validasi token pada endpoint `POST /api/submissions/` mengembalikan `{"correct": true, "challenge": 67}` (Status HTTP 201 Created).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kemampuan Triage Format Data Transmisi (LKS CTF & SOC Analyst):** Dalam analisis insiden lalu lintas web dan malware analysis, payload berbahaya (misal PowerShell one-liners `-EncodedCommand`, Basic Authentication HTTP header, atau Webhook tokens) umumnya dikemas dalam format Base64. Peserta LKS harus dapat mengenali entropi visual Base64 dalam hitungan detik.
- **Implementasi Enkripsi Kuat (Defensive):** Jangan pernah mengandalkan Base64 untuk menyembunyikan data sensitif di sisi klien (*client-side cookies*, localStorage, atau parameter URL). Gunakan enkripsi standar industri terotentikasi (seperti AES-256-GCM atau ChaCha20-Poly1305) jika kerahasiaan dan integritas data diperlukan.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_67_bases.py`.
