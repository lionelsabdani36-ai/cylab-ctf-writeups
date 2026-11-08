# Writeup: MultiCode (Challenge ID: 710)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Multi-Layer Encoding & De-obfuscation
- **Difficulty:** Easy (1)
- **Event:** picoCTF 2026
- **Points:** 100
- **Author:** CyLab Academy
- **Flag:** `academy{nested_enc0ding_74af0c65}`

---

## Problem Statement & Scope
Tantangan `MultiCode` menyajikan berkas teks terenkripsi/terobfuskasi bertingkat (`message.txt`) yang dicegat dari komunikasi jaringan mencurigakan:
> "We intercepted a suspiciously encoded message, but it’s clearly hiding a flag. No encryption, just multiple layers of obfuscation."

Tantangan ini menguji kompetensi dasar peserta kompetisi LKS Cyber Security dalam mengidentifikasi pola pengkodean biner/teks (*pattern recognition*), mengurai rantai transformasi berlapis (*layered de-obfuscation pipeline*), serta menerapkan standar spesifikasi protokol internet (RFC) dan prinsip pengujian reproduktif NIST SP 800-115.

Lingkungan target menyediakan artefak statis pada CDN CyLab:
`https://challenge-files.cylabacademy.net/library/c3ba15daad71c2f215d6e6db4a6d4c70a4696eef42dd338372287cc4d2a6268e/message.txt`

---

## Teori & Akar Kerentanan (Root Cause Theory)
Obfuskasi data adalah teknik menyamarkan muatan informasi agar tidak terbaca langsung oleh inspeksi kasat mata (*casual inspection*) tanpa menggunakan algoritma kriptografi asimetris/simetris berkunci rahasia. Dalam analisis insiden malware dan forensic stream analysis (NIST SP 800-115 Bagian 4.1), penyerang sering kali menggabungkan beberapa skema pengkodean standar untuk mengelabui filter deteksi berbasis tanda tangan (*signature-based IDS/IPS*).

Empat lapisan pengkodean standar yang diimplementasikan secara berurutan:
1. **Base64 Encoding (RFC 4648 §4):**
   Mekanisme representasi data biner ke dalam 64 karakter ASCII aman cetak (`A-Z`, `a-z`, `0-9`, `+`, `/`) dengan padding karakter sama dengan (`=`). Pola string masukan berakhiran `=` mengindikasikan pengisian Base64 pada blok 24-bit.
2. **Hexadecimal ASCII Representation (RFC 4648 §8):**
   Keluaran dari Base64 menghasilkan sekuens pasangan digit heksadesimal (`0-9`, `a-f`). Setiap byte ASCII direpresentasikan oleh 2 nibble (misalnya `0x6e` melambangkan huruf `'n'`).
3. **Uniform Resource Identifier (URI) Percent-Encoding (RFC 3986 §2.1):**
   Mekanisme pelolosan karakter khusus pada URL di mana byte non-unreserved diwakili oleh tanda persen `%` diikuti oleh dua digit heksadesimal. Karakter pembatas `{` direpresentasikan sebagai `%7B`, dan `}` direpresentasikan sebagai `%7D`.
4. **Caesar Substitution Cipher / ROT13 (RFC 4880):**
   Sandi substitusi monoalfabetik simetris dengan pergeseran 13 karakter alfabet Latin ($C \equiv P + 13 \pmod{26}$). Sifat involutif ROT13 ($\text{ROT13}(\text{ROT13}(x)) = x$) memungkinkan operasi dekripsi dilakukan menggunakan tabel pergeseran yang identik.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Inspeksi String Masukan:**
   String masukan mentah pada berkas `message.txt`:
   ```text
   NmU3MDZlNzE3MjdhNmMyNTM3NDI2MTcyNjY2NzcyNzE1ZjcyNjE3MDMwNzE3NjYxNzQ1ZjM3MzQ2ZTczMzA3MDM2MzUyNTM3NDQ=
   ```
   Tanda padding tunggal `=` di akhir string memastikan data adalah Base64 valid.

2. **Eksekusi Dekode Layer 1 (Base64 -> Hex):**
   ```python
   import base64
   layer1 = base64.b64decode(raw).decode('utf-8')
   ```
   Hasil:
   ```text
   6e706e71727a6c2537426172666772715f72617030717661745f37346e7330703635253744
   ```

3. **Eksekusi Dekode Layer 2 (Hex -> URL Encoded):**
   Mengonversi sekuens heksadesimal menjadi string ASCII:
   ```python
   layer2 = bytes.fromhex(layer1).decode('utf-8')
   ```
   Hasil:
   ```text
   npnqrzl%7Barfgrq_rap0qvat_74ns0p65%7D
   ```

4. **Eksekusi Dekode Layer 3 (URL Unquote -> ROT13):**
   Menguraikan percent-encoding RFC 3986:
   ```python
   import urllib.parse
   layer3 = urllib.parse.unquote(layer2)
   ```
   Hasil:
   ```text
   npnqrzl{arfgrq_rap0qvat_74ns0p65}
   ```
   Pola `npnqrzl{...}` memiliki struktur dan panjang yang identik dengan format token `academy{...}`.

5. **Eksekusi Dekode Layer 4 (ROT13 Reversal -> Plaintext Flag):**
   Menerapkan pergeseran -13 karakter alfabet:
   ```python
   import codecs
   flag = codecs.decode(layer3, 'rot13')
   ```
   Hasil:
   ```text
   academy{nested_enc0ding_74af0c65}
   ```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{nested_enc0ding_74af0c65}`
- **Format Token Komunitas:** `CTF{nested_enc0ding_74af0c65}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_710_multicode.py` (HTTP 201 correct=True via `POST /api/submissions/`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Analisis Protokol & Penegakan Normalisasi Input:**
   Dalam arsitektur *Web Application Firewall* (WAF) dan sistem IDS/IPS (Suricata, Snort), kegagalan melakukan *recursive multi-step URL decoding* memungkinkan penyerang menyelundupkan muatan injeksi (XSS/SQLi) melalui *nested encoding evasion*. Solusi defensif mewajibkan dekode rekursif hingga mencapai kanonikal sebelum evaluasi pola berbahaya.
2. **Obfuscation vs Cryptographic Security:**
   Pengembang sistem dilarang mengandalkan rantai pengkodean terbuka (*security through obscurity*) untuk mengamankan data sensitif atau token otentikasi. Seluruh data rahasia wajib diamankan dengan algoritma enkripsi standar (AES-GCM-256) dengan manajemen kunci terisolasi (KMS/HSM).
