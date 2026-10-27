# Writeup: vault-door-5 (Challenge ID: 77)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Layered Encoding Inversion
- **Difficulty:** Medium
- **Author:** Mark E. Haase
- **Event:** picoCTF 2019
- **Points:** 300
- **Flag:** `academy{c0nv3rt1ng_fr0m_ba5e_64_953e9301}`

---

## Problem Statement & Scope
Diberikan program Java `VaultDoor5.java`. Masukan kata sandi pengguna diubah menjadi representasi URL encoding terlebih dahulu, kemudian dienkodekan lagi menggunakan Base64 standar. Hasil akhirnya dibandingkan dengan string target berikut:
`JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVmJTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2JTM0JTVmJTM5JTM1JTMzJTY1JTM5JTMzJTMwJTMx`.
Analis diminta membalikkan rantai transformasi ganda tersebut.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Rantai Transformasi Reversibel (Encoding Pipeline):**
   Proses encoding yang diterapkan adalah:
   $$\text{Password} \xrightarrow{\text{URL Encode}} \text{String URL} \xrightarrow{\text{Base64 Encode}} \text{String Expected}$$
   Karena baik URL encoding (persen-encoding) maupun Base64 merupakan fungsi bijektif yang dapat dibalikkan secara langsung tanpa kunci (*lossless non-cryptographic transformations*), proses pemulihannya adalah:
   $$\text{Expected} \xrightarrow{\text{Base64 Decode}} \text{String URL} \xrightarrow{\text{URL Decode}} \text{Password}$$
2. **Kekeliruan Konseptual Encoding vs Encryption:** Menggabungkan beberapa algoritma encoding (seperti Base64 dan URL encoding) tidak meningkatkan keamanan kriptografis, melainkan hanya menambah sedikit latensi parsing bagi analis manusia.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Dekode string target dari format Base64:
   ```python
   import base64
   raw_url = base64.b64decode(expected).decode()
   # Output: %63%30%6e%76%33%72%74%31%6e%67%5f%66%72%30%6d%5f%62%61%35%65%5f%36%34%5f%39%35%33%65%39%33%30%31
   ```
2. Lakukan proses unquote / URL-decode terhadap string heksadesimal berpersen:
   ```python
   import urllib.parse
   password = urllib.parse.unquote(raw_url)
   # Output: c0nv3rt1ng_fr0m_ba5e_64_953e9301
   ```
3. Susun flag resmi: `academy{c0nv3rt1ng_fr0m_ba5e_64_953e9301}`.
4. Eksekusi solver Python terintegrasi:
   ```bash
   python3 scripts/solve_77_vault_door_5.py
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{c0nv3rt1ng_fr0m_ba5e_64_953e9301}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Standardisasi Enkripsi vs Serialisasi:** Format representasi data seperti Base64, Hex, atau URL-encoding dirancang murni untuk transport jaringan dan serialisasi data yang aman terhadap karakter kontrol, bukan untuk melindungi kerahasiaan (*confidentiality*).
- **Arsitektur Zero-Trust Kredensial:** Di dalam modul kompetensi pertahanan LKS, data sensitif wajib diamankan menggunakan algoritma enkripsi simetris terotentikasi (AES-256-GCM) dengan integritas data terjamin via HMAC atau GCM tag.
