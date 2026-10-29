# Tap into Hash (Challenge 466, Reverse Engineering)

- **ID:** 466 | **Event:** picoCTF 2025 | **Kategori:** Reverse Engineering | **Level:** Medium
- **Flag:** `academy{block_3SRhViRbT1qcX_XUjM0r49cH_qCzmJZzBK_3a847c57}` (recovered lokal, roundtrip OK;

## Skenario
File `enc_flag` berisi DUA baris cetakan `main()`: `Key: b'...'` (token acak
32 byte) dan `Encrypted Blockchain: b'...'` (384 byte = 24 blok). `encrypt()`
menyisipkan token di tengah string hash-chain blok, PKCS7-pad, lalu XOR tiap
blok 16 byte dengan `sha256(key).digest()`. Kunci ada di file yang sama —
tidak perlu memecahkan hash apa pun.

## Root Cause
Kunci enkripsi ikut didistribusikan bersama ciphertext (key disclosure).
XOR dengan digest yang bisa direkonstruksi = obfuscation, bukan enkripsi.
Pelajaran: jangan pernah menyimpan kunci di samping data terenkripsi; gunakan
KDF + nonce acak dan pisahkan manajemen kunci.

## Rekonstruksi
1. Parse dua literal `b'...'` dari `enc_flag` (`ast`/eval aman: file lokal).
2. `k16 = sha256(key).digest()[:16]` — `xor_bytes` zip 32-byte digest lawan
   blok 16 byte, jadi hanya 16 byte pertama yang terpakai.
3. XOR ulang tiap blok 16 byte dengan `k16`, buang padding PKCS7
   (`pt[:-pt[-1]]`), decode UTF-8.
4. Flag `academy{...}` tertanam di tengah rantai hash blok.
   Otomasi: `python3 scripts/solve_466_tap_into_hash.py enc_flag`.

## Mitigasi
Pisahkan kunci dari ciphertext (KMS/HSM), gunakan AEAD (AES-GCM), dan jangan
mencetak material kunci ke log/output.

## Takeaway LKS
Klasifikasi Reverse Engineering: membaca alur `encrypt()` → mengenali XOR
simetris yang bisa dibalik + parsing format output program. Fondasi pola
"key-in-file" yang muncul di banyak tantangan forensik/reversing.
