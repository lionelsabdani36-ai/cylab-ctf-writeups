# Writeup: MultiCode (Challenge ID: 710)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Multi-Layer Encoding
- **Difficulty:** Easy
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Points:** 200
- **Flag:** `academy{nested_enc0ding_74af0c65}`

---

## Deskripsi Tantangan
> We intercepted a suspiciously encoded message, but it’s clearly hiding a flag. No encryption, just multiple layers of obfuscation.

---

## Analisis Decoding Pipeline
Ciphertext awal:
`NmU3MDZlNzE3MjdhNmMyNTM3NDI2MTcyNjY2NzcyNzE1ZjcyNjE3MDMwNzE3NjYxNzQ1ZjM3MzQ2ZTczMzA3MDM2MzUyNTM3NDQ=`

### Tahapan Decoding:
1. **Layer 1 (Base64 Decode):**
   Dihasilkan string heksadesimal:
   `6e706e71727a6c2537426172666772715f72617030717661745f37346e7330703635253744`
2. **Layer 2 (Hex Decode):**
   Dihasilkan string dengan URL encoding:
   `npnqrzl%7Barfgrq_rap0qvat_74ns0p65%7D`
3. **Layer 3 (URL Unquote):**
   Karakter `%7B` menjadi `{` dan `%7D` menjadi `}`:
   `npnqrzl{arfgrq_rap0qvat_74ns0p65}`
4. **Layer 4 (ROT13 Shift -13):**
   Rotasi huruf 13 posisi mengembalikan plaintext flag:
   `academy{nested_enc0ding_74af0c65}`
