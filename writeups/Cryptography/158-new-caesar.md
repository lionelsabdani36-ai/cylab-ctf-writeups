# Writeup: New Caesar (Challenge ID: 158)

- **Platform:** CyLab Security Academy (picoCTF 2021)
- **Category:** Cryptography / Base16 & Caesar Shift
- **Difficulty:** Medium
- **Playlist:** Cryptography and Challenge Library Learning Intro (Module 136)
- **Points:** 60
- **Flag:** `academy{et_tu?_a91448ca}`

---

## Deskripsi Tantangan
> We found a brand new type of encryption, can you break the secret code? (Wrap with academy{})
> Ciphertext: `cbdabldadbplblcnpfpnpapapecpcn`
> File: `new_caesar.py`

---

## Analisis & Solusi
Skrip enkripsi `new_caesar.py` melakukan:
1. `b16_encode`: Memetakan setiap byte (8 bit) menjadi dua karakter alfabet 4 bit (`a`-`p`).
2. `shift`: Menambahkan offset karakter kunci 1-karakter `key` ke tiap karakter base16 modulo 16.
Karena panjang kunci hanya 1 huruf (`k in 'abcdefghijklmnop'`), ruang pencarian kunci hanya berjumlah 16 kemungkinan.

### Skrip Solver Python
```python
import string

LOWERCASE_OFFSET = ord('a')
ALPHABET = string.ascii_lowercase[:16]
enc = 'cbdabldadbplblcnpfpnpapapecpcn'

def unshift(c, k):
    t2 = ord(k) - LOWERCASE_OFFSET
    idx = ALPHABET.index(c)
    t1 = (idx - t2) % len(ALPHABET)
    return ALPHABET[t1]

def b16_decode(s):
    res = ''
    for i in range(0, len(s), 2):
        b1 = ALPHABET.index(s[i])
        b2 = ALPHABET.index(s[i+1])
        res += chr((b1 << 4) | b2)
    return res

for k in ALPHABET:
    dec = b16_decode(''.join(unshift(c, k) for c in enc))
    if 'et_tu' in dec:
        print(f'Kunci {k}: academy{{{dec}}}')
```
Pada kunci `m`: dihasilkan teks `et_tu?_a91448ca`.

Flag: `academy{et_tu?_a91448ca}`.
