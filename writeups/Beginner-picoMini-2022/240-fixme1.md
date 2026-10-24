# Writeup: fixme1.py (Challenge ID: 240)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Python Debugging
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** Beginner picoMini 2022
- **Playlist:** Python in CTF's (Module 109)
- **Points:** 25
- **Flag:** `academy{1nd3nt1ty_cr1515_f63757ad}`

---

## Deskripsi Tantangan
> Fix the syntax error in this Python script to print the flag.
> Download: `fixme1.py`

---

## Analisis & Solusi
Membuka berkas Python `fixme1.py`:
```python
import random

def str_xor(secret, key):
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)        
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])

flag_enc = chr(0x04) + chr(0x0d) + ...

flag = str_xor(flag_enc, 'enkidu')
  print('That is correct! Here\'s your flag: ' + flag)
```

Terdapat kesalahan indentasi pada baris terakhir (`IndentationError: unexpected indent`). Pernyataan `print` memiliki indentasi spasi ekstra di luar blok fungsi atau kondisi apapun.

### Perbaikan
Menghapus spasi di depan perintah `print`:
```python
flag = str_xor(flag_enc, 'enkidu')
print('That is correct! Here\'s your flag: ' + flag)
```

Mengeksekusi skrip:
```bash
python3 fixme1.py
```
Output:
`That is correct! Here's your flag: academy{1nd3nt1ty_cr1515_f63757ad}`

Flag: `academy{1nd3nt1ty_cr1515_f63757ad}`.
