# Writeup: fixme2.py (Challenge ID: 241)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Python Debugging
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** Beginner picoMini 2022
- **Playlist:** Python in CTF's (Module 110)
- **Points:** 25
- **Flag:** `academy{3qu4l1ty_n0t_4551gnm3nt_ad29eab9}`

---

## Deskripsi Tantangan
> Fix the syntax error in this Python script to print the flag.
> Download: `fixme2.py`

---

## Analisis & Solusi
Membuka berkas Python `fixme2.py`:
```python
flag = str_xor(flag_enc, 'enkidu')

# Check that flag is not empty
if flag = "":
  print('String XOR encountered a problem, quitting.')
else:
  print('That is correct! Here\'s your flag: ' + flag)
```

Terdapat kesalahan sintaks operator perbandingan pada baris 21 (`SyntaxError: invalid syntax. Maybe you meant '==' or ':=' instead of '='?`). Program menggunakan operator penugasan (*assignment*) `=` di dalam kondisi `if`, bukannya operator kesetaraan (*equality*) `==`.

### Perbaikan
Mengganti `=` menjadi `==`:
```python
if flag == "":
  print('String XOR encountered a problem, quitting.')
else:
  print('That is correct! Here\'s your flag: ' + flag)
```

Mengeksekusi skrip:
```bash
python3 fixme2.py
```
Output:
`That is correct! Here's your flag: academy{3qu4l1ty_n0t_4551gnm3nt_ad29eab9}`

Flag: `academy{3qu4l1ty_n0t_4551gnm3nt_ad29eab9}`.
