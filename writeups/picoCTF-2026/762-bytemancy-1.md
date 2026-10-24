# Writeup: bytemancy 1 (Challenge ID: 762)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Scripting & Byte Encoding
- **Difficulty:** Easy
- **Author:** CyLab Team
- **Event:** picoCTF 2026
- **Points:** 100
- **Flag:** `academy{h0w_m4ny_e's???_6fd2faa9}`

---

## Deskripsi Tantangan
> Can you conjure the right bytes?
> Source: `app.py`
> Hint: No copy-pasta, please - use Python!

---

## Analisis & Solusi
Membaca source code Python `app.py` target:
```python
    user_input = input('==> ')
    if user_input == "\x65"*1751:
      print(open("./flag.txt", "r").read())
      break
```

Kode heksadesimal `\x65` dalam desimal bernilai 101, yang merepresentasikan karakter ASCII `'e'`.
Program meminta string karakter `'e'` yang diulang persis sebanyak 1751 kali.

### Solver Python (Socket)
```python
import socket

s = socket.socket()
s.connect(('chatelaine.cylabacademy.net', 41819))
s.recv(4096)

payload = ('e' * 1751) + '\n'
s.sendall(payload.encode('utf-8'))
out = s.recv(4096).decode('utf-8', errors='ignore')
print(out)
```

Server memverifikasi panjang dan nilai byte string, lalu mencetak isi file `flag.txt`:
Flag: `academy{h0w_m4ny_e's???_6fd2faa9}`.
