# Writeup: Perceptron Play Naught (Challenge ID: 775)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{n4ught_bu7_53p4r4b13_cf9e7c6f}`

---

## Deskripsi Tantangan
> The points would be inseparable in just the x-dimension, but each point now has a new y-value so the set becomes linearly separable in 2D. Watch the ASCII plot update in real time as you tweak the perceptron weights and bias. Separate the labeled points with a single line to earn the flag. Connect with netcat:
> `$ nc xebec.cylabacademy.net 28541`

---

## Analisis & Teori Pemisahan Dimensi Tambahan
Tantangan mendemonstrasikan konsep dasar penambahan dimensi fitur (basis dari *Kernel Trick* pada Support Vector Machines). Dalam 1 dimensi ($x$), titik-titik kelas 0 dan kelas 1 saling tumpang tindih sehingga tidak dapat dipisahkan oleh satu ambang batas linear.

Namun ketika fitur dimensi kedua ($y$) diberikan, distribusi titik menjadi:
- **Kelas 0:** `(-4, -1)`, `(0, -1)`, `(2, -1)` $\rightarrow$ semua memiliki koordinat $y = -1$.
- **Kelas 1:** `(-1, +2)`, `(+0, +2)`, `(+3, +1)`, `(+4, +2)` $\rightarrow$ semua memiliki koordinat $y \ge +1$.

Fungsi aktivasi perceptron:
$$f(x, y) = \begin{cases} 1 & \text{jika } w_1 x + w_2 y + b \ge 0 \\ 0 & \text{jika } w_1 x + w_2 y + b < 0 \end{cases}$$

Dengan menetapkan garis pemisah horizontal pada $y = 0$:
- $w_1 = 0$
- $w_2 = 1$
- $b = 0$

Maka:
- Untuk Kelas 0: $0(x) + 1(-1) + 0 = -1 < 0 \rightarrow 0$ (Benar)
- Untuk Kelas 1: $0(x) + 1(y) + 0 = y \ge 1 > 0 \rightarrow 1$ (Benar)

---

## Solusi Eksploitasi
Menghubungkan ke socket TCP interaktif dan mengirim perintah `SET 0 1 0` diikuti oleh `CHECK`:

```python
import socket

s = socket.socket()
s.connect(('xebec.cylabacademy.net', 28541))
s.recv(4096)

s.sendall(b'SET 0 1 0\n')
s.recv(4096)

s.sendall(b'CHECK\n')
out = s.recv(4096).decode()
print(out)
```

---

## Hasil & Verifikasi
- **Akurasi Tercapai:** 100.0% (7/7 titik terklasifikasi sempurna)
- **Flag yang Diterima:** `academy{n4ught_bu7_53p4r4b13_cf9e7c6f}`
- **Submisi:** Validated by CyLab API (`solved_by_user = true`).
