# Writeup: Perceptron Play Alpha (Challenge ID: 774)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{11n34r1y_53p4r4813_a4f2a27b}`

---

## Deskripsi Tantangan
> Play with the weights and bias of a 2D perceptron while watching an ASCII plot update in real time. Tune the parameters so that the decision boundary separates all of the labeled points and you will earn the flag. Connect with netcat:
> `$ nc xebec.cylabacademy.net 30983`

---

## Analisis & Teori Separabilitas Linear 2D
Tantangan ini menyajikan lingkungan eksplorasi parameter bobot ($w_1, w_2$) dan bias ($b$) dari perceptron 2 dimensi dengan aturan keputusan:
$$\hat{y} = \begin{cases} 1 & \text{jika } w_1 x + w_2 y + b \ge 0 \\ 0 & \text{jika } w_1 x + w_2 y + b < 0 \end{cases}$$

Dataset terdiri atas 6 titik terlabel:
- **Kelas 0:** `(-3, -2)`, `(-1, -1)`, `(-4, -2)` $\rightarrow$ Seluruhnya berada di kuadran ketiga ($x < 0, y < 0$)
- **Kelas 1:** `(+3, +1)`, `(+2, +2)`, `(+1, +3)` $\rightarrow$ Seluruhnya berada di kuadran pertama ($x > 0, y > 0$)

Garis batas keputusan tegak lurus terhadap vektor gradien diagonal $x + y = 0$ dapat memisahkan kedua klaster titik secara sempurna:
- $w_1 = 1.0$
- $w_2 = 1.0$
- $b = 0.0$

Aktivasi titik:
- Titik kelas 1: $(+3) + (+1) = 4 \ge 0 \rightarrow 1$ (Benar)
- Titik kelas 1: $(+2) + (+2) = 4 \ge 0 \rightarrow 1$ (Benar)
- Titik kelas 1: $(+1) + (+3) = 4 \ge 0 \rightarrow 1$ (Benar)
- Titik kelas 0: $(-3) + (-2) = -5 < 0 \rightarrow 0$ (Benar)
- Titik kelas 0: $(-1) + (-1) = -2 < 0 \rightarrow 0$ (Benar)
- Titik kelas 0: $(-4) + (-2) = -6 < 0 \rightarrow 0$ (Benar)

---

## Solusi Eksploitasi
Koneksi soket TCP interaktif menerima perintah `SET 1 1 0` untuk menetapkan vektor bobot dan bias secara langsung, kemudian perintah `CHECK` untuk memicu validasi dan ekstraksi flag:

```python
import socket

s = socket.socket()
s.connect(('xebec.cylabacademy.net', 30983))
s.recv(4096)

s.sendall(b'SET 1 1 0\n')
s.recv(4096)

s.sendall(b'CHECK\n')
out = s.recv(4096).decode()
print(out)
```

---

## Hasil & Verifikasi
- **Akurasi Tercapai:** 100.0% (6/6 titik terklasifikasi sempurna)
- **Flag yang Diterima:** `academy{11n34r1y_53p4r4813_a4f2a27b}`
- **Submisi:** Validated by CyLab API (`solved_by_user = true`).
