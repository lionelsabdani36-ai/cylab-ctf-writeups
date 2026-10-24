# Writeup: Perceptron Play 1D Alpha (Challenge ID: 773)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{0n3_d_thr35h0ld_0291d6fb}`

---

## Deskripsi Tantangan
> Play with the weight and bias of a 1D perceptron on a number line. Adjust the parameters until every labeled point is classified correctly and you will earn the flag.

---

## Analisis & Solusi
Dataset 1D dengan sebaran:
- Titik kelas 0: $x \in \{-4, -2, 0\}$
- Titik kelas 1: $x \in \{2, 3, 4\}$

Aturan aktivasi perceptron 1D:
$$\hat{y} = \begin{cases} 1 & \text{jika } w \cdot x + b \ge 0 \\ 0 & \text{jika } w \cdot x + b < 0 \end{cases}$$

Dengan bobot awal $w = 1, b = 0$, titik $x = 0$ menghasilkan $1(0) + 0 = 0 \ge 0 \rightarrow 1$ (salah, karena targetnya 0).
Threshold optimal berada di antara 0 dan 2, yakni $x = 1$.
Menyetel $w = 1.0, b = -1.0$:
- $x = 0 \rightarrow 1(0) - 1 = -1 < 0 \rightarrow 0$ (Benar)
- $x = 2 \rightarrow 1(2) - 1 = 1 \ge 0 \rightarrow 1$ (Benar)

Perintah soket: `SET 1 -1` lalu `CHECK`.
Flag: `academy{0n3_d_thr35h0ld_0291d6fb}`.
