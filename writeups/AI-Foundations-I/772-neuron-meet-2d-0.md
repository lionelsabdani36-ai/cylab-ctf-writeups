# Writeup: Neuron Meet 2D-0 (Challenge ID: 772)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Perceptron Probing
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{2d_n3ur0n_m3t_8c453797}`

---

## Deskripsi Tantangan
> Probe a 2D perceptron over the network. Send it pairs of numbers (x, y) and watch whether the neuron fires or not. Use those responses to figure out the decision boundary, then line up the last eight outputs to read the ASCII for p (01110000) and you'll earn the flag.
> Rules: Bounds [-10, 10], no back-to-back duplicate points.

---

## Analisis & Solusi
Tujuan adalah memicu 8 output berturut-turut yang cocok dengan representasi biner karakter ASCII `'p'` (`01110000`).
Melalui probing awal:
- Titik firing (1): `(10, 10)`, `(9, 9)`, `(8, 8)`
- Titik non-firing (0): `(-10, -10)`, `(-9, -9)`, `(-8, -8)`, `(-7, -7)`

Urutan input tanpa pengulangan back-to-back:
1. `(-10, -10)` -> 0
2. `(10, 10)`   -> 1
3. `(9, 9)`     -> 1
4. `(8, 8)`     -> 1
5. `(-10, -10)` -> 0
6. `(-9, -9)`   -> 0
7. `(-8, -8)`   -> 0
8. `(-7, -7)`   -> 0

Pola `01110000` terpenuhi dan service merespons dengan flag:
`academy{2d_n3ur0n_m3t_8c453797}`.
