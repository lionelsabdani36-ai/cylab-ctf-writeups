# Writeup: Neuron Express 2D-0 (Challenge ID: 770)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Parameter Recovery
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{n3ur0n_expr_2d_0159e40e}`

---

## Deskripsi Tantangan
> Probe a 2D perceptron over the network. Send it integer pairs (x, y) and watch whether the neuron fires or not. Use those responses to figure out the underlying integer weights and bias, then submit your guess with the TEST command to earn the flag.
> Command: `TEST w1 w2 b`

---

## Analisis & Solusi
Perceptron 2D memenuhi aturan: $w_1 x + w_2 y + b \ge 0 \rightarrow 1$.
Dilakukan sampling 28 titik uji pada sumbu koordinat:
- $x = 0$ menghasilkan nilai identik independen terhadap $y$, membuktikan bahwa $w_2 = 0$.
- Transisi output terjadi pada koordinat $x = 3$:
  - Untuk $x \ge 3$, output = 1
  - Untuk $x < 3$, output = 0

Dengan $w_2 = 0$ dan $w_1 = 1$:
$$1(3) + 0(y) + b \ge 0 \implies b = -3$$

Verifikasi command:
`TEST 1 0 -3`

Output server: `Perfect match! Here is your flag:`
Flag: `academy{n3ur0n_expr_2d_0159e40e}`.
