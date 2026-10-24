# Writeup: Neuron Express 0 (Challenge ID: 769)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Parameter Recovery
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{n3ur0n_expr_f075f57b}`

---

## Deskripsi Tantangan
> Probe a 1D perceptron over the network. Send it integers and watch whether the neuron fires or not. Use those responses to figure out the underlying weight and bias, then submit your guess with the TEST command to earn the flag.
> Command: `TEST w b`

---

## Analisis & Solusi
Sampling output bilangan bulat $x \in [-10, 10]$:
- Untuk $x \le 1 \rightarrow 0$ (stays quiet)
- Untuk $x \ge 2 \rightarrow 1$ (fires)

Batas keputusan berada pada $x = 2$:
$$w \cdot x + b \ge 0$$
Dengan $w = 1$:
$$1(2) + b = 0 \implies b = -2$$

Verifikasi command:
`TEST 1 -2`

Output server: `Perfect match! Here is your flag:`
Flag: `academy{n3ur0n_expr_f075f57b}`.
