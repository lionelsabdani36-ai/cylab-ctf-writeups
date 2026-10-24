# Writeup: Neuron Meet 0 (Challenge ID: 771)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Perceptron Probing
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{n3ur0n_m3t_227803d1}`

---

## Deskripsi Tantangan
> Probe a 1D perceptron over the network. Send it numbers and watch whether the neuron fires or not. Use those responses to figure out the decision boundary, then line up the last eight outputs to read the ASCII for p (01110000) and you'll earn the flag.
> Rules: Bounds [-10, 10], no back-to-back duplicate inputs.

---

## Analisis & Solusi
Perceptron 1D: $w \cdot x + b \ge 0 \rightarrow 1$, else $0$.
Probing nilai input:
- Titik non-firing ($0$): $x \le 0$ (misal: `-10, -9, -8, -7`)
- Titik firing ($1$): $x \ge 5$ (misal: `10, 9, 8`)

Target urutan 8-bit untuk ASCII `'p'` (`01110000`):
1. `-10` -> 0
2. `10`  -> 1
3. `9`   -> 1
4. `8`   -> 1
5. `-10` -> 0
6. `-9`  -> 0
7. `-8`  -> 0
8. `-7`  -> 0

Flag: `academy{n3ur0n_m3t_227803d1}`.
