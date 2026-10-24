# Writeup: Perceptron Train Classic 0 (Challenge ID: 777)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{perceptron_classic_mode_02a3669e}`

---

## Deskripsi Tantangan
> Watch a perceptron learn in real time using the classic update rule: only misclassified points trigger updates, with no weight decay. This dataset is intentionally gentle, so many learning rates still converge quickly. Dial in a rate, trigger a run, and the interface will animate each step until every point is classified correctly.
> Instance: `http://xebec.cylabacademy.net:39452/`

---

## Analisis & Teori Konvergensi
Tantangan ini merupakan perkenalan dasar implementasi algoritma Rosenblatt Perceptron dengan aturan pembaruan Hebbian diskrit:
$$\Delta w = \eta (y - \hat{y}) x$$
$$\Delta b = \eta (y - \hat{y})$$

Dataset terdiri atas 8 titik data dua dimensi yang tersebar secara teratur:
- Titik Kelas 0: `(-4, -2)`, `(-3, -4)`, `(-2, -3)`, `(-3, -1)` (kuadran kiri bawah)
- Titik Kelas 1: `(3, 4)`, `(4, 2)`, `(2, 3)`, `(3, 1)` (kuadran kanan atas)

Margin pemisah antar kelas sangat longgar ($\gamma \gg 0$). Dengan batas iterasi 16 langkah (`maxSteps = 16`), laju pembelajaran $\eta = 0.02$ mampu mengoreksi vektor bobot awal $w_0 = [1.0, -1.0], b_0 = 0.0$ menuju hiperbidang separasi sempurna (akurasi $100\%$) hanya dalam beberapa iterasi.

---

## Solusi Eksploitasi
Cukup melakukan satu panggilan POST HTTP ke endpoint `/train` dengan parameter `learningRate` valid dalam rentang $[0.02, 2.0]$:

```python
import urllib.request
import json

req = urllib.request.Request(
    'http://xebec.cylabacademy.net:39452/train',
    data=json.dumps({'learningRate': 0.02}).encode('utf-8'),
    headers={'Content-Type': 'application/json'}
)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())
    print("Flag:", data.get('flag'))
```

---

## Hasil & Verifikasi
- **Akurasi Akhir:** 100.0%
- **Flag yang Diterima:** `academy{perceptron_classic_mode_02a3669e}`
- **Submisi:** Validated by CyLab API (`solved_by_user = true`).
