# Writeup: Perceptron Train XNOR (Challenge ID: 781)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{xn0r_unl34rn4bl3_by_p3rc3ptr0ns_da5e1216}`

---

## Deskripsi Tantangan
> Watch a perceptron learn in real time on XNOR data using the classic update rule: only misclassified points trigger updates, with no weight decay. Because XNOR is not linearly separable, a single perceptron cannot hit 100% accuracy. Reach 75% accuracy to prove you understand the limitation and reveal the flag.
> Instance: `http://xebec.cylabacademy.net:38226/`

---

## Analisis & Teori Mesin Pembelajar
Sama seperti gerbang logika XOR, gerbang **XNOR** (Exclusive NOR / kesamaan identitas logika) menghasilkan output:
- $( -2, -2 ) \rightarrow 1$ (Sama -> True)
- $( 2, 2 ) \rightarrow 1$ (Sama -> True)
- $( -2, 2 ) \rightarrow 0$ (Berbeda -> False)
- $( 2, -2 ) \rightarrow 0$ (Berbeda -> False)

Masalah ini adalah negasi langsung dari XOR dan memiliki karakteristik non-linear yang identik. Sebuah garis pemisah tunggal $w^T x + b = 0$ secara matematis hanya bisa memisahkan maksimal 3 dari 4 kuadran data, menghasilkan batas akurasi teoritis $75\%$.

---

## Solusi Eksploitasi
Mengirimkan request pelatihan via HTTP POST ke endpoint `/train` dengan parameter learning rate minimum $\eta = 0.02$:

```python
import urllib.request
import json

req = urllib.request.Request(
    'http://xebec.cylabacademy.net:38226/train',
    data=json.dumps({'learningRate': 0.02}).encode('utf-8'),
    headers={'Content-Type': 'application/json'}
)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())
    print("Flag:", data.get('flag'))
```

---

## Hasil & Verifikasi
- **Akurasi Tercapai:** 75.0%
- **Flag yang Diterima:** `academy{xn0r_unl34rn4bl3_by_p3rc3ptr0ns_da5e1216}`
- **Submisi:** Validated by CyLab API (`solved_by_user = true`).
