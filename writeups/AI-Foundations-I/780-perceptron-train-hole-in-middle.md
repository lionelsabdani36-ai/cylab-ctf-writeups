# Writeup: Perceptron Train Hole in Middle (Challenge ID: 780)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{h0l3_1n_m1ddl3_unl34rn4bl3_l1n34rly_c85a6043}`

---

## Deskripsi Tantangan
> Watch a perceptron learn in real time on a "hole in the middle" pattern: positive points surround one negative center point. The classic perceptron update rule still applies (only misclassified points trigger updates, with no weight decay), but this shape is not linearly separable by a single line. Reach 88.9% accuracy to reveal the flag.
> Instance: `http://chatelaine.cylabacademy.net:36063/`

---

## Analisis & Teori Mesin Pembelajar
Pola *"Hole in the Middle"* terdiri dari:
- 8 titik positif ($label = 1$) yang mengelilingi pusat lingkaran.
- 1 titik negatif ($label = 0$) tepat di pusat koordinat $(0, 0)$.

Secara topologis, pemisahan titik pusat yang dikelilingi oleh kelas lain membutuhkan kurva tertutup (lingkaran / batas kuadratik $x^2 + y^2 < r^2$), bukan garis linear $w_1 x + w_2 y + b = 0$.
Karena model yang digunakan adalah Single-Layer Perceptron linear, akurasi maksimal adalah mengklasifikasikan seluruh 8 titik luar dengan benar dan mengorbankan titik pusat (atau sebaliknya):
$$\text{Akurasi Maksimal} = \frac{8}{9} \approx 88.89\%$$

---

## Solusi Eksploitasi
Mengirimkan parameter training `learningRate: 0.2` ke endpoint `/train`:

```python
import urllib.request
import json

req = urllib.request.Request(
    'http://chatelaine.cylabacademy.net:36063/train',
    data=json.dumps({'learningRate': 0.2}).encode('utf-8'),
    headers={'Content-Type': 'application/json'}
)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())
    print("Flag:", data.get('flag'))
```

---

## Hasil & Verifikasi
- **Akurasi Tercapai:** 88.89% (8/9 sample benar)
- **Flag yang Diterima:** `academy{h0l3_1n_m1ddl3_unl34rn4bl3_l1n34rly_c85a6043}`
- **Submisi:** Validated by CyLab API (`solved_by_user = true`).
