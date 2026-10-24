# Writeup: Perceptron Train 3-Bit Parity (Challenge ID: 776)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{3b1t_p4r1ty_unl34rn4bl3_l1n34rly_5d1cd0f2}`

---

## Deskripsi Tantangan
> Watch a perceptron learn in real time on 3-bit parity data using the classic update rule: only misclassified points trigger updates, with no weight decay. This challenge extends the same idea into 3 dimensions, and the frontend renders the points in 3D space. Because parity is not linearly separable by one plane, a single perceptron cannot hit 100% accuracy. Reach 75% accuracy to reveal the flag.
> Instance: `http://chatelaine.cylabacademy.net:45398/`

---

## Analisis & Teori Batas Separabilitas Non-Linear 3D
Fungsi paritas 3-bit ($x_1 \oplus x_2 \oplus x_3$) merupakan generalisasi multidimensi dari problem XOR. Dataset memetakan seluruh 8 simpul kubus pada ruang 3 dimensi $\mathbb{R}^3$:
- `(-2, -2, -2) -> 0` (Paritas genap)
- `(-2, -2,  2) -> 1` (Paritas ganjil)
- `(-2,  2, -2) -> 1` (Paritas ganjil)
- `(-2,  2,  2) -> 0` (Paritas genap)
- `( 2, -2, -2) -> 1` (Paritas ganjil)
- `( 2, -2,  2) -> 0` (Paritas genap)
- `( 2,  2, -2) -> 0` (Paritas genap)
- `( 2,  2,  2) -> 1` (Paritas ganjil)

Sebuah bidang datar tunggal $w_1 x_1 + w_2 x_2 + w_3 x_3 + b = 0$ secara matematis tidak dapat memisahkan simpul-simpul berparitas ganjil dan genap secara serentak (*Minsky & Papert, 1969*). Akurasi klasifikasi maksimum yang dapat dicapai oleh sebuah single-layer perceptron adalah 6 dari 8 titik ($75\%$).

---

## Solusi Eksploitasi
Tantangan menetapkan ambang keberhasilan `successThreshold = 0.75`. Server menyediakan endpoint `/train` yang menerima parameter `learningRate`:

```http
POST /train HTTP/1.1
Content-Type: application/json

{"learningRate": 0.12}
```

Dengan menguji rentang learning rate $\eta \in [0.02, 2.0]$, pada nilai $\eta = 0.12$ perceptron berhasil memisahkan 6 titik data secara akurat dalam batasan 16 langkah pembelajaran (`maxSteps = 16`), menghasilkan akurasi tepat $75\%$ dan merilis flag.

### Script Solver Otomatis
```python
import urllib.request
import json

req = urllib.request.Request(
    'http://chatelaine.cylabacademy.net:45398/train',
    data=json.dumps({'learningRate': 0.12}).encode('utf-8'),
    headers={'Content-Type': 'application/json'}
)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())
    print("Flag:", data.get('flag'))
```

---

## Hasil & Verifikasi
- **Akurasi Tercapai:** 75.0%
- **Flag yang Diterima:** `academy{3b1t_p4r1ty_unl34rn4bl3_l1n34rly_5d1cd0f2}`
- **Submisi:** Berhasil divalidasi oleh CyLab API (`solved_by_user = true`).
