# Writeup: Perceptron Train XOR (Challenge ID: 782)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{x0r_unl34rn4bl3_by_p3rc3ptr0ns_d7c0c598}`

---

## Deskripsi Tantangan
> Watch a perceptron learn in real time on XOR data using the classic update rule: only misclassified points trigger updates, with no weight decay. Because XOR is not linearly separable, a single perceptron cannot hit 100% accuracy. Reach 75% accuracy to prove you understand the limitation and reveal the flag.
> Instance: `http://xebec.cylabacademy.net:22064/`

---

## Analisis & Teori Mesin Pembelajar
Perceptron sederhana satu lapis (Single-Layer Perceptron) hanya mampu memisahkan kelas data yang bersifat **linearly separable** (dapat dipisahkan dengan sebuah garis lurus / hyperplane berdimensi $n-1$).

Distribusi titik XOR pada ruang 2D:
- $( -2, -2 ) \rightarrow 0$ (Kelas 0)
- $( 2, 2 ) \rightarrow 0$ (Kelas 0)
- $( -2, 2 ) \rightarrow 1$ (Kelas 1)
- $( 2, -2 ) \rightarrow 1$ (Kelas 1)

Titik-titik ini membentuk pola silang (diagonal) yang mustahil dipisahkan secara sempurna oleh garis lurus tunggal $w_1 x + w_2 y + b = 0$. Akurasi teoritis maksimum untuk model linear pada problem XOR adalah $3/4 = 75\%$.

---

## Solusi Eksploitasi
Aplikasi web menyediakan endpoint `/train` yang menerima parameter `learningRate`:

```http
POST /train HTTP/1.1
Content-Type: application/json

{"learningRate": 0.02}
```

Dengan menyetel learning rate minimum $\eta = 0.02$, model mencapai batas konvergensi separasi 3 titik benar dan 1 titik salah (akurasi $75\%$), memenuhi kriteria keberhasilan dan mengembalikan flag.

### Script Solver Otomatis
```python
import urllib.request
import json

req = urllib.request.Request(
    'http://xebec.cylabacademy.net:22064/train',
    data=json.dumps({'learningRate': 0.02}).encode('utf-8'),
    headers={'Content-Type': 'application/json'}
)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())
    print("Flag:", data.get('flag'))
```

---

## Hasil & Verifikasi
- **Akurasi Akhir:** 75.0%
- **Flag yang Diterima:** `academy{x0r_unl34rn4bl3_by_p3rc3ptr0ns_d7c0c598}`
- **Submisi:** Validated by CyLab API (`solved_by_user = true`).
