# Writeup: Perceptron Train Classic 2 Alpha (Challenge ID: 779)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{perceptron_classic_2_alpha_5rates_13e2875c}`

---

## Deskripsi Tantangan
> Watch a perceptron learn in real time using the classic update rule: only misclassified points trigger updates, with no weight decay. In this variant you must find 5 successful learning rates (each reaching 100% accuracy) before the flag is revealed. The dataset is still linearly separable, but it is less toy-like and the separation is less obvious. Dial in a rate, trigger a run, and the interface animates each step.
> Instance: `http://chatelaine.cylabacademy.net:24891/`

---

## Analisis & Konvergensi Perceptron
Teorema Konvergensi Perceptron (*Novikoff, 1962*) menyatakan bahwa jika suatu kumpulan data bersifat *linearly separable* (terdapat vektor bobot optimal $w^*$ yang memisahkan seluruh titik dengan margin $\gamma > 0$), maka algoritma perceptron dijamin akan konvergen dalam jumlah iterasi berhingga:
$$k \le \frac{R^2}{\gamma^2}$$
di mana $R = \max_i \|x_i\|$.

Namun, dalam skenario dengan batasan langkah maksimum ($maxSteps = 16$), pemilihan learning rate ($\eta$) menentukan apakah bobot dapat mencapai wilayah separasi sebelum iterasi habis. Nilai $\eta$ yang terlalu kecil tidak cukup menggeser hyperplane, sedangkan nilai yang terlalu besar dapat menyebabkan osilasi bolak-balik melompati margin optimal.

---

## Solusi Eksploitasi
Tantangan mewajibkan penemuan 5 learning rate berbeda yang masing-masing menghasilkan akurasi $100\%$ dalam sesi HTTP yang sama (`successCount = 5`).

Dibuat script otomasi berbasis `urllib.request` dengan `http.cookiejar.CookieJar` untuk melakukan sweep nilai $\eta \in [0.02, 5.0]$:

```python
import urllib.request
import json
import http.cookiejar

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# Inisialisasi sesi
opener.open('http://chatelaine.cylabacademy.net:24891/config.json')

successful_lrs = []
for lr_int in range(2, 500, 2):
    lr = round(lr_int * 0.01, 2)
    req = urllib.request.Request(
        'http://chatelaine.cylabacademy.net:24891/train',
        data=json.dumps({'learningRate': lr}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    with opener.open(req) as resp:
        data = json.loads(resp.read().decode())
        if data.get('accuracy') == 1.0:
            successful_lrs.append(lr)
            if data.get('flag'):
                print("Flag:", data.get('flag'))
                break
```

---

## Hasil & Verifikasi
- **Learning Rates Konvergen:** $\eta \in \{0.12, 0.16, 0.18, 0.24, 0.26\}$
- **Flag yang Diterima:** `academy{perceptron_classic_2_alpha_5rates_13e2875c}`
- **Submisi:** Validated by CyLab API (`solved_by_user = true`).
