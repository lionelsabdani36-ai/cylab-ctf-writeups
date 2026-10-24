# Writeup: Perceptron Train Classic 1 (Challenge ID: 778)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{perceptron_classic_5rates_a95545ef}`

---

## Deskripsi Tantangan
> Watch a perceptron learn in real time using the classic update rule: only misclassified points trigger updates, with no weight decay. In this variant you must find 5 successful learning rates (each reaching 100% accuracy) before the flag is revealed. Dial in a rate, trigger a run, and the interface animates each step.
> Instance: `http://chatelaine.cylabacademy.net:36775/`

---

## Analisis & Teori Konvergensi
Tantangan ini menguji pemahaman praktis Teorema Konvergensi Perceptron (*Novikoff's Theorem*). Dataset terdiri atas 8 titik data dua dimensi:
- Titik Kelas 0: `(-4, -2)`, `(-3, -4)`, `(-2, -3)`, `(-3, -1)` (kuadran ketiga)
- Titik Kelas 1: `(3, 4)`, `(4, 2)`, `(2, 3)`, `(3, 1)` (kuadran pertama)

Karena terdapat margin geometris $\gamma > 0$ yang cukup lebar di antara kedua klaster titik pada sumbu diagonal, data bersifat *linearly separable*.

Model diinisialisasi dengan bobot awal $w = [1.0, -1.0]$ dan bias $b = 0.0$ (akurasi awal $50\%$). Server membatasi jumlah pembaruan bobot maksimal 16 langkah (`maxSteps = 16`). Agar kriteria keberhasilan tercapai, pengguna harus menemukan 5 learning rate ($\eta$) yang berbeda dalam satu sesi HTTP aktif (`successTarget = 5`) hingga akurasi mencapai $100\%$.

---

## Solusi Eksploitasi
Eksploitasi dilakukan dengan memelihara sesi cookie HTTP (`CookieJar`) agar status `successCount` terakumulasi secara persisten pada backend Express/Node.js instance.

Prosedur sweep learning rate:
1. Mulai dari nilai $\eta = 0.02$ dengan penambahan step $0.02$.
2. Kirim payload JSON `{"learningRate": lr}` ke endpoint `/train`.
3. Evaluasi apakah `accuracy == 1.0`. Jika ya, backend akan menginkrementasi counter `successCount`.
4. Setelah 5 learning rate berhasil diverifikasi berturut-turut, server merilis flag resmi.

### Script Solver
```python
import urllib.request
import json
import http.cookiejar

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# Inisialisasi sesi
opener.open('http://chatelaine.cylabacademy.net:36775/config.json')

successes = []
for lr_int in range(2, 2000, 2):
    lr = round(lr_int * 0.01, 2)
    req = urllib.request.Request(
        'http://chatelaine.cylabacademy.net:36775/train',
        data=json.dumps({'learningRate': lr}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    with opener.open(req) as resp:
        data = json.loads(resp.read().decode())
        if data.get('accuracy') == 1.0:
            successes.append((lr, data.get('successCount')))
            if data.get('flag'):
                print("FLAG:", data.get('flag'))
                break
```

---

## Hasil & Verifikasi
- **Learning Rates Konvergen:** $\eta \in \{0.02, 0.04, 0.06, 0.08, 0.10\}$
- **Flag:** `academy{perceptron_classic_5rates_a95545ef}`
- **Submisi:** Terverifikasi sukses via endpoint `/api/submissions/` CyLab Security Academy.
