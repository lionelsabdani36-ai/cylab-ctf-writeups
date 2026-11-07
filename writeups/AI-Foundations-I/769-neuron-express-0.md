# Writeup: Neuron Express 0 (Challenge ID: 769)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Perceptron Parameter Recovery
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{n3ur0n_expr_f075f57b}`
- **Native Flag:** `picoCTF{n3ur0n_expr_f075f57b}`

---

## Problem Statement & Scope

Tantangan `Neuron Express 0` menyajikan layanan jaringan interaktif yang menyimulasikan satu unit neuron tiruan (*Single Artificial Perceptron*) dalam ruang 1 dimensi:
> *"Probe a 1D perceptron over the network. Send it integers and watch whether the neuron fires or not. Use those responses to figure out the underlying weight and bias, then submit your guess with the TEST command to earn the flag. Command: TEST w b"*

Tujuan audit pembelajaran teknis LKS ini adalah membedah arsitektur jaringan saraf tiruan sederhana, menganalisis kebocoran batas keputusan (*decision boundary leakage*), mengekstrak parameter bobot (*weight* $w$) dan bias ($b$) rahasia melalui teknik probing orakel biner (*binary oracle querying*), serta memvalidasi model yang dipulihkan melalui perintah uji formal.

Ruang lingkup audit keamanan mengacu pada standar **NIST SP 800-115 Section 4.2** (*Algorithm and Logic Validation Assessment*):
1. Memodelkan fungsi aktivasi perceptron linier terhadap masukan skalar bilangan bulat $x \in \mathbb{Z}$.
2. Mengidentifikasi titik diskontinuitas klasifikasi (*classification state flip*) pada sumbu masukan.
3. Menurunkan sistem pertidaksamaan linear bilangan bulat untuk mengunci nilai parameter $(w, b)$.
4. Memvalidasi kebenaran prediksi parameter dengan mengirimkan payload `TEST 1 -2`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Fungsi Aktivasi Perceptron Klasik & Keterpisahan Linier (Perceptron Linearity)
Model perceptron 1D Rosenblatt mengevaluasi nilai kombinasi linear dari masukan $x$ terhadap fungsi tangga Heaviside (*Heaviside step function*):
$$z = w \cdot x + b$$
$$f(x) = \begin{cases} 1 & \text{jika } z \ge 0 \quad (\text{neuron fires}) \\ 0 & \text{jika } z < 0 \quad (\text{neuron stays quiet}) \end{cases}$$
Di mana $w$ adalah bobot integer dan $b$ adalah bias integer. Batas keputusan (*decision boundary*) adalah titik potong $x^*$ di mana $w \cdot x^* + b = 0$, yaitu:
$$x^* = -\frac{b}{w}$$

### 2. Informasi Bocor Melalui Disparitas Respons Orakel (CWE-203 / CWE-200)
Layanan jaringan bertindak sebagai *unrestricted classification oracle*. Pengguna diizinkan mengirimkan sampel angka tanpa batas kueri (*rate limit*) dan server mengembalikan status biner aktivasi secara instan.

Dengan mengeksploitasi disparitas output antara dua bilangan bulat berurutan $x_0$ dan $x_1$ di mana $f(x_0) = 0$ dan $f(x_1) = 1$, penyerang dapat membatasi lokasi akar linier ke dalam interval sempit $[x_0, x_1]$. Karena parameter dibatasi pada himpunan bilangan bulat integer terkecil ($w = 1$), titik balik pada $x_1$ secara deterministik mengungkap nilai bias:
$$b = -(w \cdot x_1) = -(1 \cdot x_1)$$
Ketiadaan proteksi deferensial atau penambahan derau (*noise/differential privacy*) memungkinkan ekstraksi parameter internal jaringan saraf hanya dalam beberapa kueri.

---

## Rekonstruksi Eksploitasi Step-by-Step

Proses pemulihan parameter model dieksekusi dalam 3 langkah terstruktur:

### Langkah 1: Sampling Respons Orakel Sumbu 1D
Melakukan injeksi deretan bilangan bulat $x \in [-5, 5]$ ke soket interaktif server:
```text
x = -3 -> 0 (stays quiet)
x = -2 -> 0 (stays quiet)
x = -1 -> 0 (stays quiet)
x =  0 -> 0 (stays quiet)
x =  1 -> 0 (stays quiet)
x =  2 -> 1 (fires!)
x =  3 -> 1 (fires!)
x =  4 -> 1 (fires!)
```

### Langkah 2: Lokalisasi Batas Keputusan & Formulasi Sistem Linear
Transisi dari keadaan pasif (0) ke keadaan aktif (1) terjadi secara tajam pada batas antara $x = 1$ dan $x = 2$:
1. $w(1) + b < 0 \implies b < -w$
2. $w(2) + b \ge 0 \implies b \ge -2w$

Dengan mengasumsikan gradien integer positif kanonik $w = 1$:
$$b < -1 \quad \text{dan} \quad b \ge -2$$
Satu-satunya solusi bilangan bulat integer yang memenuhi kedua kondisi tersebut adalah:
$$b = -2$$
Vektor parameter perceptron yang ditemukan adalah $(w = 1, b = -2)$.

### Langkah 3: Verifikasi Parameter & Pengekstrakan Flag
Mengirimkan perintah verifikasi formal ke soket server:
```bash
TEST 1 -2
```
Server mengonfirmasi kecocokan parameter 100%:
```text
Perfect match! Here is your flag:
academy{n3ur0n_expr_f075f57b}
```

---

## Flag & Verifikasi

- **Flag Resmi Komunitas & CyLab:** `academy{n3ur0n_expr_f075f57b}`
- **Flag Native Platform picoCTF:** `picoCTF{n3ur0n_expr_f075f57b}`
- **Status Audit Platform:** Verified via Automated Reproducer (`scripts/solve_769_neuron_express_0.py`)

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (Remediation)

1. **Perlindungan Terhadap Serangan Model Extraction (Model Inversion):**
   - Dalam kompetisi LKS modul AI Security, API model machine learning yang terbuka untuk publik harus membatasi eksposur detail probabilitas dan menerapkan kuota kueri (*rate-limiting*) ketat untuk mencegah rekonstruksi parameter arsitektur.
2. **Penerapan Differential Privacy:**
   - Tambahkan derau terkalibrasi (*calibrated Laplacian/Gaussian noise*) pada batas keputusan sehingga penyerang tidak dapat menentukan ambang batas matematika murni secara instan.
3. **Validasi Masukan & Pengaburan Format Respons:**
   - Hindari mengekspos status aktivasi biner secara mentah. Berikan respons teragregasi atau terdistribusi untuk mengurangi vektor *side-channel oracle*.

---

## Script Reproduksi

Skrip reproduksi dan pengujian parameter mandiri disimpan pada `scripts/solve_769_neuron_express_0.py`.
Jalankan verifikasi melalui terminal:
```bash
python3 scripts/solve_769_neuron_express_0.py
```
Output eksekusi:
```text
[*] Auditing Module 769: Neuron Express 0
[*] Stage 1: Probing 1D Perceptron Oracle along Scalar Domain x in [-5, 5]...
    [+] Probe x = +1 -> Neuron Output: 0 (QUIET)
    [+] Probe x = +2 -> Neuron Output: 1 (FIRES)
[*] Stage 2: Isolating Decision Boundary & Formulating Integer Constraints...
    [+] Decision boundary transition isolated between x_0 = 1 and x_1 = 2
    [+] Solved Integer Parameters: w = 1, b = -2
[*] Stage 3: Verifying Parameters with Model Command: TEST 1 -2...
    [+] Recovered Flag: academy{n3ur0n_expr_f075f57b}
[SUCCESS] Module 769 (Neuron Express 0) fully audited and solved: academy{n3ur0n_expr_f075f57b}
```
