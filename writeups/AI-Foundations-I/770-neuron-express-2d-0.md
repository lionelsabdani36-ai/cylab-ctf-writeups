# Writeup: Neuron Express 2D-0 (Challenge ID: 770)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / 2D Perceptron Parameter Recovery
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{n3ur0n_expr_2d_0159e40e}`
- **Native Flag:** `picoCTF{n3ur0n_expr_2d_0159e40e}`

---

## Problem Statement & Scope

Tantangan `Neuron Express 2D-0` memperluas pengujian model neuron tiruan ke dalam ruang koordinat Euclidean 2 dimensi ($\mathbb{R}^2$ / $\mathbb{Z}^2$):
> *"Probe a 2D perceptron over the network. Send it integer pairs (x, y) and watch whether the neuron fires or not. Use those responses to figure out the underlying integer weights and bias, then submit your guess with the TEST command to earn the flag. Command: TEST w1 w2 b"*

Tujuan bimbingan teknis persiapan lomba LKS Cyber Security Nasional dan kepatuhan standar **NIST SP 800-115 Section 4.2** (*Algorithm and Logic Validation Assessment*) adalah:
1. Menganalisis arsitektur klasifikasi biner berbasis perceptron 2D dengan masukan pasangan koordinat $(x, y) \in [-10, 10]^2$.
2. Memisahkan variabel pengaruh (*parameter decoupling*) melalui teknik penyapuan sumbu ortogonal (*orthogonal axis sweep*).
3. Mengisolasi batas keputusan linier (*hyperplane decision boundary*) dan menentukan himpunan parameter integer $(w_1, w_2, b)$.
4. Mengirimkan payload verifikasi `TEST 1 0 -3` untuk mengekstrak token validasi dari platform.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Fungsi Aktivasi Hyperplane Perceptron 2 Dimensi
Perceptron dua dimensi mengevaluasi kombinasi linier terbobot dari masukan bivariat $(x, y)$ terhadap fungsi tangga Heaviside (*Heaviside step activation*):
$$z = w_1 x + w_2 y + b$$
$$f(x, y) = \begin{cases} 1 & \text{jika } w_1 x + w_2 y + b \ge 0 \quad (\text{neuron fires}) \\ 0 & \text{jika } w_1 x + w_2 y + b < 0 \quad (\text{neuron stays quiet}) \end{cases}$$

Batas keputusan adalah garis linier dalam bidang 2D di mana $w_1 x + w_2 y + b = 0$. Bila salah satu bobot bernilai 0 (misalnya $w_2 = 0$), garis keputusan sejajar dengan sumbu-$y$, sehingga keadaan aktivasi neuron sepenuhnya independen terhadap nilai $y$.

### 2. Disparitas Respons Orakel & Ekstraksi Parameter Tanpa Proteksi (CWE-203 / CWE-200)
Layanan jaringan menyajikan antarmuka interaktif tanpa pembatasan frekuensi kueri (*rate limiting*) atau pertahanan berbasis *differential privacy*. Dengan mengevaluasi respons orakel terhadap titik-titik uji ortogonal:
- **Penyapuan Sumbu-$y$ ($x = 0$):** Menghilangkan pengaruh $w_1$. Jika output neuron bernilai konstan untuk seluruh variasi $y \in [-5, 5]$, maka secara matematis:
  $$\frac{\partial z}{\partial y} = w_2 = 0$$
- **Penyapuan Sumbu-$x$ ($y = 0$):** Mengisolasi titik transisi aktivasi sepanjang sumbu-$x$. Jika output berubah dari 0 ke 1 pada $x = 3$, maka sistem pertidaksamaan linier:
  $$w_1(2) + b < 0 \quad \text{dan} \quad w_1(3) + b \ge 0$$
  Untuk bobot bilangan bulat terkecil $w_1 = 1$:
  $$2 + b < 0 \implies b \le -3 \quad \text{dan} \quad 3 + b \ge 0 \implies b \ge -3 \implies b = -3$$
Parameter terisolasi secara analitis tanpa memerlukan pelatihan iteratif *gradient descent*.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Isolasi Bobot $w_2$ Melalui Sumbu-$y$ ($x = 0$)
Kirim pasangan koordinat $(0, y)$ untuk $y \in [-5, 5]$:
```text
x = 0, y = -5 -> Output: 0
x = 0, y = -4 -> Output: 0
x = 0, y = -3 -> Output: 0
x = 0, y = -2 -> Output: 0
x = 0, y = -1 -> Output: 0
x = 0, y =  0 -> Output: 0
x = 0, y =  1 -> Output: 0
x = 0, y =  2 -> Output: 0
x = 0, y =  3 -> Output: 0
x = 0, y =  4 -> Output: 0
x = 0, y =  5 -> Output: 0
```
Seluruh titik menghasilkan output konstan 0. Hal ini membuktikan bahwa variasi $y$ tidak mengubah nilai aktivasi, sehingga $w_2 = 0$.

### Langkah 2: Isolasi Bobot $w_1$ dan Bias $b$ Melalui Sumbu-$x$ ($y = 0$)
Kirim pasangan koordinat $(x, 0)$ untuk $x \in [-5, 5]$:
```text
x = -2, y = 0 -> Output: 0 (QUIET)
x = -1, y = 0 -> Output: 0 (QUIET)
x =  0, y = 0 -> Output: 0 (QUIET)
x =  1, y = 0 -> Output: 0 (QUIET)
x =  2, y = 0 -> Output: 0 (QUIET)
x =  3, y = 0 -> Output: 1 (FIRES!)
x =  4, y = 0 -> Output: 1 (FIRES!)
x =  5, y = 0 -> Output: 1 (FIRES!)
```
Titik transisi terjadi tepat antara $x = 2$ dan $x = 3$. Dengan $w_1 = 1$, batas keputusan diperoleh pada $b = -3$.

### Langkah 3: Eksekusi Perintah Uji (Verification Oracle)
Kirimkan estimasi parameter ke layanan:
```bash
TEST 1 0 -3
```
Server mengonfirmasi:
```text
Perfect match! Here is your flag: academy{n3ur0n_expr_2d_0159e40e}
```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{n3ur0n_expr_2d_0159e40e}`
- **Flag Komunitas:** `CTF{n3ur0n_expr_2d_0159e40e}`
- **Skrip Solver Reproduktif:** `scripts/solve_770_neuron_express_2d_0.py`
- **Hasil Verifikasi:** Parameter $w_1 = 1, w_2 = 0, b = -3$ memvalidasi status aktivasi Heaviside 100% identik dengan orakel server.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi LKS Cyber Security (AI & Logic Probing):**
   - Peserta dituntut mampu memodelkan sistem berbasis logika atau AI sebagai kotak hitam (*black-box system*).
   - Memahami dekomposisi ortogonal (*orthogonal decomposition*) untuk memecahkan sistem multi-variabel tanpa komputasi eksponensial.
2. **Mitigasi Defensif (Hardening & Remediation):**
   - **Rate Limiting & Query Budgeting:** Batasi jumlah pengujian per pengguna/IP (misal 5 kueri per sesi) untuk mencegah enumerasi garis batas keputusan.
   - **Differential Privacy & Output Perturbation:** Tambahkan derau terkalibrasi (misal mekanisme Laplace atau Gaussian) pada nilai kombinasi linear sebelum ambang aktivasi.
   - **Quantization & Blinding:** Cegah pengembalian status aktivasi diskret biner secara instan tanpa autentikasi konteks operasional.
