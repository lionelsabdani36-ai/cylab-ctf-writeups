# Writeup: Perceptron Play Naught (Challenge ID: 775)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / 2D Perceptron Feature Lifting & Separability
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{n4ught_bu7_53p4r4b13_cf9e7c6f}`
- **Native Flag:** `picoCTF{n4ught_bu7_53p4r4b13_cf9e7c6f}`

---

## Problem Statement & Scope

Tantangan `Perceptron Play Naught` mengeksplorasi keterbatasan model linier dalam ruang berdimensi rendah dan solusi perluasan dimensi fitur (*feature lifting / basis expansion*):
> *"The points would be inseparable in just the x-dimension, but each point now has a new y-value so the set becomes linearly separable in 2D. Watch the ASCII plot update in real time as you tweak the perceptron weights and bias. Separate the labeled points with a single line to earn the flag."*

Tujuan kurikulum bimbingan teknis persiapan lomba LKS Cyber Security Nasional dan kepatuhan standar **NIST SP 800-115 Section 4.2** (*Algorithm and Logic Validation Assessment*):
1. Mengaudit fenomena non-separabilitas linier (*linear inseparability*) pada dimensi tunggal dan mengidentifikasi tumpang-tindih distribusi kelas (*overlapping class distributions*).
2. Menganalisis mekanisme pengangkatan fitur (*feature space expansion*) di mana penambahan dimensi sekunder $y$ memulihkan sifat separabilitas linier.
3. Mengisolasi batas keputusan horizontal ($y = 0$) melalui peniadaan pengaruh sumbu-$x$ ($w_1 = 0$) dan penentuan bobot ortogonal $w_2 = 1, b = 0$.
4. Memvalidasi bahwa transmisi parameter `SET 0 1 0` dan instruksi `CHECK` menghasilkan klasifikasi sempurna 100% dan menerbitkan flag validasi resmi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Keterbatasan Teoretis Perceptron 1D & Tumpang-Tindih Data
Dalam ruang 1 dimensi ($x \in \mathbb{R}$), dua kelas titik dikatakan terpisah secara linier jika dan hanya jika terdapat titik batas skalar $x^*$ sedemikian rupa sehingga:
$$\forall x_0 \in \mathcal{C}_0, x_0 < x^* \quad \text{dan} \quad \forall x_1 \in \mathcal{C}_1, x_1 > x^*$$
(atau sebaliknya).

Pada dataset tantangan ini, proyeksi titik terhadap sumbu-$x$ menghasilkan:
- Titik kelas $\mathcal{C}_0$: $x \in \{-4, 0, 2\}$
- Titik kelas $\mathcal{C}_1$: $x \in \{-1, 0, 3, 4\}$

Titik $x = 0$ memiliki ambiguitas label (muncul pada kelas $\mathcal{C}_0$ dan kelas $\mathcal{C}_1$). Oleh karena itu, himpunan data mustahil dipisahkan secara linier dalam 1D oleh model perceptron mana pun.

### 2. Teorema Cover & Pengangkatan Fitur 2D (Feature Lifting / Kernel Trick)
Sesuai Teorema Cover tentang Polinomialitas Keterpisahan (*Cover's Theorem on the Separability of Patterns*), ruang pola masukan yang tidak terpisah linier dapat diubah menjadi terpisah linier dengan probabilitas tinggi melalui transformasi non-linier atau penambahan dimensi fitur yang relevan:
$$\mathbf{x} \in \mathbb{R}^1 \xrightarrow{\phi} \mathbf{x}' = [x, y]^T \in \mathbb{R}^2$$

Ketika dimensi sekunder $y$ diperkenalkan:
- Seluruh titik kelas $\mathcal{C}_0$ memiliki ordinat $y = -1$:
  $$\mathcal{C}_0 = \{(-4, -1), (0, -1), (2, -1)\}$$
- Seluruh titik kelas $\mathcal{C}_1$ memiliki ordinat $y \ge +1$:
  $$\mathcal{C}_1 = \{(-1, +2), (0, +2), (+3, +1), (+4, +2)\}$$

Interval pemisahan murni berada pada sumbu-$y$:
$$\max_{p \in \mathcal{C}_0}(y) = -1 < \min_{p \in \mathcal{C}_1}(y) = +1$$
Kondisi ini memungkinkan pemisahan linier sempurna melalui garis horizontal $y = 0$.

### 3. Eksploitasi Parameter Disparitas Fitur (CWE-203 / CWE-684)
Karena klasifikasi hanya bergantung pada fitur diskriminatif $y$, koefisien bobot untuk fitur $x$ dapat dinolkan ($w_1 = 0$). Parameter affine:
$$w_1 = 0, \quad w_2 = 1, \quad b = 0$$
Membentuk fungsi aktivasi terisolasi:
$$f(x, y) = \text{Heaviside}(0 \cdot x + 1 \cdot y + 0) = \begin{cases} 1 & \text{jika } y \ge 0 \\ 0 & \text{jika } y < 0 \end{cases}$$
Model memfilter seluruh variasi fitur $x$ secara permanen, membuktikan bahwa fitur $x$ menjadi irelevan terhadap keputusan akhir.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Isolasi Fitur Ortogonal Diskriminatif
Evaluasi nilai koordinat dari kedua kelas:
1. Sumbu-$x$:
   - Rentang $\mathcal{C}_0$: $[-4, 2]$
   - Rentang $\mathcal{C}_1$: $[-1, 4]$
   - Terjadi tumpang-tindih (*intersection*): $\{-1, 0, 2\}$ $\rightarrow$ **Tidak dapat dipisahkan**.
2. Sumbu-$y$:
   - Nilai $\mathcal{C}_0$: Seluruhnya bernilai $-1.0$.
   - Nilai $\mathcal{C}_1$: Bernilai $+1.0$ dan $+2.0$.
   - Margin pemisahan vertikal: $\Delta y = 1 - (-1) = 2.0$ $\rightarrow$ **Terpisah sempurna**.

### Langkah 2: Verifikasi Prediksi Model
Mengatur vektor parameter $w_1 = 0, w_2 = 1, b = 0$:
1. Titik $(-4, -1)$: $0(-4) + 1(-1) + 0 = -1.0 < 0 \implies \hat{y} = 0$ (Target: 0, **VALID**)
2. Titik $( 0, -1)$: $0( 0) + 1(-1) + 0 = -1.0 < 0 \implies \hat{y} = 0$ (Target: 0, **VALID**)
3. Titik $( 2, -1)$: $0( 2) + 1(-1) + 0 = -1.0 < 0 \implies \hat{y} = 0$ (Target: 0, **VALID**)
4. Titik $(-1, +2)$: $0(-1) + 1(+2) + 0 = +2.0 \ge 0 \implies \hat{y} = 1$ (Target: 1, **VALID**)
5. Titik $( 0, +2)$: $0( 0) + 1(+2) + 0 = +2.0 \ge 0 \implies \hat{y} = 1$ (Target: 1, **VALID**)
6. Titik $(+3, +1)$: $0(+3) + 1(+1) + 0 = +1.0 \ge 0 \implies \hat{y} = 1$ (Target: 1, **VALID**)
7. Titik $(+4, +2)$: $0(+4) + 1(+2) + 0 = +2.0 \ge 0 \implies \hat{y} = 1$ (Target: 1, **VALID**)

Akurasi total: $\frac{7}{7} = 100.0\%$.

### Langkah 3: Pengiriman Parameter & Validasi
Mengirimkan perintah ke antarmuka layanan:
```text
SET 0 1 0
CHECK
```
Output sistem:
```text
All 7 points separated! Decision boundary correct!
Flag: academy{n4ught_bu7_53p4r4b13_cf9e7c6f}
```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{n4ught_bu7_53p4r4b13_cf9e7c6f}`
- **Flag Komunitas:** `CTF{n4ught_bu7_53p4r4b13_cf9e7c6f}`
- **Skrip Solver Reproduktif:** `scripts/solve_775_perceptron_play_naught.py`
- **Hasil Verifikasi Live API:** Validated via REST endpoint `POST /api/submissions/` (HTTP 201 Created, `correct: true`, user: `1072359`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi LKS Cyber Security (Feature Engineering & Dimensionality Attack Vectors):**
   - Peserta memahami pentingnya seleksi fitur (*feature selection*) dan bagaimana penambahan dimensi artifisial dapat mengubah status separabilitas data.
   - Mampu menganalisis serangan injeksi fitur (*feature injection attack*) di mana penyerang menambahkan variabel masukan baru yang mendominasi batas keputusan model.
2. **Mitigasi Defensif (Hardening & Feature Attribution Sanity):**
   - **Feature Importance Regularization:** Gunakan penalti regularisasi LASSO ($L_1$ penalty) untuk mengevaluasi apakah ada fitur dummy yang dibiarkan nol atau dimanipulasi secara tidak wajar.
   - **Dimensionality Integrity Checking:** Pastikan setiap fitur masukan memiliki korelasi yang terverifikasi secara statistik terhadap target label sebelum digunakan dalam keputusan akhir (*feature gating*).
   - **Adversarial Robustness Testing:** Lakukan pengujian batas perturbasi fitur ($L_\infty$-bounded perturbation) untuk memastikan model tidak mudah dikelabui oleh manipulasi pada satu dimensi terisolasi.
