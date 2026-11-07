# Writeup: Perceptron Play 1D Alpha (Challenge ID: 773)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / 1D Perceptron Linear Decision Boundary
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{0n3_d_thr35h0ld_0291d6fb}`
- **Native Flag:** `picoCTF{0n3_d_thr35h0ld_0291d6fb}`

---

## Problem Statement & Scope

Tantangan `Perceptron Play 1D Alpha` memperkenalkan fondasi pemodelan klasifikasi biner berbasis perceptron linear pada garis bilangan 1 dimensi ($\mathbb{R}$):
> *"Play with the weight and bias of a 1D perceptron on a number line. Adjust the parameters until every labeled point is classified correctly and you will earn the flag."*

Tujuan kurikulum bimbingan teknis persiapan lomba LKS Cyber Security Nasional dan kepatuhan standar **NIST SP 800-115 Section 4.2** (*Algorithm and Logic Validation Assessment*):
1. Mengaudit model klasifikasi matematis sederhana yang berinteraksi melalui soket TCP interaktif.
2. Mengevaluasi sifat keterpisahan linier (*linear separability*) dari himpunan titik berlabel dalam ruang satu dimensi.
3. Menghitung ambang batas analitis (*decision threshold*) optimal guna mempartisi ruang masukan secara deterministik.
4. Memvalidasi bahwa penetapan bobot ($w$) dan bias ($b$) melalui perintah `SET w b` dan eksekusi `CHECK` menghasilkan akurasi 100% dan menerbitkan token validasi dari platform.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Model Aktivasi Heaviside 1 Dimensi
Perceptron satu dimensi menerima masukan skalar kontinu atau diskret $x \in \mathbb{R}$ dan menerapkan kombinasi linier terbobot sebelum dilewatkan ke fungsi tangga satuan Heaviside (*Heaviside step activation*):
$$z = w \cdot x + b$$
$$f(x) = \begin{cases} 1 & \text{jika } w \cdot x + b \ge 0 \quad (\text{kelas } \mathcal{C}_1) \\ 0 & \text{jika } w \cdot x + b < 0 \quad (\text{kelas } \mathcal{C}_0) \end{cases}$$

Batas keputusan (*decision boundary*) terjadi tepat pada titik singular di mana nilai kombinasi linier bernilai nol:
$$w \cdot x^* + b = 0 \implies x^* = -\frac{b}{w}$$
Untuk bobot bernilai positif ($w > 0$), setiap masukan $x \ge x^*$ dipetakan ke kelas $\mathcal{C}_1$, sedangkan setiap masukan $x < x^*$ dipetakan ke kelas $\mathcal{C}_0$.

### 2. Sifat Keterpisahan Linier & Ketiadaan Regularisasi (CWE-684 / CWE-203)
Dataset yang disediakan oleh sistem terdiri atas dua himpunan diskret:
- Titik kelas $\mathcal{C}_0$: $X_0 = \{-4, -2, 0\}$
- Titik kelas $\mathcal{C}_1$: $X_1 = \{2, 3, 4\}$

Kondisi keterpisahan linier terpenuhi secara mutlak karena:
$$\max(X_0) = 0 < \min(X_1) = 2$$
Interval pemisahan tanpa galat (*margin zone*) berada pada selang terbuka:
$$x^* \in (0, 2)$$
Karena model layanan menerima parameter bebas tanpa menerapkan batasan margin minimum (*margin enforcement*) atau regularisasi penalti bobot ($L_1 / L_2$ norm), penyerang/peserta dapat langsung menetapkan nilai integer terkecil:
$$w = 1.0, \quad b = -1.0 \implies x^* = -\frac{-1.0}{1.0} = 1.0$$
Titik ambang $x^* = 1.0$ membelah interval $[0, 2]$ secara simetris, menghasilkan akurasi empiris 100% tanpa memerlukan iterasi *Perceptron Learning Algorithm* (PLA) atau *Stochastic Gradient Descent* (SGD).

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Pemetaan Distribusi Dataset Terlabel
Inspeksi data titik pada garis bilangan menunjukkan:
- Nilai maksimum untuk titik kelas 0 adalah $x = 0$.
- Nilai minimum untuk titik kelas 1 adalah $x = 2$.
- Jarak antar-kelas (*class margin*): $\Delta x = 2 - 0 = 2$.

### Langkah 2: Penentuan Parameter Bobot & Bias
Ambang batas tengah optimal:
$$x^* = \frac{0 + 2}{2} = 1.0$$
Menetapkan $w = 1$, maka:
$$b = -w \cdot x^* = -(1)(1.0) = -1$$

Evaluasi analitis terhadap seluruh titik:
1. Titik $x = -4$: $1(-4) - 1 = -5 < 0 \rightarrow \hat{y} = 0$ (Target: 0, **VALID**)
2. Titik $x = -2$: $1(-2) - 1 = -3 < 0 \rightarrow \hat{y} = 0$ (Target: 0, **VALID**)
3. Titik $x =  0$: $1( 0) - 1 = -1 < 0 \rightarrow \hat{y} = 0$ (Target: 0, **VALID**)
4. Titik $x =  2$: $1( 2) - 1 = +1 \ge 0 \rightarrow \hat{y} = 1$ (Target: 1, **VALID**)
5. Titik $x =  3$: $1( 3) - 1 = +2 \ge 0 \rightarrow \hat{y} = 1$ (Target: 1, **VALID**)
6. Titik $x =  4$: $1( 4) - 1 = +3 \ge 0 \rightarrow \hat{y} = 1$ (Target: 1, **VALID**)

Akurasi klasifikasi: $\frac{6}{6} = 100\%$.

### Langkah 3: Pengiriman Perintah & Ekstraksi Token
Melalui koneksi interaktif TCP:
```text
SET 1 -1
CHECK
```
Respons sistem:
```text
All points classified correctly! Accuracy: 100%
Flag: academy{0n3_d_thr35h0ld_0291d6fb}
```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{0n3_d_thr35h0ld_0291d6fb}`
- **Flag Komunitas:** `CTF{0n3_d_thr35h0ld_0291d6fb}`
- **Skrip Solver Reproduktif:** `scripts/solve_773_perceptron_play_1d_alpha.py`
- **Hasil Verifikasi Live API:** Validated via REST endpoint `POST /api/submissions/` (HTTP 201 Created, `correct: true`, user: `1072359`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi LKS Cyber Security (AI Model & Decision Boundary Auditing):**
   - Peserta memahami bagaimana arsitektur model linier mengevaluasi data numerik dan bagaimana batas keputusan (*hyperplane*) mempartisi ruang masukan.
   - Menguasai verifikasi integritas klasifikasi dan identifikasi celah inferensi pada model berbasis aturan linier.
2. **Mitigasi Defensif (Hardening & Robustness):**
   - **Soft Decision Boundaries (Sigmoid / Softmax):** Hindari penggunaan Heaviside step diskret mentah yang rentan terhadap eksploitasi ambang batas tajam; gunakan fungsi probabilistik dengan suhu terkalibrasi (*temperature scaling*).
   - **Margin Regularization (Support Vector Machines):** Terapkan optimasi berbasis margin maksimum dengan penalti soft-margin ($C$-parameter) guna mencegah pemilihan bidang pembatas yang terlalu rapuh terhadap pergeseran distribusi data masukan.
   - **Input Quantization & Rate Limiting:** Batasi kueri perubahan parameter model interaktif untuk mencegah enumerasi batas keputusan oleh entitas yang tidak sah.
