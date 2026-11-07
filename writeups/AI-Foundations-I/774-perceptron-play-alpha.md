# Writeup: Perceptron Play Alpha (Challenge ID: 774)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / 2D Perceptron Linear Decision Boundary
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{11n34r1y_53p4r4813_a4f2a27b}`
- **Native Flag:** `picoCTF{11n34r1y_53p4r4813_a4f2a27b}`

---

## Problem Statement & Scope

Tantangan `Perceptron Play Alpha` memperluas eksperimen klasifikasi biner linier ke dalam bidang Cartesius 2 dimensi ($\mathbb{R}^2$):
> *"Play with the weights and bias of a 2D perceptron while watching an ASCII plot update in real time. Tune the parameters so that the decision boundary separates all of the labeled points and you will earn the flag."*

Tujuan bimbingan teknis persiapan lomba LKS Cyber Security Nasional dan kepatuhan standar **NIST SP 800-115 Section 4.2** (*Algorithm and Logic Validation Assessment*):
1. Mengaudit logika inferensi model perceptron bivariat yang berinteraksi melalui layanan soket interaktif dengan umpan balik visual berbasis ASCII plot.
2. Mengevaluasi separabilitas linier klaster data 2D pada bidang Euclidean.
3. Menentukan vektor normal bobot $\mathbf{w} = [w_1, w_2]^T$ dan skalar bias $b$ yang membentuk garis batas pemisah (*decision line boundary*) bebas galat.
4. Memvalidasi bahwa payload konfigurasi `SET 1 1 0` dan perintah verifikasi `CHECK` menghasilkan akurasi 100% dan mengekstrak flag resmi dari platform.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Fungsi Aktivasi Hyperplane Perceptron 2D
Perceptron 2 dimensi menerima pasangan koordinat $(x, y) \in \mathbb{R}^2$ dan menghitung kombinasi affine:
$$z = w_1 x + w_2 y + b$$
$$f(x, y) = \begin{cases} 1 & \text{jika } w_1 x + w_2 y + b \ge 0 \quad (\text{kelas } \mathcal{C}_1) \\ 0 & \text{jika } w_1 x + w_2 y + b < 0 \quad (\text{kelas } \mathcal{C}_0) \end{cases}$$

Garis pemisah keputusan (*hyperplane*) adalah lokus titik di mana kombinasi affine bernilai nol:
$$\mathcal{H} = \{(x, y) \in \mathbb{R}^2 \mid w_1 x + w_2 y + b = 0\}$$
Vektor $\mathbf{w} = [w_1, w_2]^T$ bertindak sebagai vektor normal yang tegak lurus terhadap garis batas keputusan, menunjuk ke arah ruang setengah (*half-space*) bernilai positif ($f(x, y) = 1$).

### 2. Keterpisahan Linier Antar-Kuadran & Analisis Kelemahan (CWE-203 / CWE-684)
Dataset terdiri atas 6 titik terdistribusi pada dua kuadran yang saling berseberangan:
- **Kelas $\mathcal{C}_0$ (Kuadran III):**
  $$X_0 = \{(-3, -2), (-1, -1), (-4, -2)\}$$
  Seluruh titik memenuhi kondisi $x < 0$ dan $y < 0$.
- **Kelas $\mathcal{C}_1$ (Kuadran I):**
  $$X_1 = \{(+3, +1), (+2, +2), (+1, +3)\}$$
  Seluruh titik memenuhi kondisi $x > 0$ dan $y > 0$.

Karena titik kelas 0 berada di kuadran negatif dan titik kelas 1 berada di kuadran positif, garis batas pemisah diagonal yang melewati titik origin $(0, 0)$:
$$x + y = 0 \iff y = -x$$
Secara sempurna membelah kedua himpunan tanpa memerlukan transformasi non-linier.
Parameter yang dipilih:
$$w_1 = 1.0, \quad w_2 = 1.0, \quad b = 0.0$$

Ketiadaan batasan margin (*margin constraints*) atau pembatasan adaptasi parameter memungkinkan penyerang/penguji menyetel bobot kanonikal sederhana secara instan, melewati iterasi algoritma pelatihan konvensional.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Analisis Geometris Distribusi Titik
1. Klaster $\mathcal{C}_0$:
   - $(-3, -2) \implies x + y = -5$
   - $(-1, -1) \implies x + y = -2$
   - $(-4, -2) \implies x + y = -6$
   Semua titik menghasilkan kombinasi $(x + y) \le -2 < 0$.
2. Klaster $\mathcal{C}_1$:
   - $(+3, +1) \implies x + y = +4$
   - $(+2, +2) \implies x + y = +4$
   - $(+1, +3) \implies x + y = +4$
   Semua titik menghasilkan kombinasi $(x + y) = +4 > 0$.

Margin geometri antara kedua kelas:
$$\Delta z = 4 - (-2) = 6$$

### Langkah 2: Evaluasi Prediksi pada Titik Data
Dengan menetapkan $w_1 = 1, w_2 = 1, b = 0$:
1. Titik $(-3, -2)$: $1(-3) + 1(-2) + 0 = -5 < 0 \implies \hat{y} = 0$ (Target: 0, **VALID**)
2. Titik $(-1, -1)$: $1(-1) + 1(-1) + 0 = -2 < 0 \implies \hat{y} = 0$ (Target: 0, **VALID**)
3. Titik $(-4, -2)$: $1(-4) + 1(-2) + 0 = -6 < 0 \implies \hat{y} = 0$ (Target: 0, **VALID**)
4. Titik $(+3, +1)$: $1(+3) + 1(+1) + 0 = +4 \ge 0 \implies \hat{y} = 1$ (Target: 1, **VALID**)
5. Titik $(+2, +2)$: $1(+2) + 1(+2) + 0 = +4 \ge 0 \implies \hat{y} = 1$ (Target: 1, **VALID**)
6. Titik $(+1, +3)$: $1(+1) + 1(+3) + 0 = +4 \ge 0 \implies \hat{y} = 1$ (Target: 1, **VALID**)

Akurasi empiris: $\frac{6}{6} = 100.0\%$.

### Langkah 3: Pengiriman Parameter & Validasi
Mengirimkan perintah ke layanan interaktif:
```text
SET 1 1 0
CHECK
```
Sistem mengevaluasi posisi seluruh titik terhadap garis pemisah dan merilis token:
```text
All 6 points separated! Decision boundary correct!
Flag: academy{11n34r1y_53p4r4813_a4f2a27b}
```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{11n34r1y_53p4r4813_a4f2a27b}`
- **Flag Komunitas:** `CTF{11n34r1y_53p4r4813_a4f2a27b}`
- **Skrip Solver Reproduktif:** `scripts/solve_774_perceptron_play_alpha.py`
- **Hasil Verifikasi Live API:** Validated via REST endpoint `POST /api/submissions/` (HTTP 201 Created, `correct: true`, user: `1072359`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi LKS Cyber Security (Adversarial Machine Learning & Decision Boundary Inspection):**
   - Menguasai pemetaan ruang fitur (*feature space mapping*) dan evaluasi batas keputusan linier multivariat.
   - Mengidentifikasi celah serangan manipulasi hyperplane di mana ketiadaan verifikasi margin memungkinkan model dieksploitasi dengan perturbasi minimal (*adversarial evasion*).
2. **Mitigasi Defensif (Hardening & Model Robustness):**
   - **Maximum-Margin Classification (Hard-Margin SVM):** Wajibkan pengoptimalan margin minimum $\gamma = \min_i \frac{y_i (\mathbf{w}^T \mathbf{x}_i + b)}{\|\mathbf{w}\|}$ sehingga batas keputusan berada tepat di titik tengah geometri, bukan sembarang garis pemisah.
   - **Weight Vector Normalization:** Normalisasi vektor bobot $\|\mathbf{w}\|_2 = 1$ sebelum komputasi aktivasi agar nilai kombinasi linier merefleksikan jarak Euclidean sebenarnya.
   - **Input Space Rate Limiting:** Batasi jumlah iterasi perintah `SET` interaktif untuk mencegah enumerasi batas keputusan oleh penyerang.
