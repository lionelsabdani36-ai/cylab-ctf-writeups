# Writeup: Perceptron Train Classic 0 (Challenge ID: 777)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations (CWE-684 / NIST SP 800-115 §4.2)
- **Difficulty:** Easy (1)
- **Points:** 1
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Flag (Resmi CyLab):** `academy{perceptron_classic_mode_02a3669e}`
- **Flag Komunitas:** `CTF{perceptron_classic_mode_02a3669e}`

---

## Problem Statement & Scope

Tantangan memperkenalkan dasar optimasi model linier biner (*Rosenblatt Perceptron*) menggunakan aturan pembaruan Hebbian diskrit klasik:
> *"Watch a perceptron learn in real time using the classic update rule: only misclassified points trigger updates, with no weight decay. This dataset is intentionally gentle, so many learning rates still converge quickly. Dial in a rate, trigger a run, and the interface will animate each step until every point is classified correctly."*

Layanan web interaktif menyediakan visualisasi HTML5 Canvas dan endpoint REST API `/train`. Model dihadapkan pada dataset 2 dimensi yang dapat dipisahkan secara linier (*linearly separable*). Parameter evaluasi backend menuntut akurasi sempurna ($100\%$, seluruh 8 titik diklasifikasikan dengan benar) dalam batasan maksimum 16 langkah pembelajaran (`maxSteps = 16`) tanpa degradasi bobot (*no weight decay*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Teorema Konvergensi Perceptron Novikoff (1962):**
   Jika sebuah himpunan data pelatihan bersifat dapat dipisahkan secara linier dengan margin geometris positif $\gamma = \min_i y_i (\vec{w}^* \cdot \vec{x}_i + b^*) / \|\vec{w}^*\| > 0$, dan seluruh vektor masukan dibatasi oleh radius euklidian $\|\vec{x}_i\| \le R$, maka algoritma pembelajaran perceptron dengan aturan diskrit:
   $$\Delta \vec{w} = \eta (y - \hat{y}) \vec{x}$$
   $$\Delta b = \eta (y - \hat{y})$$
   dijamin akan konvergen ke sebuah hiperbidang separasi sempurna dalam jumlah pembaruan terhingga yang dibatasi oleh:
   $$k \le \left(\frac{2R}{\gamma}\right)^2$$

2. **Analisis Topologi Dataset & Margin Separasi:**
   Dataset terdiri dari 8 titik koordinat pada $\mathbb{R}^2$:
   - Kelas 0 ($y = 0$, Kuadran Kiri Bawah): $(-4, -2)$, $(-3, -4)$, $(-2, -3)$, $(-3, -1)$
   - Kelas 1 ($y = 1$, Kuadran Kanan Atas): $(3, 4)$, $(4, 2)$, $(2, 3)$, $(3, 1)$
   Margin antara kedua klaster titik sangat lebar ($\gamma \gg 1.0$), dan vektor bobot awal diinisialisasi pada $w_0 = [1.0, -1.0], b_0 = 0.0$. Akibatnya, penyesuaian bobot dengan laju pembelajaran konservatif $\eta = 0.02$ mampu mengoreksi seluruh kesalahan klasifikasi hanya dalam 4 langkah iterasi, menghasilkan akurasi sempurna $100\%$.

3. **Korelasi Evaluasi Keamanan Siber (NIST SP 800-115 §4.2):**
   Memahami karakteristik konvergensi model klasifikasi linier merupakan prasyarat teknis dalam evaluasi sistem keamanan berbasis AI (misalnya deteksi malware berbasis signature biner atau filtering spam). Sistem pertahanan berbasis model linier tanpa regularisasi rentan terhadap pergeseran batas keputusan jika menerima masukan ekstrem yang memicu *gradient explosion* atau manipulasi margin.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Antarmuka & Endpoint Komunikasi:**
   Endpoint `/train` menerima parameter JSON:
   - Method: `POST`
   - URL: `http://<instance-host>:<port>/train`
   - Header: `Content-Type: application/json`
   - Body: `{"learningRate": 0.02}`

2. **Eksekusi Probing & Evaluasi Respon Model:**
   Mengirim permintaan HTTP dengan laju pembelajaran standar $\eta = 0.02$:
   ```bash
   curl -X POST http://xebec.cylabacademy.net:39452/train \
        -H "Content-Type: application/json" \
        -d '{"learningRate": 0.02}'
   ```
   Respons JSON:
   ```json
   {
     "success": true,
     "accuracy": 1.0,
     "steps": 4,
     "weights": [1.20, -0.72],
     "bias": -0.04,
     "flag": "academy{perceptron_classic_mode_02a3669e}"
   }
   ```
   Perceptron mencapai konvergensi 100% pada langkah ke-4, dan backend langsung merilis token autentikasi.

3. **Verifikasi Automasi Melalui REST API:**
   Skrip reproduksi mandiri `scripts/solve_777_perceptron_train_classic_0.py` mengeksekusi simulasi konvergensi matematis dan mensinkronisasikan hasil ke backend CyLab (`POST /api/submissions/`).

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{perceptron_classic_mode_02a3669e}`
- **Format Flag Komunitas:** `CTF{perceptron_classic_mode_02a3669e}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 777, "flag": "academy{perceptron_classic_mode_02a3669e}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Jaminan Konvergensi pada Data Linier:**
   Dalam skenario klasifikasi keamanan biner (misalnya klasifikasi domain berbahaya vs aman), algoritma perceptron klasik efektif dan cepat apabila fitur yang diekstraksi memiliki separabilitas linier terbukti.
2. **Pemberlakuan Batasan Nilai Masukan (Input Clipping & Normalization):**
   Untuk mencegah penyerang mendestabilisasi bidang keputusan (*decision hyperplane destabilization*) melalui titik pencilan (*outliers*), sistem klasifikasi wajib menerapkan normalisasi fitur masukan (misalnya $Z$-score atau Min-Max scaling ke rentang $[-1, 1]$).
3. **Pencegahan Overfitting Melalui Regularisasi Bobot:**
   Pada implementasi produksi, selalu tambahkan mekanisme penalti $L_2$ (*weight decay*) atau batasan *learning rate decay* agar bobot model tidak mengalami lonjakan drastis saat menghadapi sampel adversarial.
