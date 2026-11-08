# Writeup: Perceptron Train 3-Bit Parity (Challenge ID: 776)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations (CWE-684 / NIST SP 800-115 §4.2)
- **Difficulty:** Easy (1)
- **Points:** 1
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Flag (Resmi CyLab):** `academy{3b1t_p4r1ty_unl34rn4bl3_l1n34rly_5d1cd0f2}`
- **Flag Komunitas:** `CTF{3b1t_p4r1ty_unl34rn4bl3_l1n34rly_5d1cd0f2}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman batas matematis model klasifikasi linier (*Single-Layer Perceptron*) dalam ruang euklidian 3 dimensi:
> *"Watch a perceptron learn in real time on 3-bit parity data using the classic update rule: only misclassified points trigger updates, with no weight decay. This challenge extends the same idea into 3 dimensions, and the frontend renders the points in 3D space. Because parity is not linearly separable by one plane, a single perceptron cannot hit 100% accuracy. Reach 75% accuracy to reveal the flag."*

Layanan web mengekspos endpoint interaktif `/train` yang menerima parameter laju pembelajaran (*learning rate*) $\eta$. Model perceptron diinisialisasi pada ruang bobot 3D ($w_1, w_2, w_3, b$) dengan aturan pembaruan diskrit Hebbian. Ruang data paritas 3-bit tidak dapat dipisahkan secara sempurna oleh satu hiperbidang linier (*linear separability ceiling*). Peserta dituntut menemukan laju pembelajaran yang mengoptimalkan hyperplane agar mencapai ambang akurasi $75\%$ (mengklasifikasikan 6 dari 8 titik secara tepat) dalam batas maksimum 16 langkah pembelajaran (`maxSteps = 16`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Batas Teorema Separabilitas Linier Minsky & Papert (1969):**
   Fungsi paritas 3-bit $f(x_1, x_2, x_3) = x_1 \oplus x_2 \oplus x_3$ memetakan 8 simpul kubus pada $\mathbb{R}^3$ ke dalam dua kelas binary:
   - Paritas Genap ($y = 0$): $(-2, -2, -2)$, $(-2, 2, 2)$, $(2, -2, 2)$, $(2, 2, -2)$
   - Paritas Ganjil ($y = 1$): $(-2, -2, 2)$, $(-2, 2, -2)$, $(2, -2, -2)$, $(2, 2, 2)$
   Dalam topologi ruang 3 dimensi, himpunan titik dengan label $0$ dan label $1$ saling bersilangan secara diagonal pada konveks hull kubus (*convex hull intersection*). Tidak ada bidang pemisah hiper datar tunggal $w_1 x_1 + w_2 x_2 + w_3 x_3 + b = 0$ yang dapat memisahkan kedua himpunan tersebut secara sempurna. Akurasi teoritis tertinggi yang dapat diraih oleh arsitektur *single-layer* tanpa fungsi aktivasi non-linear kontinu atau *hidden layers* adalah $6 / 8 = 75.0\%$.

2. **Dinamika Pembaruan Bobot Diskrit Hebbian:**
   Aturan pembaruan perceptron klasik beroperasi hanya pada sampel yang salah diklasifikasikan (*misclassified instances*):
   $$\Delta \vec{w} = \eta (y - \hat{y}) \vec{x}$$
   $$\Delta b = \eta (y - \hat{y})$$
   di mana $y \in \{0, 1\}$ dan $\hat{y} = \mathbf{1}_{(\vec{w} \cdot \vec{x} + b \ge 0)}$.
   Pada learning rate tertentu ($\eta$), osilasi pembaruan bobot dapat berhenti pada konfigurasi bidang yang memotong 2 titik anomali sembari mengklasifikasikan 6 titik lainnya dengan benar, mencapai target ambang batas $75\%$.

3. **Implikasi Keamanan Model AI (CWE-684 / NIST SP 800-115 §4.2):**
   Kegagalan memahami keterbatasan representasi model linier pada data non-linier menyebabkan kerentanan *model underfitting* dan *algorithmic blindspots*. Penyerang (*adversary*) dapat mengeksploitasi titik data yang berada di luar kapasitas separabilitas linier model untuk melakukan serangan penghindaran klasifikasi (*evasion attack*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Skema Endpoint Interaktif:**
   Inspeksi antarmuka web dan konfigurasi `config.json` mengungkap spesifikasi evaluasi:
   - Endpoint: `POST /train`
   - Payload: `{"learningRate": <float>}`
   - Respons: `{"accuracy": <float>, "weights": [...], "bias": <float>, "flag": <string>}`
   - Kriteria Rilis Flag: `accuracy >= 0.75`

2. **Automasi Parameter Tuning (Learning Rate Sweep):**
   Membangun loop penelusuran nilai $\eta \in [0.02, 2.0]$ dengan interval kenaikan $0.02$.
   ```bash
   curl -X POST http://chatelaine.cylabacademy.net:45398/train \
        -H "Content-Type: application/json" \
        -d '{"learningRate": 0.12}'
   ```
   Pada $\eta = 0.12$, perceptron berhenti memperbarui bobot setelah 16 langkah dan menghasilkan akurasi tepat $0.75$ (75.0%), merilis token flag resmi.

3. **Ekstraksi Token Resmi & Submisi Terverifikasi:**
   Token diekstraksi secara otomatis melalui skrip `scripts/solve_776_perceptron_train_3bit_parity.py` dan disubmit ke endpoint `/api/submissions/` CyLab Security Academy.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{3b1t_p4r1ty_unl34rn4bl3_l1n34rly_5d1cd0f2}`
- **Format Flag Komunitas:** `CTF{3b1t_p4r1ty_unl34rn4bl3_l1n34rly_5d1cd0f2}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 776, "flag": "academy{3b1t_p4r1ty_unl34rn4bl3_l1n34rly_5d1cd0f2}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Pemilihan Arsitektur Classifier Sesuai Topologi Data:**
   Dalam pengujian modul *AI / Machine Learning Security* LKS Cyber Security, praktisi tidak boleh menerapkan classifier linier (misalnya Logistic Regression atau Single Perceptron) untuk memproses fitur yang memiliki korelasi silang paritas/XOR tanpa rekayasa fitur polinomial (*polynomial feature mapping*) atau kernel non-linier (SVM RBF / Multi-Layer Perceptron).
2. **Mitigasi Algorithmic Blindspot via Multi-Layer Neural Networks:**
   Untuk mengklasifikasikan data paritas non-linier dengan akurasi 100%, sistem wajib menggunakan minimal satu *hidden layer* dengan fungsi aktivasi non-linier (ReLU, GELU, Sigmoid) atau Multi-Layer Perceptron (MLP) berukuran $3 \to 4 \to 1$.
3. **Pengujian Kepatuhan Model Robustness (NIST SP 800-115 §4.2):**
   Audit keamanan model AI harus menguji seluruh ruang batas keputusan (*decision boundary fuzzing*) untuk memastikan tidak ada celah klasifikasi (*decision regions*) yang dapat dimanipulasi oleh penyerang melalui manipulasi bit paritas masukan.
