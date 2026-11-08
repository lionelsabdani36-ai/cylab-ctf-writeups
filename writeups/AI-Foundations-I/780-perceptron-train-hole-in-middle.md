# Writeup: Perceptron Train Hole in Middle (Challenge ID: 780)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations (CWE-684 / NIST SP 800-115 §4.2)
- **Difficulty:** Easy (1)
- **Points:** 1
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Flag (Resmi CyLab):** `academy{h0l3_1n_m1ddl3_unl34rn4bl3_l1n34rly_c85a6043}`
- **Flag Komunitas:** `CTF{h0l3_1n_m1ddl3_unl34rn4bl3_l1n34rly_c85a6043}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman batas matematis model klasifikasi linier (*Single-Layer Perceptron*) dalam menangani distribusi geometris non-konveks yang dikenal sebagai pola *"Hole in the Middle"*:
> *"Watch a perceptron learn in real time on a 'hole in the middle' pattern: positive points surround one negative center point. The classic perceptron update rule still applies (only misclassified points trigger updates, with no weight decay), but this shape is not linearly separable by a single line. Reach 88.9% accuracy to reveal the flag."*

Layanan web mengekspos endpoint `/train` yang menerima parameter laju pembelajaran $\eta$. Kumpulan data terdiri dari 9 titik sampel: 8 titik positif ($label = 1$) yang membentuk cincin di sekeliling titik asal, dan 1 titik negatif ($label = 0$) tepat di pusat koordinat $(0, 0)$. Karena topologi lingkaran tidak dapat dipisahkan secara sempurna oleh garis lurus, peserta dituntut menemukan laju pembelajaran yang mengarahkan perceptron mencapai batas teoritis tertinggi yaitu $8 / 9 \approx 88.89\%$ (88.9%) akurasi dalam batas 16 langkah iterasi (`maxSteps = 16`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Batas Geometri Separabilitas Ruang Separuh (Half-Space Geometry):**
   Suatu perceptron linier dua dimensi mendefinisikan garis pemisah $w_1 x_1 + w_2 x_2 + b = 0$, yang membagi bidang Euclidean $\mathbb{R}^2$ menjadi dua separuh bidang konveks (*affine half-spaces*):
   $$H^+ = \{x \in \mathbb{R}^2 \mid w^T x + b \ge 0\}$$
   $$H^- = \{x \in \mathbb{R}^2 \mid w^T x + b < 0\}$$
   Titik pusat $(0, 0)$ yang berlabel $0$ terletak secara eksklusif di dalam lambung konveks (*convex hull*) dari 8 titik berlabel $1$ yang melingkarinya:
   $$(0, 0) \in \text{Conv}(\{x_i \mid y_i = 1\})$$
   Berdasarkan Teorema Pemisahan Hiperbidang (*Hyperplane Separation Theorem*), dua himpunan hanya dapat dipisahkan secara linier jika lambung konveks keduanya tidak saling beririsan. Karena titik negatif berada di dalam interior konveks himpunan positif, pemisahan sempurna adalah kemustahilan matematis bagi classifier linier.

2. **Batas Atas Akurasi Teoritis ($8/9 = 88.89\%$):**
   Setiap garis lurus yang memotong bidang hanya dapat memisahkan paling banyak sebagian titik cincin. Namun, jika garis diletakkan sedemikian rupa sehingga seluruh bidang dinyatakan sebagai kelas positif ($H^+ = \mathbb{R}^2$, melalui penyesuaian bias $b > 0$), maka seluruh 8 titik cincin akan terklasifikasi dengan benar, sementara hanya 1 titik pusat yang salah. Hal ini menghasilkan batas akurasi maksimum:
   $$\text{Akurasi Maksimum} = \frac{8}{9} \approx 88.8889\%$$

3. **Implikasi Keamanan Model AI (CWE-684 / NIST SP 800-115 §4.2):**
   Kerentanan ini merepresentasikan masalah arsitektural fundamental (*representational limitation*). Dalam sistem keamanan berbasis machine learning, apabila fitur anomali (seperti muatan serangan berbahaya) terkonsentrasi di tengah-tengah pola trafik normal tanpa adanya pemetaan non-linier, classifier linier dipaksa untuk mengorbankan salah satu kelas, menyebabkan *false negative* sistemik yang dapat dieksploitasi penyerang.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Antarmuka Web & Konfigurasi Evaluasi:**
   Inspeksi konfigurasi `/config.json` dan antarmuka web:
   - Endpoint: `POST /train`
   - Parameter Masukan: `{"learningRate": <float>}`
   - Ambang Kelulusan: `accuracy >= 0.888` (88.9%)
   - Batas Iterasi: `maxSteps = 16`

2. **Automasi Penyesuaian Parameter Pelatihan:**
   Mengirimkan permintaan pelatihan menggunakan laju pembelajaran $\eta = 0.02$ atau $\eta = 0.20$ via skrip otomasi:
   ```python
   import urllib.request, json

   payload = json.dumps({"learningRate": 0.2}).encode("utf-8")
   req = urllib.request.Request(
       "http://chatelaine.cylabacademy.net:36063/train",
       data=payload,
       headers={"Content-Type": "application/json"}
   )
   with urllib.request.urlopen(req) as resp:
       res = json.loads(resp.read().decode())
       print("Akurasi:", res.get("accuracy"))
       print("Flag:", res.get("flag"))
   ```
   Pada eksekusi, perceptron menyesuaikan bobot dan berhenti pada akurasi tepat $88.89\%$, yang memenuhi kriteria sistem dan membuka flag.

3. **Ekstraksi Token Resmi & Submisi Terverifikasi:**
   Token resmi diekstraksi dan disubmit ke endpoint REST API CyLab `/api/submissions/`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{h0l3_1n_m1ddl3_unl34rn4bl3_l1n34rly_c85a6043}`
- **Format Flag Komunitas:** `CTF{h0l3_1n_m1ddl3_unl34rn4bl3_l1n34rly_c85a6043}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 780, "flag": "academy{h0l3_1n_m1ddl3_unl34rn4bl3_l1n34rly_c85a6043}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Transformasi Fitur Non-Linier (Kernel Trick / Polar Projection):**
   Dalam kurikulum LKS Cyber Security bidang Artificial Intelligence, peserta harus memahami cara mengatasi non-separabilitas geometris melalui rekayasa fitur (*feature engineering*). Pada kasus pola konsentris / cincin, mentransformasikan koordinat Kartesius $(x, y)$ menjadi koordinat polar atau menambahkan fitur radial $r^2 = x^2 + y^2$ memungkinkan pemisahan linier sempurna pada dimensi baru ($z = x^2 + y^2 \ge r_0^2$).
2. **Penerapan Multi-Layer Perceptron (MLP) dengan Aktivasi Non-Linier:**
   Arsitektur jaringan saraf tiruan harus menyertakan sedikitnya satu lapisan tersembunyi (*hidden layer*) dengan fungsi aktivasi seperti ReLU ($\max(0, x)$) atau Sigmoid agar model mampu membentuk batas keputusan tertutup (*convex boundary enclosure*) untuk memisahkan anomali sentral.
3. **Pengujian Kepatuhan Model Robustness (NIST SP 800-115 §4.2):**
   Pengujian penetrasi terhadap modul AI harus memetakan struktur topologi data uji. Memverifikasi bahwa data pelatihan tidak memiliki interseksi lambung konveks (*convex hull overlap*) antar kelas adalah langkah wajib sebelum menyebarkan model deteksi ancaman ke lingkungan produksi.
