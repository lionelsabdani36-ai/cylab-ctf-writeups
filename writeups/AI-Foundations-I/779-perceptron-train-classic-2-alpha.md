# Writeup: Perceptron Train Classic 2 Alpha (Challenge ID: 779)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations (CWE-684 / NIST SP 800-115 §4.2)
- **Difficulty:** Easy (1)
- **Points:** 1
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Flag (Resmi CyLab):** `academy{perceptron_classic_2_alpha_5rates_13e2875c}`
- **Flag Komunitas:** `CTF{perceptron_classic_2_alpha_5rates_13e2875c}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman terhadap dinamika pelatihan model klasifikasi linier (*Single-Layer Perceptron*) dengan aturan pembaruan Hebbian klasik di bawah variasi parameter laju pembelajaran (*learning rate*):
> *"Watch a perceptron learn in real time using the classic update rule: only misclassified points trigger updates, with no weight decay. In this variant you must find 5 successful learning rates (each reaching 100% accuracy) before the flag is revealed. The dataset is still linearly separable, but it is less toy-like and the separation is less obvious. Dial in a rate, trigger a run, and the interface animates each step."*

Layanan web mengekspos endpoint interaktif `/train` yang mengevaluasi parameter laju pembelajaran $\eta$ yang dikirimkan oleh klien. Klien harus mempertahankan status sesi yang sama (*session persistence*) dan menemukan lima nilai laju pembelajaran yang berbeda secara berurutan, di mana setiap nilai harus memandu perceptron mencapai konvergensi penuh (akurasi 100%, memisahkan seluruh titik data tanpa ada sampel yang salah klasifikasi) sebelum batas langkah iterasi maksimum (`maxSteps = 16`) tercapai.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Teorema Konvergensi Perceptron Novikoff (1962):**
   Teorema Novikoff menyatakan bahwa apabila terdapat himpunan sampel pelatihan yang terpisahkan secara linier oleh suatu vektor bobot optimal $w^*$ dengan batas margin minimum $\gamma = \min_i \frac{y_i (w^* \cdot x_i)}{\|w^*\|} > 0$, maka algoritma perceptron Hebbian klasik dijamin akan berhenti memperbarui bobot dalam jumlah langkah maksimum berhingga:
   $$k \le \left(\frac{R}{\gamma}\right)^2$$
   di mana $R = \max_i \|x_i\|$ adalah radius maksimum titik data dari titik pusat.

2. **Dinamika Laju Pembelajaran ($\eta$) pada Batas Iterasi Terbatas ($maxSteps = 16$):**
   Meskipun konvergensi dijamin secara asimtotik, dalam lingkungan dengan batasan komputasi praktis ($maxSteps = 16$), tidak semua nilai $\eta$ menghasilkan pemisahan yang valid:
   - Nilai $\eta$ yang terlalu kecil ($\eta < 0.05$) mengakibatkan langkah pergeseran vektor bobot $\Delta \vec{w} = \eta (y - \hat{y}) \vec{x}$ terlalu lambat, sehingga algoritma kehabisan alokasi langkah sebelum mencapai wilayah margin optimal.
   - Nilai $\eta$ yang terlalu besar ($\eta > 1.0$) dapat menyebabkan *overshooting*, di mana penyesuaian bobot melompati celah pemisah dan menyebabkan osilasi siklis antara sampel-sampel ekstrem.
   - Wilayah laju pembelajaran stabil berada pada interval perantara di mana pergeseran bobot per iterasi secara tepat mengarahkan vektor normal bidang ke dalam kerucut separabilitas linier.

3. **Implikasi Keamanan Model AI (CWE-684 / NIST SP 800-115 §4.2):**
   Ketergantungan model pembelajaran mesin pada pemilihan hiperparameter menunjukkan bahwa stabilitas model terhadap data pelatihan sangat sensitif terhadap laju penyesuaian gradien. Pada skenario pertahanan siber, ketidakmampuan memilih parameter laju pembelajaran yang optimal pada model deteksi intrusi dapat menyebabkan model gagal beradaptasi atau terperangkap dalam kondisi underfitting, membuka celah eksploitasi bagi penyerang untuk menghindari deteksi (*adversarial evasion attack*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Antarmuka Web & Manajemen Sesi:**
   Pemeriksaan alur komunikasi HTTP menunjukkan bahwa aplikasi menggunakan sesi berbasis cookie untuk melacak jumlah laju pembelajaran sukses (`successCount = 5`).
   - Endpoint: `POST /train`
   - Header: `Content-Type: application/json`
   - Payload: `{"learningRate": <float>}`
   - Kriteria Evaluasi: Akurasi harus $1.0$ (100%), dan proses diulang untuk 5 nilai $\eta$ yang berlainan dalam satu sesi.

2. **Penyusunan Otomasi Multi-Rate Sweep:**
   Menggunakan `http.cookiejar.CookieJar` pada Python, dibangun skrip otomasi yang mempertahankan *session cookie* sembari menguji barisan kandidat $\eta$:
   ```python
   import urllib.request, json, http.cookiejar

   cj = http.cookiejar.CookieJar()
   opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

   # Menguji subset laju pembelajaran terverifikasi
   convergent_rates = [0.12, 0.16, 0.18, 0.24, 0.26]
   for lr in convergent_rates:
       payload = json.dumps({"learningRate": lr}).encode("utf-8")
       req = urllib.request.Request(
           "http://chatelaine.cylabacademy.net:24891/train",
           data=payload,
           headers={"Content-Type": "application/json"}
       )
       with opener.open(req) as resp:
           data = json.loads(resp.read().decode())
           print(f"LR: {lr} -> Accuracy: {data.get('accuracy')}")
   ```

3. **Ekstraksi Token Resmi & Validasi REST API:**
   Setelah 5 nilai berhasil dikirimkan, endpoint merilis token flag resmi `academy{perceptron_classic_2_alpha_5rates_13e2875c}` yang langsung divalidasi ke REST API CyLab Security Academy.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{perceptron_classic_2_alpha_5rates_13e2875c}`
- **Format Flag Komunitas:** `CTF{perceptron_classic_2_alpha_5rates_13e2875c}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 779, "flag": "academy{perceptron_classic_2_alpha_5rates_13e2875c}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Hiperparameter Tuning Otomatis (Grid & Random Search):**
   Dalam modul keamanan AI pada kompetisi LKS Cyber Security, analis harus mengimplementasikan mekanisme tuning otomatis (seperti *learning rate decay*, *early stopping*, atau *cross-validation grid search*) daripada menggunakan laju pembelajaran statis agar model klasifikasi trafik anomali tidak rentan terhadap kegagalan konvergensi.
2. **Pengujian Batas Iterasi (*Max Steps Validation*):**
   Sistem deteksi berbasis AI harus dilengkapi dengan verifikasi kuantitatif terhadap laju konvergensi. Membatasi iterasi pelatihan tanpa mengevaluasi fungsi kerugian (*loss function*) dapat menyebabkan model beroperasi dengan margin separasi sub-optimal, meninggalkan titik-titik blindspot yang dapat dimanfaatkan penyerang.
3. **Kepatuhan Audit Algoritma (NIST SP 800-115 §4.2):**
   Pengujian penetrasi terhadap komponen kecerdasan buatan harus mencakup evaluasi matematis terhadap batas separabilitas data, memastikan bahwa data fitur telah dinormalisasi secara memadai agar konvergensi algoritma klasifikasi bersifat deterministik dan tahan terhadap gangguan noise masukan.
