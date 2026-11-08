# Writeup: Perceptron Train XNOR (Challenge ID: 781)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations (CWE-684 / NIST SP 800-115 §4.2)
- **Difficulty:** Easy (1)
- **Points:** 1
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Flag (Resmi CyLab):** `academy{xn0r_unl34rn4bl3_by_p3rc3ptr0ns_da5e1216}`
- **Flag Komunitas:** `CTF{xn0r_unl34rn4bl3_by_p3rc3ptr0ns_da5e1216}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman batas matematis model klasifikasi linier (*Single-Layer Perceptron*) dalam menyelesaikan masalah non-linier fundamental gerbang logika kesetaraan (*XNOR Logic Gate*):
> *"Watch a perceptron learn in real time on XNOR data using the classic update rule: only misclassified points trigger updates, with no weight decay. Because XNOR is not linearly separable, a single perceptron cannot hit 100% accuracy. Reach 75% accuracy to prove you understand the limitation and reveal the flag."*

Layanan web mengekspos endpoint interaktif `/train` yang menerima parameter laju pembelajaran $\eta$. Kumpulan data terdiri dari 4 titik pada ruang Cartesius $\mathbb{R}^2$:
- $(-2, -2) \to 1$ (Nilai logika sama -> True)
- $( 2,  2) \to 1$ (Nilai logika sama -> True)
- $(-2,  2) \to 0$ (Nilai logika beda -> False)
- $( 2, -2) \to 0$ (Nilai logika beda -> False)

Karena fungsi XNOR merupakan negasi langsung dari XOR, kedua kelas saling bersilangan secara diagonal sehingga mustahil dipisahkan secara sempurna oleh satu garis lurus. Peserta dituntut menemukan laju pembelajaran yang mengarahkan perceptron mencapai batas teoritis tertinggi yaitu $3 / 4 = 75.0\%$ akurasi dalam alokasi 16 langkah iterasi (`maxSteps = 16`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Teorema Separabilitas Linier Minsky & Papert (1969):**
   Masalah XOR dan XNOR merupakan bukti historis ketidakmampuan perceptron lapis tunggal (*Single-Layer Perceptron*) dalam mempelajari fungsi Boolean non-linier. Suatu classifier linier memisahkan ruang berdasarkan pertidaksamaan:
   $$w_1 x_1 + w_2 x_2 + b \ge 0 \implies \hat{y} = 1$$
   $$w_1 x_1 + w_2 x_2 + b < 0 \implies \hat{y} = 0$$
   Untuk fungsi XNOR, kondisi pemisahan sempurna menuntut pemenuhan sistem pertidaksamaan berikut secara simultan:
   - Titik $(-2, -2)$: $-2w_1 - 2w_2 + b \ge 0$
   - Titik $(2, 2)$: $2w_1 + 2w_2 + b \ge 0$
   - Titik $(-2, 2)$: $-2w_1 + 2w_2 + b < 0$
   - Titik $(2, -2)$: $2w_1 - 2w_2 + b < 0$
   Menjumlahkan dua pertidaksamaan pertama menghasilkan $2b \ge 0 \implies b \ge 0$.
   Menjumlahkan dua pertidaksamaan terakhir menghasilkan $2b < 0 \implies b < 0$.
   Kontradiksi matematis $b \ge 0$ dan $b < 0$ membuktikan secara mutlak bahwa tidak ada konfigurasi bobot $(w_1, w_2, b)$ yang dapat memisahkan keempat titik tersebut.

2. **Batas Atas Akurasi Teoritis ($3/4 = 75.0\%$):**
   Sebuah garis lurus pada bidang Cartesius hanya dapat memotong paling banyak 3 kuadran secara konsisten, meninggalkan setidaknya 1 kuadran pada separuh bidang yang salah. Akibatnya, akurasi optimal yang dapat dicapai oleh perceptron adalah mengklasifikasikan 3 titik secara tepat dan mengorbankan 1 titik, menghasilkan batas atas akurasi $75.0\%$.

3. **Implikasi Keamanan Model AI (CWE-684 / NIST SP 800-115 §4.2):**
   Memahami batas representasi logika Boolean pada arsitektur pembelajaran mesin sangat krusial dalam evaluasi pertahanan siber. Jika sebuah *Intrusion Detection System* (IDS) atau filter firewall berbasis AI menggunakan model linier tanpa transformasi fitur untuk mendeteksi korelasi bersilang (*cross-feature dependencies*), sistem tersebut secara struktural rentan terhadap *evasion attack*, di mana penyerang merekayasa muatan yang memanfaatkan titik kontradiksi logika untuk lolos dari inspeksi.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Antarmuka Web & Konfigurasi Pelatihan:**
   Inspeksi konfigurasi `/config.json` dan antarmuka web:
   - Endpoint: `POST /train`
   - Parameter Masukan: `{"learningRate": <float>}`
   - Ambang Kelulusan: `accuracy >= 0.75` (75.0%)
   - Batas Iterasi: `maxSteps = 16`

2. **Automasi Penyesuaian Parameter Pelatihan:**
   Mengirimkan permintaan pelatihan menggunakan laju pembelajaran $\eta = 0.02$ via skrip otomasi:
   ```python
   import urllib.request, json

   payload = json.dumps({"learningRate": 0.02}).encode("utf-8")
   req = urllib.request.Request(
       "http://xebec.cylabacademy.net:38226/train",
       data=payload,
       headers={"Content-Type": "application/json"}
   )
   with urllib.request.urlopen(req) as resp:
       res = json.loads(resp.read().decode())
       print("Akurasi:", res.get("accuracy"))
       print("Flag:", res.get("flag"))
   ```
   Pada eksekusi, perceptron menyesuaikan bobot dan berhenti pada akurasi tepat $75.0\%$, memenuhi kriteria tantangan dan merilis token flag resmi.

3. **Ekstraksi Token Resmi & Submisi Terverifikasi:**
   Token resmi diekstraksi dan disubmit ke endpoint REST API CyLab `/api/submissions/`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{xn0r_unl34rn4bl3_by_p3rc3ptr0ns_da5e1216}`
- **Format Flag Komunitas:** `CTF{xn0r_unl34rn4bl3_by_p3rc3ptr0ns_da5e1216}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 781, "flag": "academy{xn0r_unl34rn4bl3_by_p3rc3ptr0ns_da5e1216}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Penggunaan Fitur Polinomial Bersilang ($x_1 \cdot x_2$):**
   Dalam kurikulum LKS Cyber Security bidang Artificial Intelligence, peserta harus mampu mengatasi kelemahan XOR/XNOR melalui ekspansi basis fitur. Menambahkan fitur interaksi non-linier $x_3 = x_1 \cdot x_2$ memetakan data ke dalam ruang 3 dimensi di mana titik-titik XNOR menjadi terpisahkan secara linier sempurna oleh hiperbidang $w_3 x_3 + b = 0$ ($x_1 \cdot x_2 > 0$ untuk titik berlabel 1 dan $x_1 \cdot x_2 < 0$ untuk titik berlabel 0).
2. **Penerapan Jaringan Saraf Tiruan Berlapis (*Multi-Layer Perceptron*):**
   Untuk menyelesaikan fungsi logika non-linier secara umum tanpa rekayasa fitur manual, sistem wajib mengadopsi jaringan syaraf tiruan dengan minimal satu *hidden layer* yang memuat sekurang-kurangnya 2 neuron tersembunyi dengan fungsi aktivasi non-linier (ReLU/Sigmoid).
3. **Pengujian Kepatuhan Model Robustness (NIST SP 800-115 §4.2):**
   Penilaian keamanan arsitektur AI harus memastikan bahwa ketergantungan relasional antar-fitur (seperti kombinasi atribut autentikasi ganda atau korelasi header paket) dianalisis menggunakan model dengan kapasitas representasi yang cukup (*adequate hypothesis space*), menghindari kegagalan deteksi akibat keterbatasan matematis model linier sederhana.
