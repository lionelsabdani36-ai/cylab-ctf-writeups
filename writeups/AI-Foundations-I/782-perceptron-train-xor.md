# Writeup: Perceptron Train XOR (Challenge ID: 782)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations (CWE-684 / NIST SP 800-115 §4.2)
- **Difficulty:** Easy (1)
- **Points:** 1
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Flag (Resmi CyLab):** `academy{x0r_unl34rn4bl3_by_p3rc3ptr0ns_d7c0c598}`
- **Flag Komunitas:** `CTF{x0r_unl34rn4bl3_by_p3rc3ptr0ns_d7c0c598}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman teoritis dan praktis atas batas komputasi model klasifikasi linier (*Single-Layer Perceptron*) dalam memetakan fungsi logika ketidaksamaan Boolean (*XOR Logic Gate*):
> *"Watch a perceptron learn in real time on XOR data using the classic update rule: only misclassified points trigger updates, with no weight decay. Because XOR is not linearly separable, a single perceptron cannot hit 100% accuracy. Reach 75% accuracy to prove you understand the limitation and reveal the flag."*

Layanan web mengekspos endpoint `/train` yang menerima parameter laju pembelajaran $\eta$ (`learningRate`). Distribusi data uji terdiri dari 4 titik pada ruang Cartesius $\mathbb{R}^2$:
- $(-2, -2) \to 0$ (Nilai logika sama -> False)
- $( 2,  2) \to 0$ (Nilai logika sama -> False)
- $(-2,  2) \to 1$ (Nilai logika beda -> True)
- $( 2, -2) \to 1$ (Nilai logika beda -> True)

Model diperbarui menggunakan aturan klasik Rosenblatt (*no weight decay*, pembaruan bobot hanya dipicu oleh titik yang salah diklasifikasikan) dengan batas maksimal 16 iterasi (`maxSteps = 16`). Peserta dituntut melakukan tuning laju pembelajaran $\eta \in [0.02, 20.0]$ agar model mencapai akurasi batas atas teoritis yaitu $3/4 = 75.0\%$ untuk membuka token flag resmi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Teorema Separabilitas Linier Minsky & Papert (1969):**
   Fungsi logika XOR merupakan representasi kanonikal dari permasalahan non-linearly separable. Sebuah perceptron lapis tunggal membagi ruang dua dimensi dengan hiperbidang linier:
   $$w_1 x_1 + w_2 x_2 + b \ge 0 \implies \hat{y} = 1$$
   $$w_1 x_1 + w_2 x_2 + b < 0 \implies \hat{y} = 0$$
   Untuk memisahkan keempat titik XOR secara sempurna, sistem pertidaksamaan berikut wajib dipenuhi secara simultan:
   - Titik $(-2, -2)$: $-2w_1 - 2w_2 + b < 0$
   - Titik $(2, 2)$: $2w_1 + 2w_2 + b < 0$
   - Titik $(-2, 2)$: $-2w_1 + 2w_2 + b \ge 0$
   - Titik $(2, -2)$: $2w_1 - 2w_2 + b \ge 0$
   Menjumlahkan dua pertidaksamaan pertama menghasilkan $2b < 0 \implies b < 0$.
   Menjumlahkan dua pertidaksamaan terakhir menghasilkan $2b \ge 0 \implies b \ge 0$.
   Kontradiksi $b < 0$ dan $b \ge 0$ membuktikan secara matematis bahwa tidak ada konfigurasi bobot linier $(w_1, w_2, b)$ yang mampu memisahkan kelas 0 dan kelas 1 pada fungsi XOR.

2. **Batas Atas Akurasi Teoritis ($3/4 = 75.0\%$):**
   Sebuah garis lurus pada bidang datar $\mathbb{R}^2$ hanya dapat memisahkan paling banyak 3 kuadran secara simultan, meninggalkan setidaknya 1 sampel berada di sisi hiperbidang yang keliru. Oleh karena itu, akurasi optimal perceptron lapis tunggal pada dataset XOR terbatas secara mutlak pada $3/4 = 75.0\%$.

3. **Implikasi Keamanan Arsitektur AI (CWE-684 / NIST SP 800-115 §4.2):**
   Dalam konteks keamanan siber, mengandalkan model klasifikasi linier untuk mendeteksi ancaman multi-vektor (seperti aturan korelasi firewall atau deteksi anomali IDS) menciptakan celah struktural (*blind spots*). Penyerang dapat merancang muatan uji (*evasion payload*) yang mengeksploitasi ketergantungan relasional antar-fitur (*feature cross-interaction*) yang tidak mampu dipelajari oleh model linier sederhana.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Antarmuka Web & Konfigurasi Pelatihan:**
   Inspeksi endpoint live dan konfigurasi lab:
   - Endpoint: `POST /train`
   - Payload JSON: `{"learningRate": <float>}`
   - Ambang Keberhasilan: `accuracy >= 0.75`
   - Batas Pembaruan: `maxSteps = 16`

2. **Automasi Penyesuaian Parameter Pelatihan:**
   Mengirimkan permintaan pelatihan HTTP POST dengan laju pembelajaran $\eta = 0.02$ menggunakan skrip reproduktif `scripts/solve_782_perceptron_train_xor.py`:
   ```python
   import urllib.request, json

   payload = json.dumps({"learningRate": 0.02}).encode("utf-8")
   req = urllib.request.Request(
       "http://xebec.cylabacademy.net:22064/train",
       data=payload,
       headers={"Content-Type": "application/json"}
   )
   with urllib.request.urlopen(req) as resp:
       res = json.loads(resp.read().decode())
       print("Akurasi:", res.get("accuracy"))
       print("Flag:", res.get("flag"))
   ```
   Pada eksekusi, bobot perceptron bergeser dan berhenti pada akurasi tepat $75.0\%$, memenuhi kriteria tantangan dan memicu rilis token flag resmi.

3. **Ekstraksi Token Resmi & Submisi Terverifikasi:**
   Token diekstraksi dan disubmit langsung ke REST API CyLab `/api/submissions/`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{x0r_unl34rn4bl3_by_p3rc3ptr0ns_d7c0c598}`
- **Format Flag Komunitas:** `CTF{x0r_unl34rn4bl3_by_p3rc3ptr0ns_d7c0c598}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 782, "flag": "academy{x0r_unl34rn4bl3_by_p3rc3ptr0ns_d7c0c598}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Rekayasa Fitur Polinomial Interaktif ($x_1 \cdot x_2$):**
   Dalam kurikulum bimbingan teknis LKS Cyber Security bidang Artificial Intelligence, peserta harus memahami bahwa kelemahan linieritas dapat diatasi dengan transformasi ruang fitur (*basis function expansion*). Menambahkan fitur perkalian silang $x_3 = x_1 \cdot x_2$ memetakan data ke ruang $\mathbb{R}^3$, di mana titik XOR menjadi terpisahkan linier sempurna oleh hiperbidang $w_3 x_3 + b = 0$ ($x_1 \cdot x_2 < 0$ untuk kelas 1 dan $x_1 \cdot x_2 > 0$ untuk kelas 0).
2. **Penerapan Arsitektur Jaringan Multi-Lapis (*Multi-Layer Perceptron*):**
   Untuk menyelesaikan fungsi non-linier tanpa rekayasa fitur manual, arsitektur wajib mengadopsi Multi-Layer Perceptron (MLP) dengan minimal 1 *hidden layer* yang memuat fungsi aktivasi non-linier seperti ReLU atau Sigmoid, memungkinkan pembentukan kurva batas keputusan cembung ganda.
3. **Pengujian Kepatuhan Keandalan Model (NIST SP 800-115 §4.2):**
   Evaluator keamanan sistem AI harus memverifikasi bahwa model deteksi ancaman memiliki kapasitas representasional yang memadai terhadap seluruh permutasi kombinasi atribut serangan, mencegah lolosnya vektor serangan berbasis interaksi fitur silang.
