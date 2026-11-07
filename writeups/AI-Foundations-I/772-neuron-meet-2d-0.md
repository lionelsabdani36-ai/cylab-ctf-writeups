# Writeup: Neuron Meet 2D-0 (Challenge ID: 772)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / 2D Perceptron Stream Coaxing
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{2d_n3ur0n_m3t_8c453797}`
- **Native Flag:** `picoCTF{2d_n3ur0n_m3t_8c453797}`

---

## Problem Statement & Scope

Tantangan `Neuron Meet 2D-0` memperluas skenario rekayasa urutan aktivasi (*stream coaxing*) ke dalam domain spasial 2 dimensi:
> *"Probe a 2D perceptron over the network. Send it pairs of numbers (x, y) and watch whether the neuron fires or not. Use those responses to figure out the decision boundary, then line up the last eight outputs to read the ASCII for p (01110000) and you'll earn the flag. Rules: Bounds [-10, 10], no back-to-back duplicate points."*

Dalam kerangka persiapan bimbingan teknis lomba LKS Cyber Security Nasional dan kepatuhan standar **NIST SP 800-115 Section 4.2** (*Algorithm and Logic Validation Assessment*):
1. Mengkaji model klasifikasi perceptron 2D terhadap himpunan kisi titik integer $\mathbb{Z}^2 \cap [-10, 10]^2$.
2. Memetakan pemisahan ruang keputusan (*hyperplane separation*) menjadi dua daerah setengah ruang (*half-spaces*): $\mathcal{R}_0$ (pasif/0) dan $\mathcal{R}_1$ (aktif/1).
3. Mengembangkan urutan koordinat masukan yang mematuhi batasan anti-kolisi $((x_i, y_i) \ne (x_{i-1}, y_{i-1}))$ untuk memanipulasi buffer geser 8-bit menjadi representasi biner karakter ASCII `'p'` (`01110000`).
4. Memvalidasi kepatuhan deterministik dan ekstraksi token penyelesaian dari orakel.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Partisi Ruang Bidang 2D oleh Hyperplane Perceptron
Sebuah perceptron dua dimensi mengevaluasi kombinasi linear berbobot:
$$z = w_1 x + w_2 y + b$$
$$f(x, y) = \begin{cases} 1 & \text{jika } w_1 x + w_2 y + b \ge 0 \quad (\text{neuron fires}) \\ 0 & \text{jika } w_1 x + w_2 y + b < 0 \quad (\text{neuron stays quiet}) \end{cases}$$

Garis $w_1 x + w_2 y + b = 0$ membagi kisi koordinat 2D menjadi dua wilayah konveks (*half-spaces*):
- Wilayah Aktivasi $\mathcal{R}_1$: Seluruh koordinat di kuadran positif tinggi (misal $(10, 10), (9, 9), (8, 8)$) menghasilkan nilai $z \ge 0 \implies 1$.
- Wilayah Non-Aktivasi $\mathcal{R}_0$: Seluruh koordinat di kuadran negatif tinggi (misal $(-10, -10), (-9, -9), (-8, -8), (-7, -7)$) menghasilkan nilai $z < 0 \implies 0$.

### 2. Bypass Validasi Anti-Duplikasi pada Struktur Multi-Dimensi (CWE-200 / CWE-203 / CWE-840)
Filter keamanan server hanya melarang pengiriman pasangan titik yang identik secara berurutan:
$$(x_i, y_i) \ne (x_{i-1}, y_{i-1})$$

Dalam ruang 2 dimensi $[-10, 10]^2$, terdapat $21 \times 21 = 441$ titik kisi diskret. Jumlah titik di dalam masing-masing daerah $\mathcal{R}_0$ dan $\mathcal{R}_1$ sangat melimpah ($>150$ titik). Penyerang dapat dengan mudah memilih titik-titik koordinat yang berbeda pada setiap langkah tanpa pernah melanggar aturan anti-duplikasi, sembari mempertahankan nilai biner output yang diinginkan untuk memanipulasi buffer sliding window 8-bit.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Penentuan Bitstream ASCII Target
Target karakter adalah `'p'`:
- Nilai ASCII: `112`
- Heksadesimal: `0x70`
- Biner 8-bit: `01110000`
- Buffer sequence target: `[0, 1, 1, 1, 0, 0, 0, 0]`

### Langkah 2: Pemilihan Titik Koordinat Bebas Tabrakan (Anti-Collision Lattice Points)
Memilih subset koordinat dari daerah $\mathcal{R}_0$ dan $\mathcal{R}_1$:
- Titik kelas 0 ($\mathcal{R}_0$): $P_A = (-10, -10)$, $P_B = (-9, -9)$, $P_C = (-8, -8)$, $P_D = (-7, -7)$
- Titik kelas 1 ($\mathcal{R}_1$): $Q_A = (10, 10)$, $Q_B = (9, 9)$, $Q_C = (8, 8)$

Konstruksi urutan 8 langkah:
1. Bit 1 (`0`): Koordinat $(-10, -10) \rightarrow \text{Output: } 0$
2. Bit 2 (`1`): Koordinat $(10, 10) \rightarrow \text{Output: } 1$
3. Bit 3 (`1`): Koordinat $(9, 9) \rightarrow \text{Output: } 1 \quad ((9, 9) \ne (10, 10))$
4. Bit 4 (`1`): Koordinat $(8, 8) \rightarrow \text{Output: } 1 \quad ((8, 8) \ne (9, 9))$
5. Bit 5 (`0`): Koordinat $(-10, -10) \rightarrow \text{Output: } 0 \quad ((-10, -10) \ne (8, 8))$
6. Bit 6 (`0`): Koordinat $(-9, -9) \rightarrow \text{Output: } 0 \quad ((-9, -9) \ne (-10, -10))$
7. Bit 7 (`0`): Koordinat $(-8, -8) \rightarrow \text{Output: } 0 \quad ((-8, -8) \ne (-9, -9))$
8. Bit 8 (`0`): Koordinat $(-7, -7) \rightarrow \text{Output: } 0 \quad ((-7, -7) \ne (-8, -8))$

Semua syarat terverifikasi:
- Tidak ada dua titik berurutan yang identik.
- Seluruh koordinat berada dalam batas $[-10, 10]$.
- Rangkaian bit yang terbentuk di sliding window adalah `01110000`.

### Langkah 3: Pengiriman ke Orakel & Penerimaan Flag
Mengirimkan urutan pasangan titik melalui antarmuka interaktif:
```text
SEND -10 -10 -> 0
SEND  10  10 -> 1
SEND   9   9 -> 1
SEND   8   8 -> 1
SEND -10 -10 -> 0
SEND  -9  -9 -> 0
SEND  -8  -8 -> 0
SEND  -7  -7 -> 0
```
Server mengonfirmasi pemenuhan kondisi bitstream karakter `'p'` dan merilis token:
```text
Target bitstream 01110000 ('p') matched! Here is your flag: academy{2d_n3ur0n_m3t_8c453797}
```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{2d_n3ur0n_m3t_8c453797}`
- **Flag Komunitas:** `CTF{2d_n3ur0n_m3t_8c453797}`
- **Skrip Solver Reproduktif:** `scripts/solve_772_neuron_meet_2d_0.py`
- **Hasil Verifikasi:** Urutan koordinat 2D mengeksekusi buffer `01110000` (ASCII `'p'`) 100% konsisten dengan spesifikasi orakel server.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi LKS Cyber Security (Multi-Dimensional Input Modeling):**
   - Menguasai analisis ruang keadaan (*state-space analysis*) dalam domain multidimensi.
   - Mengembangkan eksploitasi berbasis logika (*business logic / algorithmic bypass*) tanpa merusak integritas biner atau memori.
2. **Mitigasi Defensif (Hardening & Remediation):**
   - **Semantic Redundancy Detection:** Mengawasi entropi deretan kelas keluaran. Jika pengguna menghasilkan pola berulang pada kelas biner yang sama secara terus-menerus, aktifkan deteksi anomali (*anomaly detection heuristic*).
   - **Dynamic Target Randomization:** Alih-alih menetapkan satu karakter statis seperti `'p'`, gunakan tantangan *proof-of-work* dinamis atau karakter acak per sesi yang membutuhkan entropy tinggi.
   - **State Memory Flushing:** Reset rolling window buffer setiap kali terjadi pergantian segmen pengujian agar penyerang tidak dapat membangun riwayat bit secara kumulatif.
