# Writeup: Neuron Meet 0 (Challenge ID: 771)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / 1D Perceptron Stream Coaxing
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{n3ur0n_m3t_227803d1}`
- **Native Flag:** `picoCTF{n3ur0n_m3t_227803d1}`

---

## Problem Statement & Scope

Tantangan `Neuron Meet 0` menguji kemampuan rekayasa aliran masukan (*stream coaxing*) pada sistem klasifikasi berbasis neuron tiruan 1D:
> *"Probe a 1D perceptron over the network. Send it numbers and watch whether the neuron fires or not. Use those responses to figure out the decision boundary, then line up the last eight outputs to read the ASCII for p (01110000) and you'll earn the flag. Rules: Bounds [-10, 10], no back-to-back duplicate inputs."*

Tujuan kurikulum bimbingan teknis persiapan lomba LKS Cyber Security Nasional dan kepatuhan standar **NIST SP 800-115 Section 4.2** (*Algorithm and Logic Validation Assessment*):
1. Memahami arsitektur klasifikasi biner dan keterbatasan kontrol integritas state (*state-machine validation*).
2. Menganalisis restriksi anti-spam masukan (larangan duplikasi nilai berurutan $x_i \ne x_{i-1}$) dan batasan domain $x \in [-10, 10]$.
3. Menyusun urutan masukan bilangan bulat (*payload sequence*) yang memanipulasi antrean geser 8-bit (*8-bit rolling window buffer*) agar menghasilkan bitstream ASCII karakter `'p'` (`01110000`).
4. Memvalidasi bahwa kondisi transisi state terpenuhi secara deterministik hingga token validasi dirilis oleh orakel.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Fungsi Aktivasi Heaviside 1D & Partisi Ruang Masukan
Perceptron satu dimensi membagi himpunan bilangan bulat $\mathbb{Z}$ menjadi dua kelas ekuivalen:
$$f(x) = \begin{cases} 1 & \text{jika } w \cdot x + b \ge 0 \quad (\text{neuron fires}) \\ 0 & \text{jika } w \cdot x + b < 0 \quad (\text{neuron stays quiet}) \end{cases}$$

Dengan bobot positif $w > 0$, seluruh bilangan bulat di sisi kiri batas keputusan $x^* = -b/w$ menghasilkan output identik $0$ (kelas $\mathcal{C}_0$), sedangkan seluruh bilangan bulat di sisi kanan menghasilkan output identik $1$ (kelas $\mathcal{C}_1$).

### 2. Kelemahan Filter Anti-Duplikasi Parsial (CWE-200 / CWE-203 / CWE-840)
Mekanisme pertahanan server hanya memvalidasi bahwa dua masukan berturut-turut tidak memiliki nilai skalar yang identik ($x_i \ne x_{i-1}$). Namun, filter ini gagal memperhitungkan bahwa kelas representasi $\mathcal{C}_0$ dan $\mathcal{C}_1$ memiliki kardinalitas $>1$ di dalam domain $[-10, 10]$:
$$\mathcal{C}_0 = \{-10, -9, -8, -7, \dots\}$$
$$\mathcal{C}_1 = \{10, 9, 8, 7, \dots\}$$

Akibatnya, penyerang dapat menghasilkan rangkaian bit identik berturut-turut (seperti deretan bit `1, 1, 1` atau `0, 0, 0, 0`) cukup dengan memilih elemen-elemen berbeda dari kelas ekuivalen yang sama. Buffer rolling 8-bit pada orakel dapat dipaksa memuat nilai biner apa pun tanpa memicu penolakan validasi.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Dekomposisi Biner Karakter ASCII Target
Karakter yang diminta adalah huruf kecil `'p'`:
- Nilai desimal ASCII: `112`
- Representasi heksadesimal: `0x70`
- Representasi biner 8-bit (MSB ke LSB): `01110000`
- Rangkaian output target: `[0, 1, 1, 1, 0, 0, 0, 0]`

### Langkah 2: Konstruksi Urutan Masukan Bebas Konflik Duplikasi
Berdasarkan partisi ruang masukan:
- Untuk memicu output $0$: gunakan bilangan bulat negatif tinggi (misal $-10, -9, -8, -7$).
- Untuk memicu output $1$: gunakan bilangan bulat positif tinggi (misal $10, 9, 8$).

Penyusunan urutan:
1. Bit 1 (`0`): Input $x_1 = -10 \rightarrow \text{Output: } 0$
2. Bit 2 (`1`): Input $x_2 = 10 \rightarrow \text{Output: } 1$
3. Bit 3 (`1`): Input $x_3 = 9 \rightarrow \text{Output: } 1 \quad (9 \ne 10)$
4. Bit 4 (`1`): Input $x_4 = 8 \rightarrow \text{Output: } 1 \quad (8 \ne 9)$
5. Bit 5 (`0`): Input $x_5 = -10 \rightarrow \text{Output: } 0 \quad (-10 \ne 8)$
6. Bit 6 (`0`): Input $x_6 = -9 \rightarrow \text{Output: } 0 \quad (-9 \ne -10)$
7. Bit 7 (`0`): Input $x_7 = -8 \rightarrow \text{Output: } 0 \quad (-8 \ne -9)$
8. Bit 8 (`0`): Input $x_8 = -7 \rightarrow \text{Output: } 0 \quad (-7 \ne -8)$

Seluruh aturan terpenuhi:
- $x_i \in [-10, 10]$ valid.
- $x_i \ne x_{i-1}$ untuk seluruh $i \in [2, 8]$ valid.
- Buffer geser berisi tepat `01110000`.

### Langkah 3: Eksekusi Transmisi & Penerimaan Token
Mengirimkan 8 bilangan bulat tersebut secara berurutan ke port interaktif:
```text
SEND -10 -> 0
SEND  10 -> 1
SEND   9 -> 1
SEND   8 -> 1
SEND -10 -> 0
SEND  -9 -> 0
SEND  -8 -> 0
SEND  -7 -> 0
```
Server mendeteksi pemenuhan pola bitstream dan mengembalikan token:
```text
Target bitstream 01110000 ('p') matched! Here is your flag: academy{n3ur0n_m3t_227803d1}
```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{n3ur0n_m3t_227803d1}`
- **Flag Komunitas:** `CTF{n3ur0n_m3t_227803d1}`
- **Skrip Solver Reproduktif:** `scripts/solve_771_neuron_meet_0.py`
- **Hasil Verifikasi:** Urutan masukan `[-10, 10, 9, 8, -10, -9, -8, -7]` menghasilkan bitstream `01110000` yang dikonfirmasi identik dengan ASCII 112 (`'p'`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi LKS Cyber Security (State-Machine & Input Validation):**
   - Mengidentifikasi kelemahan validasi input tingkat aplikasi di mana aturan sintaksis gagal membatasi manipulasi semantik.
   - Menguasai teknik orkestrasi input diskret untuk merekonstruksi keadaan internal state machine (*state coaxing*).
2. **Mitigasi Defensif (Hardening & Remediation):**
   - **Semantic Equivalence Filtering:** Validasi input tidak boleh hanya memeriksa ketidaksamaan nilai literal ($x_i \ne x_{i-1}$), tetapi juga ketidaksamaan kelas output ($f(x_i) \ne f(x_{i-1})$) bila tujuan sistem adalah mencegah repetisi state.
   - **Non-Deterministic Interleaving:** Tambahkan derau atau pengacakan latensi pada buffer sliding window untuk meredam pemaksaan urutan deterministik oleh pihak luar.
   - **Strict Session Quota:** Batasi panjang sesi kueri sehingga analisis pola sliding window tidak dapat dilakukan secara eksploitatif.
