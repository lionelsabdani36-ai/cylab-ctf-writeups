# Writeup: PowerAnalysis: Part 1 (Challenge ID: 364)

- **Platform:** CyLab Security Academy (picoCTF 2023)
- **Category:** Cryptography / Correlation Power Analysis (CPA)
- **Difficulty:** Hard
- **Playlist:** Cryptography and Challenge Library Learning Intro (Module 143)
- **Points:** 400
- **Flag:** `academy{b13adff8b4d1a89da8ba668043276276}`

---

## Deskripsi Tantangan
> This embedded system allows you to measure the power consumption of the CPU while it is running an AES encryption algorithm. Use this information to leak the key via dynamic power analysis.
> Running server: `nc chatelaine.cylabacademy.net 26874`

---

## Metodologi Correlation Power Analysis (CPA)
Server mengembalikan trace konsumsi daya CPU (2666 titik sampel) untuk setiap blok plaintext yang dikirim.
Konsumsi daya pada tahap substitusi S-box putaran 1 berkorelasi kuat dengan Hamming weight dari nilai perantara:
$$H_{i, k} = \text{HW}(\text{Sbox}[p_i \oplus k])$$

### Langkah Eksekusi Solver
1. Mengumpulkan 150 trace pengukuran dengan plaintext acak 16-byte dari server.
2. Memfokuskan jendela analisis pada titik sampel $t \in [300, 400]$ (eksekusi S-Box putaran pertama AES).
3. Menghitung koefisien korelasi Pearson antara model Hamming weight untuk 256 kandidat kunci dengan trace aktual:
   $$\rho(k) = \max_{t \in [300, 400]} \left| \frac{\text{cov}(H_k, T_t)}{\sigma_{H_k} \sigma_{T_t}} \right|$$
4. Kandidat kunci dengan korelasi tertinggi (margin $\Delta > 0.15$ terhadap kandidat kedua) dipilih untuk tiap byte.

Kunci terekonstruksi: `b13adff8b4d1a89da8ba668043276276`.

Flag: `academy{b13adff8b4d1a89da8ba668043276276}`.
