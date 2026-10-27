# Writeup: vault-door-3 (Challenge ID: 60)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Permutation Inversion
- **Difficulty:** Medium
- **Author:** Mark E. Haase
- **Event:** picoCTF 2019
- **Points:** 200
- **Flag:** `academy{jU5t_a_s1mpl3_an4gr4m_4_u_bfac26}`

---

## Problem Statement & Scope
Diberikan berkas program Java `VaultDoor3.java`. Fungsi validasi menerima string masukan 32 karakter dan memprosesnya ke dalam array `buffer` berukuran 32 karakter melalui empat tahapan iterasi loop terpisah. Peserta diminta membalikkan transformasi permutasi posisi array tersebut untuk mendapatkan string kata sandi yang cocok dengan target: `jU5t_a_sna_3lpm12ga4b_u_4_mfrc46`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Analisis Permutasi Deterministik (Bijective Index Mapping):** Seluruh operasi penyalinan elemen dari `password` ke `buffer` merupakan pemetaan bijektif 1-ke-1 tanpa manipulasi nilai biner (tanpa XOR atau substitusi karakter). 
   - Loop 1: $i \in [0, 7] \implies \text{buffer}[i] = \text{password}[i]$
   - Loop 2: $i \in [8, 15] \implies \text{buffer}[i] = \text{password}[23 - i]$
   - Loop 3: $i \in [16, 31], \text{step}=2 \implies \text{buffer}[i] = \text{password}[46 - i]$
   - Loop 4: $i \in [31, 17], \text{step}=-2 \implies \text{buffer}[i] = \text{password}[i]$
2. **Kelemahan Transposisi Murni:** Cipher transposisi murni (anagram/permutasi urutan) mempertahankan frekuensi karakter asli dan sangat rentan terhadap rekonstruksi pemetaan inversi $f^{-1}(\text{index})$.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis target string $T = \text{"jU5t_a_sna_3lpm12ga4b_u_4_mfrc46"}$.
2. Telusuri pemetaan mundur ke dalam array `password`:
   - Rentang 0..7: $P[i] = T[i]$ untuk $i = 0 \dots 7$.
   - Rentang 8..15: $P[23 - i] = T[i]$ untuk $i = 8 \dots 15$.
   - Rentang genap 16..30: $P[46 - i] = T[i]$ untuk $i = 16, 18, \dots, 30$.
   - Rentang ganjil 31..17: $P[i] = T[i]$ untuk $i = 31, 29, \dots, 17$.
3. Evaluasi hasil rekonstruksi:
   `jU5t_a_s1mpl3_an4gr4m_4_u_bfac26`
4. Flag resmi: `academy{jU5t_a_s1mpl3_an4gr4m_4_u_bfac26}`.
5. Eksekusi skrip otomasi:
   ```bash
   python3 scripts/solve_60_vault_door_3.py
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{jU5t_a_s1mpl3_an4gr4m_4_u_bfac26}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Transposisi Data Bukan Pengamanan:** Teknik mengacak posisi memori atau buffer array (transposition) mudah dibalikkan oleh reverse engineer menggunakan *symbolic execution* atau pencatatan tracing indeks.
- **Implementasi Enkripsi Blok Modern:** Untuk melindungi data rahasia dalam memori aplikasi, gunakan mekanisme *authenticated encryption* (seperti AES-GCM) dengan manajemen kunci terisolasi pada keystore sistem operasi.
