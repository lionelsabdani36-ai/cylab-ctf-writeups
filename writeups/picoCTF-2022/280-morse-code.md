# Writeup: morse-code (Challenge ID: 280)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Audio Signal Analysis & Morse Code Demodulation
- **Difficulty:** Medium
- **Author:** Will Hong
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{WH47_H47H_90D_W20U9H7}`

---

## Problem Statement & Scope
Diberikan sebuah berkas rekaman audio mono dalam format Microsoft PCM WAV 16-bit 44.1 kHz (`morse_chal.wav`). Audio berisi sinyal nada termodulasi (*continuous wave audio*) yang merepresentasikan pesan sandi Morse. Analis diminta mendemodulasi sinyal audio, mengekstrak kombinasi titik (*dot*) dan garis (*dash*), menerjemahkannya ke representasi teks, serta membungkusnya dalam format token resmi `academy{...}` dengan spasi diganti garis bawah (*underscore*) dan huruf kapital.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Representasi Sinyal Audio & Morse Code Timing Standards:** Sandi Morse Internasional (ITU-R M.1677-1) menggunakan rasio durasi berbasis unit waktu dasar $T$:
   - **Dit / Dot (`.`):** $1T$ durasi sinyal aktif.
   - **Dah / Dash (`-`):** $3T$ durasi sinyal aktif.
   - **Inter-element space:** $1T$ jeda hening antar elemen dalam satu karakter.
   - **Inter-character space:** $3T$ s.d. $4T$ jeda hening antar karakter.
   - **Inter-word space:** $7T$ s.d. $8T$ jeda hening antar kata.
2. **Signal Energy Detection (Root-Mean-Square):** Dengan membagi sinyal PCM diskrit menjadi jendela waktu kecil ($10\text{ ms} = 441\text{ sampel}$ pada laju $44.1\text{ kHz}$), energi RMS dihitung sebagai $\text{RMS} = \sqrt{\frac{1}{N}\sum x_i^2}$. Komparasi terhadap ambang batas deteksi ($\text{threshold} \approx 10000$) menghasilkan deret diskrit biner (1 untuk nada aktif, 0 untuk hening).
3. **Run-Length Encoding (RLE) & Parsing:** Penerapan RLE mengelompokkan durasi sinyal ke dalam interval unit:
   - Aktif 10 unit ($100\text{ ms}$) $\rightarrow$ dot (`.`).
   - Aktif 30 unit ($300\text{ ms}$) $\rightarrow$ dash (`-`).
   - Hening 40 unit ($400\text{ ms}$) $\rightarrow$ pembatas karakter (*letter boundary*).
   - Hening 80 unit ($800\text{ ms}$) $\rightarrow$ pembatas kata (*word boundary* / `_`).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis properti berkas audio:
   ```bash
   file morse_chal.wav
   # morse_chal.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 44100 Hz
   ```
2. Ekstraksi urutan sinyal nada dan jeda melalui inspeksi kuantisasi RLE Python:
   ```text
   .--   -> W
   ....  -> H
   ....- -> 4
   --... -> 7 [JEDA KATA]
   ....  -> H
   ....- -> 4
   --... -> 7
   ....  -> H [JEDA KATA]
   ----. -> 9
   ----- -> 0
   -..   -> D [JEDA KATA]
   .--   -> W
   ..--- -> 2
   ----- -> 0
   ..-   -> U
   ----. -> 9
   ....  -> H
   --... -> 7
   ```
3. Rekonstruksi kata leetspeak:
   - Kata 1: `WH47`
   - Kata 2: `H47H`
   - Kata 3: `90D`
   - Kata 4: `W20U9H7`
4. Gabungkan kata dengan pemisah *underscore* sesuai instruksi tantangan:
   $$\text{academy\{WH47\_H47H\_90D\_W20U9H7\}}$$

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{WH47_H47H_90D_W20U9H7}`
- **Verifikasi:** Endpoint REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 280, "flag": "academy{WH47_H47H_90D_W20U9H7}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Otomasi Pemrosesan Sinyal Tanpa GUI:** Peserta lomba LKS Cyber Security sering kali mengandalkan alat visual GUI seperti Audacity atau Sonic Visualiser yang membutuhkan waktu lama untuk menyeleksi dan mencatat tiap karakter manual. Penguasaan skrip demodulasi berbasis pustaka standar (`wave`, `struct`) memungkinkan ekstraksi data audio berkecepatan tinggi dalam hitungan detik.
- **Kerahasiaan Data & Obfuskasi Sinyal (Acoustic Steganography):** Pengiriman data dalam format modulasi audio polos (*unencrypted audible carrier*) rentan disadap dan didekode oleh pihak ketiga melalui perekaman pasif. Transmisi radio atau akustik wajib dilindungi enkripsi kriptografis modern (seperti AES-GCM) sebelum dimodulasi ke saluran fisik.

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_280_morse_code.py`.

