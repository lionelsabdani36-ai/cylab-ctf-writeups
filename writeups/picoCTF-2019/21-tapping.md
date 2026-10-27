# Writeup: Tapping (Challenge ID: 21)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Morse Code Network Telemetry
- **Difficulty:** Medium
- **Author:** Danny
- **Event:** picoCTF 2019
- **Points:** 200
- **Flag:** `academy{m0rs3c0d31sfun178da798}`

---

## Problem Statement & Scope
Disediakan sebuah instance lab edukasi berbasis TCP socket on-demand (`nc xebec.cylabacademy.net <port>`). Ketika koneksi terbuka, server memancarkan aliran sinyal kode Morse yang berulang. Analis diminta untuk mendengarkan lalu lintas tersebut, mendekomposisikan sinyal titik-garis, dan mendekodekan pesan rahasia yang tersembunyi.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Prinsip Kode Morse Internasional (ITU-R M.1677-1):**
   Kode Morse merepresentasikan huruf alfabet Latin dan angka Arab menggunakan kombinasi sinyal pendek (titik/`dit` / `.`) dan sinyal panjang (garis/`dah` / `-`).
2. **Ketiadaan Kerahasiaan Kriptografis pada Protokol Sinyal:**
   Meskipun kode Morse sering diasosiasikan dengan transmisi militer atau radio amatir kuno, kode Morse murni merupakan skema *channel encoding* (modulasi amplitudo/audio sederhana), bukan *cipher*. Semua pihak yang dapat menangkap sinyal radio/jaringan dapat mendekodekan pesan tanpa memerlukan kunci rahasia (*zero confidentiality*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Nyalakan instance tantangan melalui endpoint REST API:
   ```bash
   PUT /api/challenges/21/instance/
   ```
2. Hubungkan koneksi soket jaringan ke port yang disediakan:
   ```bash
   nc xebec.cylabacademy.net 31078
   ```
3. Tangkap aliran data teks:
   ```text
   .- -.-. .- -.. . -- -.-- { -- ----- .-. ... ...-- -.-. ----- -.. ...-- .---- ... ..-. ..- -. .---- --... ---.. -.. .- --... ----. ---.. }
   ```
4. Lakukan pemetaan tabel ITU Morse ke karakter teks:
   - `.-` $\rightarrow$ `A`
   - `-.-.` $\rightarrow$ `C`
   - `.-` $\rightarrow$ `A`
   - `-..` $\rightarrow$ `D`
   - `.` $\rightarrow$ `E`
   - `--` $\rightarrow$ `M`
   - `-.--` $\rightarrow$ `Y`
   - Bagian isi:
     - `--` $\rightarrow$ `M`
     - `-----` $\rightarrow$ `0`
     - `.-.` $\rightarrow$ `R`
     - `...` $\rightarrow$ `S`
     - `...--` $\rightarrow$ `3`
     - `-.-.` $\rightarrow$ `C`
     - `-----` $\rightarrow$ `0`
     - `-..` $\rightarrow$ `D`
     - `...--` $\rightarrow$ `3`
     - `.----` $\rightarrow$ `1`
     - `...` $\rightarrow$ `S`
     - `..-.` $\rightarrow$ `F`
     - `..-` $\rightarrow$ `U`
     - `-.` $\rightarrow$ `N`
     - `.----` $\rightarrow$ `1`
     - `--...` $\rightarrow$ `7`
     - `---..` $\rightarrow$ `8`
     - `-..` $\rightarrow$ `D`
     - `.-` $\rightarrow$ `A`
     - `--...` $\rightarrow$ `7`
     - `----.` $\rightarrow$ `9`
     - `---..` $\rightarrow$ `8`
5. Susun flag resmi (huruf kecil):
   `academy{m0rs3c0d31sfun178da798}`
6. Eksekusi solver Python:
   ```bash
   python3 scripts/solve_21_tapping.py
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{m0rs3c0d31sfun178da798}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Enkripsi Saluran Telekomunikasi (Transport Encryption):** Pengiriman sinyal telemetry atau perintah kendali sistem kendali industri (SCADA/ICS) wajib dilapisi dengan protokol enkripsi TLS/IPsec untuk mencegah penyadapan (*eavesdropping*) pada saluran transmisi fisik maupun nirkabel.
- **Isolasi Layanan Jaringan Ephemeral:** Matikan instance container setelah verifikasi selesai (`DELETE /api/challenges/21/instance/`) untuk menghemat sumber daya komputasi dan meminimalkan area permukaan serangan (*attack surface reduction*).
