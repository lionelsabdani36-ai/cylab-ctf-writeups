# Writeup: Flags (Challenge ID: 31)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Visual Substitution Cipher & International Maritime Signal Flags (ICS)
- **Difficulty:** Medium (diff=2)
- **Author:** Danny
- **Event:** picoCTF 2019
- **Points:** 200
- **Flag:** `picoCTF{F1AG5AND5TUFF}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan identifikasi cipher visual dan pengenalan sistem pengkodean simbolik non-standar:
> *"What do the flags mean?"*
> Artefak: `flag.png`
> Petunjuk: *The flag is in the format PICOCTF{}*

Peserta diberikan berkas citra berformat Portable Network Graphics (PNG) bernama `flag.png`. Citra menampilkan serangkaian bendera maritim geometris warna-warni yang disusun dalam dua baris, dipisahkan oleh simbol kurung kurawal `{` dan ditutup oleh `}`. Peserta diarahkan untuk mengidentifikasi sistem standar komunikasi maritim yang digunakan dan mendekode bendera menjadi karakter teks Latin.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Kode Sinyal Internasional / International Code of Signals (ICS):**
   - ICS adalah sistem internasional resmi yang dikelola oleh International Maritime Organization (IMO / konvensi SOLAS) untuk komunikasi visual antar kapal dan otoritas pelabuhan.
   - Sistem ini mendefinisikan bendera khusus untuk:
     - 26 Huruf Latin alfabetik (Alfa hingga Zulu), masing-masing dengan pola geometris distingtif (kombinasi warna primer putih, biru, merah, kuning, dan hitam).
     - 10 Pennant numerik (0 hingga 9) berbentuk trapesium atau segitiga terpotong (*pennant shape*).
     - 3 Pengulang (*substitutes*) dan bendera penjawab.

2. **Kriptanalisis Visual Substitution Cipher:**
   - Dalam terminologi kriptografi klasik, tantangan ini merupakan varian dari *Monoalphabetic Substitution Cipher*, di mana setiap alfabet atau angka dipetakan secara statis 1-ke-1 ($f: \Sigma \to \mathcal{S}$) ke simbol grafis bendera maritim.
   - Karena panjang awalan bendera sebelum tanda kurung kurawal `{` berjumlah tepat 7 karakter, analisis frekuensi posisi mengonfirmasi pola format standar kompetisi:
     $$\text{Bendera 1-7} \implies \text{P-I-C-O-C-T-F}$$
   - Analisis bendera awalan:
     - **Papa:** Kotak biru dengan persegi panjang putih di tengah $\to$ `P`
     - **India:** Bidang kuning dengan lingkaran hitam di tengah $\to$ `I`
     - **Charlie:** 5 garis horizontal (Biru-Putih-Merah-Putih-Biru) $\to$ `C`
     - **Oscar:** Garis diagonal (Merah di kanan atas, Kuning di kiri bawah) $\to$ `O`
     - **Charlie:** $\to$ `C`
     - **Tango:** 3 garis vertikal (Merah-Putih-Biru) $\to$ `T`
     - **Foxtrot:** Bidang putih dengan belah ketupat merah $\to$ `F`

3. **Kelemahan Cipher Substitusi Monografis Sesuai Standar NIST SP 800-115:**
   - NIST SP 800-115 (Section 5.3: *Cryptographic Assessment*) menegaskan bahwa cipher berbasis pemetaan karakter statis atau obfuskasi visual tidak menyediakan properti *diffusion* atau *confusion* (prinsip Shannon).
   - Masalah ini diklasifikasikan sebagai CWE-327 (*Use of a Broken or Risky Cryptographic Algorithm*). Ketiadaan kunci rahasia (*cryptographic key*) dan entropi pseudorandom membuat teks sandi dapat dipecahkan secara instan hanya dengan mencocokkan tabel publik (ICS standard table).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Artefak Berkas:**
   Unduh citra resmi dari repositori aset tantangan:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/187296d0c352a8451662153842fc9794b9f247a1ac949978113ddfcb9a1bb76f/flag.png
   ```

2. **Pemeriksaan Visual & Pemetaan Simbol Baris Kedua (Isi Flag):**
   Setelah baris pertama didekodekan sebagai `PICOCTF{`, telusuri baris kedua bendera per bendera:
   - **Bendera 1:** Putih dengan belah ketupat merah (Foxtrot) $\to$ `F`
   - **Bendera 2:** Pennant putih dengan lingkaran merah di tengah (Pennant 1) $\to$ `1`
   - **Bendera 3:** Belah vertikal putih di hoist dan biru swallowtail di fly (Alfa) $\to$ `A`
   - **Bendera 4:** 6 garis vertikal kuning dan biru bergantian (Golf) $\to$ `G`
   - **Bendera 5:** Pennant belah vertikal kuning dan biru (Pennant 5) $\to$ `5`
   - **Bendera 6:** Alfa $\to$ `A`
   - **Bendera 7:** 16 petak catur biru dan putih (November) $\to$ `N`
   - **Bendera 8:** 3 garis horizontal kuning-biru-kuning (Delta) $\to$ `D`
   - **Bendera 9:** Pennant 5 $\to$ `5`
   - **Bendera 10:** Tango $\to$ `T`
   - **Bendera 11:** 4 kuadran merah dan putih bersilangan (Uniform) $\to$ `U`
   - **Bendera 12:** Foxtrot $\to$ `F`
   - **Bendera 13:** Foxtrot $\to$ `F`
   - **Penutup:** Simbol tanda kurung tutup $\to$ `}`

3. **Penggabungan String Teks:**
   Menggabungkan seluruh karakter hasil dekode:
   ```text
   picoCTF{F1AG5AND5TUFF}
   ```

4. **Eksekusi Skrip Solver Otomatis:**
   Skrip `scripts/solve_31_flags.py` memuat kamus representasi ICS, memverifikasi header PNG, dan menyusun token secara reproduktif:
   ```bash
   python3 scripts/solve_31_flags.py
   ```
   Keluaran:
   ```text
   [+] Recovered Flag: picoCTF{F1AG5AND5TUFF}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `picoCTF{F1AG5AND5TUFF}`
- **Bukti Validasi REST API CyLab:** Endpoint `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {
    "user": 1072359,
    "challenge": 31,
    "flag": "picoCTF{F1AG5AND5TUFF}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Penerapan pada Modul Cryptography LKS:**
   - Dalam lomba LKS Cyber Security, modul kriptografi kerap mencakup pengenalan sistem pengkodean visual dan historis (Baudot, Semaphore, Pigpen, Morse, ICS Maritime Flags, Braille, hingga DTMF tones).
   - Analis harus memiliki wawasan katalog referensi pengkodean internasional dan mampu mengidentifikasi *known-plaintext anchor* (seperti awalan `picoCTF{` atau `LKS{`) untuk memverifikasi kebenaran pemetaan simbol.

2. **Mitigasi Defensif & Hardening (Modern Cryptographic Standards):**
   - **Hindari Cipher Substitusi Statis:** Jangan pernah menggunakan cipher substitusi atau pengkodean simbolik kustom untuk mengamankan data sensitif atau kredensial rahasia.
   - **Penerapan Algoritma Kriptografi Standar:** Gunakan algoritma kriptografi modern yang telah diaudit secara publik dan tersertifikasi NIST FIPS (misalnya AES-GCM untuk kerahasiaan simetris dan Ed25519/RSA-PSS untuk autentikasi) dengan panjang kunci memadai.
