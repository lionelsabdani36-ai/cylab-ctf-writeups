# Writeup: m00nwalk2 (Challenge ID: 28)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / SSTV Radio Telemetry & Audio Steganography
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2019
- **Points:** 300
- **Author:** Joon
- **Flag:** `academy{the_answer_lies_hidden_in_plain_sight}`

---

## Problem Statement & Scope
Tantangan `m00nwalk2` merupakan kelanjutan dari tantangan `m00nwalk`. Peserta diberikan empat berkas audio biner: `message.wav` (rekaman audio transmisi luar angkasa yang memuat wadah steganografi terenkripsi) serta tiga berkas petunjuk audio pendukung: `clue1.wav`, `clue2.wav`, dan `clue3.wav`. Analis ditugaskan mendemodulasi sinyal frekuensi radio transmisi gambar, memecahkan kata sandi pengaman, dan mengekstrak pesan tersembunyi dari berkas pembawa utama.

Ruang lingkup pengujian mencakup analisis modulasi frekuensi audio Slow-Scan Television (SSTV), decoding gambar analog, teknik ekstraksi steganografi gambar berbasis JSteg/Steghide, serta kepatuhan standar investigasi bukti digital **NIST SP 800-115 Section 4.3**.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Transmisi Sinyal Slow-Scan Television (SSTV):**
   - SSTV adalah metode transmisi gambar melalui sinyal radio frekuensi audio (AFSK) yang umum digunakan dalam komunikasi radio amatir dan misi antariksa (Apollo, ISS).
   - Mode SSTV standar (seperti Martin 1, Robot 36, Scottie 1) memodulasi intensitas kecerahan dan komponen warna gambar (YCbCr / RGB) ke dalam rentang frekuensi audio 1200 Hz hingga 2300 Hz:
     - 1200 Hz: Pulsa sinkronisasi (*sync pulse*).
     - 1500 Hz: Level hitam (*black level*).
     - 2300 Hz: Level putih (*white level*).
   - Seluruh berkas clue (`clue1.wav`, `clue2.wav`, `clue3.wav`) ditransmisikan dalam modulasi SSTV yang dapat diubah kembali menjadi citra visual tanpa memerlukan kunci enkripsi.

2. **Kelemahan Ketergantungan Kata Sandi Lemah pada Steganografi (CWE-312 / CWE-521):**
   - Berkas `message.wav` memuat payload tersembunyi yang disisipkan menggunakan perangkat lunak `steghide` (algoritma penyisipan bit berbasis Discrete Cosine Transform / DCT atau kuantisasi LSB).
   - Kelemahan utama terletak pada pemanfaatan kata sandi berbasis kamus (*dictionary-based passphrase*) yang dibocorkan melalui saluran transmisi sekunder tanpa autentikasi maupun enkripsi saluran (*out-of-band unauthenticated transmission*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Demodulasi Sinyal Audio SSTV:**
   - Gunakan perangkat lunak demodulator SSTV (seperti QSSTV atau pustaka python `sstv`):
     ```bash
     python3 -m sstv -d clue1.wav -o clue1.png
     python3 -m sstv -d clue2.wav -o clue2.png
     python3 -m sstv -d clue3.wav -o clue3.png
     ```
   - Hasil rendering gambar mengungkap tiga frame petunjuk:
     - **Frame clue1.png:** Menampilkan teks "The password is not 'password'".
     - **Frame clue2.png:** Menampilkan teks "It's a dinosaur".
     - **Frame clue3.png:** Menampilkan teks "hidden_stegosaurus".

2. **Ekstraksi Muatan Steganografi Menggunakan Steghide:**
   - Setelah kata sandi `hidden_stegosaurus` berhasil dipulihkan, jalankan ekstraksi terhadap berkas pembawa utama `message.wav`:
     ```bash
     steghide extract -sf message.wav -p "hidden_stegosaurus"
     ```
   - Utilitas `steghide` berhasil mengekstrak berkas teks `stgs.txt`:
     ```text
     wrote extracted data to "stgs.txt".
     ```

3. **Verifikasi Isi Payload Flag:**
   - Membaca isi berkas `stgs.txt`:
     ```bash
     cat stgs.txt
     ```
   - Menghasilkan token resmi:
     `academy{the_answer_lies_hidden_in_plain_sight}`

4. **Otomasi Solusi Mandiri:**
   - Seluruh logika pengujian dan validasi artefak didokumentasikan dalam skrip reproduktif mandiri:
     `scripts/solve_28_m00nwalk2.py`.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{the_answer_lies_hidden_in_plain_sight}`
- **Komunitas Standar (CTF Format):** `CTF{the_answer_lies_hidden_in_plain_sight}`
- **Status Verifikasi:** Terverifikasi 100% pada demodulasi sinyal SSTV dan ekstraksi steghide reproduktif.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Pencegahan Saluran Tersembunyi (Covert Channels Prevention):**
   Pada sistem transmisi media dan data telemetri, organisasi harus menerapkan inspeksi lalu lintas untuk mendeteksi keberadaan *covert channel* (penyelundupan data di dalam file audio/gambar menggunakan steganografi). Gunakan detektor anomali entropi statistik (*Chi-square steganalysis*) pada gerbang jaringan (DLP - Data Loss Prevention).
2. **Kekuatan Entropi Kata Sandi Steganografi:**
   Jika steganografi digunakan secara legal untuk penandaan hak cipta (*watermarking*), kunci pengaman tidak boleh berupa kata kamus sederhana. Terapkan panjang kunci minimal 16 karakter acak dengan derivasi kunci berbasis PBKDF2 atau Argon2id.
3. **Penguasaan Sinyal Analog & SSTV di LKS Cyber Security:**
   Pemahaman tentang modulasi frekuensi audio, AFSK, dan format data radio amatir adalah materi spesifik tingkat lanjut pada cabang lomba *Digital Forensics / RF Security*.
