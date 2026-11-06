# Writeup: m00nwalk (Challenge ID: 26)

- Platform: CyLab Security Academy (picoCTF)
- Category: Forensics / SSTV (Slow Scan Television) Signal Demodulation
- Difficulty: Medium (diff=2)
- Author: Joon
- Event: picoCTF 2019
- Points: 250
- Flag: `picoCTF{beep_boop_im_in_space}` (Komunitas: `CTF{beep_boop_im_in_space}`)

---

## Problem Statement & Scope

Tantangan menguji pemahaman forensik transmisi radio/sinyal audio analog dan modulasi citra retro:
> *"Decode this message from the moon: message.wav"*  
>  
> Petunjuk:  
> 1. *"How did pictures from the moon landing get sent back to Earth?"*  
> 2. *"What is the CMU mascot?, that might help select a RX option"*

Lingkup pengujian mencakup identifikasi struktur sinyal audio analog WAV 48 kHz mono, analisis modulasi pita frekuensi radio amatir SSTV (Slow Scan Television), pemilihan mode transmisi berdasarkan petunjuk maskot Carnegie Mellon University (*Scotty the Scottish Terrier* -> mode Scottie 1), dan rekonstruksi raster piksel RGB citra tersembunyi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Prinsip Modulasi Slow Scan Television (SSTV):**
   - SSTV adalah metode transmisi faksimili pita sempit yang digunakan oleh operator radio amatir dan misi antariksa (seperti Apollo 11) untuk mengirimkan citra statis melalui kanal audio analog.
   - Sinyal SSTV menggunakan modulasi frekuensi analog di mana nilai kecerahan dan warna piksel dipetakan ke frekuensi audio tertentu dalam rentang 1200 Hz hingga 2300 Hz:
     - 1200 Hz: Pulsa sinkronisasi horizontal/vertikal (*Sync Pulse*).
     - 1500 Hz: Level hitam (*Black Level*).
     - 2300 Hz: Level putih (*White Level*).
   - Nada kalibrasi VIS (*Vertical Interval Signaling*) pada awal rekaman mengidentifikasi varian protokol transmisi.

2. **Mode Transmisi Scottie 1:**
   - Sesuai petunjuk *"CMU mascot"* (Scotty), mode yang digunakan adalah **Scottie 1**.
   - Mode Scottie 1 mentransmisikan citra beresolusi $320 \times 256$ piksel dengan urutan scanline: pulsa sinkronisasi, scanline hijau (Green), pulsa sinkronisasi singkat, scanline biru (Blue), dan scanline merah (Red). Waktu pemindaian per baris sekitar 428 milidetik dengan durasi total transmisi sekitar 110 detik.

3. **CWE-319 (Cleartext Transmission of Sensitive Information):**
   - Transmisi data gambar dilakukan melalui kanal analog tanpa enkripsi atau tanda tangan integritas. Siapapun yang menangkap gelombang radio atau rekaman audio dapat memulihkan seluruh konten gambar secara deterministik.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Berkas Audio:**
   Memeriksa karakteristik berkas WAV yang diunduh dari pustaka CyLab:
   ```bash
   file message.wav
   # Luaran: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 48000 Hz
   ```

2. **Demodulasi Sinyal SSTV Menggunakan Library Python:**
   Menggunakan modul `sstv` untuk mendeteksi header kalibrasi dan mendemodulasi sinyal audio menjadi berkas citra PNG:
   ```bash
   python3 -m sstv -d message.wav -o decoded_moon.png
   ```
   Pustaka berhasil menemukan header kalibrasi dan mengenali format `Scottie 1`:
   ```text
   [sstv] Searching for calibration header... Found!
   [sstv] Detected SSTV mode Scottie 1
   [sstv] Decoding image... [##############################################] 100%
   [sstv] Drawing image data... Done!
   ```

3. **Ekstraksi Teks Flag dari Citra Hasil:**
   Citra yang dipulihkan menampilkan gambar astronot di permukaan bulan dengan teks cetak banner di bagian bawah:
   ```text
   picoCTF{beep_boop_im_in_space}
   ```

4. **Verifikasi Skrip Solusi:**
   Skrip otomasi dieksekusi melalui `scripts/solve_26_m00nwalk.py`:
   ```bash
   python3 scripts/solve_26_m00nwalk.py
   # Luaran: picoCTF{beep_boop_im_in_space}
   ```

---

## Flag & Verifikasi

- **Flag:** `picoCTF{beep_boop_im_in_space}`
- **Komunitas:** `CTF{beep_boop_im_in_space}`
- **Bukti Validasi:** REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 26, "flag": "picoCTF{beep_boop_im_in_space}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi Forensik Sinyal & Media Radio di LKS:**
   - Modul forensik LKS Cyber Security kerap menguji transmisi sinyal non-standar (audio spectrogram analysis, morse code carrier, DTMF tones, dan radio telemetry SSTV/APRS).
   - Peserta harus mampu membedakan karakteristik spektrogram audio digital biasa dengan pola sapuan horizontal SSTV dan modulasi FSK/FM.

2. **Rekomendasi Keamanan Komunikasi Data (Remediation & Hardening):**
   - **Enkripsi Lapisan Transmisi:** Jangan pernah mentransmisikan data operasional atau kredensial penting melalui kanal analog siaran terbuka (*unencrypted analog RF*).
   - **Implementasi Digital Radio Kriptografis:** Gunakan protokol data digital berotentikasi dan terenkripsi kuat (seperti AES-GCM terintegrasi pada modul radio SDR / software defined radio modern) untuk mencegah *eavesdropping* dan manipulasi sinyal (*spoofing/replay*).
