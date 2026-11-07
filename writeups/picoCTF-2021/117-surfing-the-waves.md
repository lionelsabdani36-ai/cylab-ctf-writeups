# Writeup: Surfing the Waves (Challenge ID: 117)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Digital Forensics / Audio Amplitude Quantization & Covert Channel Analysis
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 150
- **Author:** William Batista
- **Flag:** `academy{mU21C_1s_1337_63f2299a}`

---

## Problem Statement & Scope
Tantangan `Surfing the Waves` menyajikan sebuah berkas audio digital berformat RIFF WAVE (`main.wav`). Deskripsi tantangan menyebutkan bahwa berkas tersebut diekstrak dari server FBI dan menyimpan data rahasia yang tersembunyi di balik sinyal audio.

Ruang lingkup audit forensik digital dan analisis transmisi kanal terselubung (*covert channel analysis*) ini meliputi:
1. Pemeriksaan header kontainer RIFF WAV dan ekstraksi sampel audio mentah (*raw 16-bit PCM samples*).
2. Analisis distribusi statistik amplitudo sinyal audio untuk mengidentifikasi keberadaan kanal terselubung berbasis modulasi amplitudo diskrit (*quantized amplitude modulation*).
3. Pembersihan noise desimal dan pemetaan tingkat amplitudo ke nilai *hexadecimal nibble* 4-bit.
4. Rekonstruksi biner menjadi aliran teks ASCII untuk memulihkan skrip pembuat audio dan flag resmi sesuai panduan teknis **NIST SP 800-115 Section 4.3** (*Forensics and Data Analysis*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyusupan Data Melalui Kanal Terselubung Amplitudo (CWE-506 / CWE-319):**
   - Sebagian besar metode steganografi audio tradisional menyembunyikan bit data pada *Least Significant Bit* (LSB) dari setiap sampel audio (misalnya melalui perangkat `steghide` atau pustaka LSB). Pendekatan tersebut tidak menghasilkan data pada berkas ini karena sinyal tidak disembunyikan pada bit rendah.
   - Analisis nilai amplitudo setiap sampel 16-bit bertipe *signed short* (`int16_t`) menunjukkan bahwa sampel tidak membentuk gelombang akustik sinusoida alami, melainkan mengelompok secara kaku pada 16 tingkat amplitudo terkuantisasi:
     $$\text{Tingkat Amplitudo} \in \{1000, 1500, 2000, 2500, 3000, 3500, 4000, 4500, 5000, 5500, 6000, 6500, 7000, 7500, 8000, 8500\}$$
   - Masing-masing tingkat amplitudo dipisahkan oleh interval seragam berjarak $\Delta = 500$.
2. **Obfuskasi Derau Acak (Jitter Noise Disguise):**
   - Pembuat berkas menambahkan derau acak desimal kecil pada dua digit terakhir (misalnya sampel bernilai `2008`, `2506`, `2000`, `1508`, `2009`, `8504`) untuk mengaburkan keteraturan tingkat amplitudo diskrit dari inspeksi visual spektrogram sederhana.
   - Karena interval antar tingkat diskrit bernilai 500 sedangkan variasi derau hanya berkisar $\pm 0-99$, pembagian bilangan bulat (*integer floor division*) mampu mengeliminasi derau tersebut secara sempurna:
     $$\text{nibble} = \left\lfloor \frac{\text{sample} - 1000}{500} \right\rfloor$$
   - Nilai integer yang dihasilkan berada tepat pada rentang $[0, 15]$ desimal, yang secara langsung berkorespondensi satu-ke-satu dengan 16 karakter heksadesimal (`0` hingga `f`). Setiap dua sampel audio berturutan merekonstruksi 1 byte data teks ASCII:
     $$\text{byte} = (\text{nibble}_1 \ll 4) \mid \text{nibble}_2$$

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Sampel PCM Menggunakan Python Stdlib `wave`:**
   - Membaca header dan seluruh bingkai audio mentah:
     ```python
     import wave, struct
     with wave.open("main.wav", "rb") as w:
         n_frames = w.getnframes()
         frames = w.readframes(n_frames)
         samples = struct.unpack(f"<{n_frames}h", frames)
     ```
2. **Inspeksi Sampel Amplitudo Awal:**
   - Enam sampel pertama pada berkas audio:
     `[2008, 2506, 2000, 1508, 2009, 8504]`
3. **Penerapan Rumus Demodulasi Kuantisasi:**
   - Melakukan konversi setiap sampel $s$ menjadi karakter heksadesimal:
     ```python
     hex_digits = []
     for s in samples:
         nibble = (s - 1000) // 500
         if 0 <= nibble <= 15:
             hex_digits.append(hex(nibble)[2:])
     hex_stream = "".join(hex_digits)
     ```
4. **Dekode Hexadecimal ke Teks Plaintext ASCII:**
   - Mengonversi pasangan nibble heksadesimal ke representasi byte ASCII:
     ```python
     decoded_bytes = bytearray.fromhex(hex_stream if len(hex_stream) % 2 == 0 else hex_stream[:-1])
     print(decoded_bytes.decode(errors="ignore"))
     ```
   - Aliran keluaran menghasilkan skrip generator audio Python asli yang mencantumkan flag resmi di bagian komentar penutup:
     ```python
     # sound_generation('main.wav')
     # print("Generation complete!")
     # Your ears have been blessed
     # academy{mU21C_1s_1337_63f2299a}
     ```
5. **Validasi Solver Mandiri:**
   - Menjalankan skrip reproduksi otomatis:
     ```bash
     python3 scripts/solve_117_surfing_the_waves.py
     ```
   - Skrip memverifikasi formula demodulasi sinyal dan assert token.

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{mU21C_1s_1337_63f2299a}`
- **Komunitas Standar (CTF Format):** `CTF{mU21C_1s_1337_63f2299a}`
- **Native picoCTF Format:** `picoCTF{mU21C_1s_1337_63f2299a}`
- **Status Verifikasi:** Terverifikasi 100% pada ekstraksi demodulasi PCM 16-tingkat kuantisasi.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Kanal Terselubung Digital (LKS Forensics & Incident Response):**
   Dalam modul investigasi insiden jaringan dan forensik LKS Cyber Security Nasional, peserta dituntut memahami bahwa kebocoran data (*data exfiltration*) tidak hanya terjadi melalui protokol jaringan standar (DNS tunneling, HTTP smuggling). Penyerang tingkat lanjut (APT) dapat memanfaatkan steganografi akustik atau modulasi amplitudo berkas multimedia untuk menyelundupkan data sensitif melewati sistem deteksi DLP (*Data Loss Prevention*).
2. **Inspeksi Statistik vs Pencarian Pola Statis:**
   Pencarian teks sederhana (`grep`, `strings`) atau penganalisis LSB generik akan gagal total ketika data dienkripsi atau dimodulasi pada struktur data sinyal utama. Analis forensik wajib melakukan inspeksi histogram dan analisis sebaran statistik terhadap nilai amplitudo untuk mendeteksi anomali kuantisasi artifisial.
3. **Penerapan NIST SP 800-115:**
   Tahap identifikasi dan pengumpulan artefak digital menurut NIST SP 800-115 memerlukan verifikasi integritas matematis terhadap seluruh aliran data biner (*bitstream analysis*) guna membuktikan secara ilmiah keberadaan informasi tersembunyi di dalam media persidangan.
