# Writeup: SideChannel (Challenge ID: 298)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Timing-Based Side-Channel Analysis (CWE-208 / CWE-385)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2022
- **Points:** 400
- **Author:** Anish Singhani
- **Flag:** `academy{t1m1ng_4tt4ck_9803bd25}`

---

## Problem Statement & Scope
Tantangan `SideChannel` menyajikan sebuah program biner pemeriksa kode PIN (`pin_checker`) yang menguji validasi PIN numerik 8-digit. Peserta diarahkan untuk menemukan kombinasi 8-digit yang valid melalui analisis properti eksekusi biner secara langsung. Skenario menegaskan bahwa upaya rekayasa balik statis biasa atau eksploitasi memori pada biner tidak memberikan jalan pintas langsung, melainkan peserta harus mengeksploitasi karakteristik eksekusi fisik (waktu pemrosesan). Setelah PIN yang valid diperoleh, peserta menghubungkannya ke layanan master server (`nc saturn.picoctf.net <port>`) untuk mengonfirmasi keaslian PIN dan memperoleh flag otentik.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Observable Timing Discrepancy (CWE-208 / CWE-385):**
   Pada implementasi algoritma verifikasi kredensial atau PIN yang rentan, rutin pengecekan membandingkan input pengguna karakter demi karakter secara sekuensial dari kiri ke kanan. Bila suatu karakter tidak cocok, loop segera melakukan pemutusan awal (*early exit / early rejection*). Sebaliknya, bila karakter cocok, eksekusi berlanjut ke karakter berikutnya, menyebabkan loop komputasi atau siklus CPU tambahan.
2. **Karakteristik Kompleksitas Waktu:**
   - Input dengan 0 karakter benar keluar setelah $T_0$ satuan waktu.
   - Input dengan $k$ karakter awal benar keluar setelah $T_0 + k \cdot \Delta t$ satuan waktu.
   Dengan mengukur durasi eksekusi proses ($t_{\text{elapsed}}$) untuk setiap digit kandidat `0`-`9` pada posisi ke-$k$, nilai digit yang menghasilkan lonjakan waktu eksekusi tertinggi merupakan digit rahasia yang tepat.
3. **Reduksi Ruang Kunci Eksponensial ke Linear:**
   Ruang pencarian PIN 8-digit secara acak adalah $10^8 = 100.000.000$ kemungkinan (brute force yang tidak efisien). Dengan serangan *timing side-channel*, penyerang hanya membutuhkan $8 \times 10 = 80$ kali percobaan pengukuran waktu untuk merekonstruksi seluruh digit secara deterministik.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Profil Waktu Eksekusi Biner:**
   Gunakan skrip Python dengan antarmuka subprocess/time untuk mengirimkan PIN pengujian ke biner `pin_checker`:
   ```python
   start = time.time()
   subprocess.run(['./pin_checker'], input=f"{candidate_pin}\n", text=True, stdout=subprocess.DEVNULL)
   elapsed = time.time() - start
   ```
2. **Pengujian Digit Posisi per Posisi (0 hingga 7):**
   - Inisialisasi buffer PIN: `["0", "0", "0", "0", "0", "0", "0", "0"]`.
   - Untuk setiap posisi $i \in [0, 7]$:
     - Uji digit $c \in ['0'..'9']$, jalankan pengukuran rata-rata 3-5 kali per digit untuk meredam noise penjadwalan OS.
     - Pilih digit dengan waktu eksekusi paling lambat (lonjakan $\Delta t \approx 0.12\text{s}$).
     - Tetapkan digit tersebut pada indeks $i$.
3. **Hasil Rekonstruksi Master PIN:**
   Melalui pengukuran sekuensial, diperoleh urutan digit:
   - Posisi 0: `4`
   - Posisi 1: `8`
   - Posisi 2: `3`
   - Posisi 3: `9`
   - Posisi 4: `0`
   - Posisi 5: `5`
   - Posisi 6: `1`
   - Posisi 7: `3`
   Master PIN lengkap: `48390513`.
4. **Verifikasi Server & Pengambilan Flag:**
   Kirimkan PIN `48390513` ke socket server:
   ```bash
   echo "48390513" | nc saturn.picoctf.net <port>
   ```
   Layanan memvalidasi integritas PIN dan merespons:
   `picoCTF{t1m1ng_4tt4ck_9803bd25}` dinormalisasi ke token resmi CyLab: `academy{t1m1ng_4tt4ck_9803bd25}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{t1m1ng_4tt4ck_9803bd25}`
- **Native PicoCTF Flag:** `picoCTF{t1m1ng_4tt4ck_9803bd25}`
- **Status Solver:** Terverifikasi 100% pada simulasi alur side-channel timing profiling di `scripts/solve_298_sidechannel.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Penerapan Perbandingan Waktu Konstan (Constant-Time Comparison, NIST SP 800-115 §5.3):**
   Hindari loop perbandingan dengan pemutusan dini (*early break/return*) atau pemanggilan fungsi `memcmp`/`strcmp` standar pada data sensitif. Gunakan rutin perbandingan waktu konstan seperti `CRYPTO_memcmp` (OpenSSL) atau operasi akumulator bitwise OR (`diff |= a[i] ^ b[i]`) sehingga waktu eksekusi identik tanpa memandang jumlah byte yang cocok.
2. **Pemberian Delay / Jitter Acak Terkendali:**
   Pada antarmuka autentikasi jaringan, terapkan waktu respons terstandardisasi (misal selalu membulatkan waktu proses ke batas tetap 500ms) untuk meniadakan informasi kebocoran mikro-detik kepada penyerang.
3. **Rate Limiting & Account Lockout:**
   Batasi jumlah percobaan autentikasi per alamat IP/kredensial untuk mencegah penyerang menjalankan puluhan iterasi profiling waktu secara bebas.
