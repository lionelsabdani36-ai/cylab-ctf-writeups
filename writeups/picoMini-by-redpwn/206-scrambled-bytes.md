# Writeup: scrambled-bytes (Challenge ID: 206)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Predictable PRNG State Reconstruction & Inverse Permutation XOR Carving (CWE-330 / CWE-327)
- **Difficulty:** Hard (diff=3)
- **Event:** picoMini by redpwn
- **Points:** 200
- **Author:** redpwn
- **Flag:** `picoCTF{n0_t1m3_t0_w4st3_5hufflin9_ar0und}`

---

## Problem Statement & Scope
Tantangan `scrambled-bytes` menyajikan skenario investigasi forensik lalu lintas jaringan (*network packet capture analysis*) yang disertai skrip transmisi data Python (`send.py`) dan berkas rekaman paket Wireshark `capture.pcapng`. 

Berdasarkan skrip sumber `send.py`, pengirim membaca berkas rahasia ke dalam buffer byte, menginisialisasi pseudo-random number generator (PRNG) bawaan Python menggunakan waktu saat ini via `random.seed(int(time()))`, lalu mengacak urutan seluruh byte payload menggunakan `random.shuffle(payload)`. Selanjutnya, untuk setiap byte yang telah diacak, skrip mengirimkan satu paket UDP ke alamat tujuan `172.17.0.3:56742` dengan *source port* acak (`random.randrange(65536)`) dan payload 1 byte hasil operasi XOR dengan byte pseudo-random (`b ^ random.randrange(256)`). 

Peserta ditugaskan untuk menganalisis pcap, menyinkronkan status PRNG dengan merekonstruksi seed waktu eksekusi yang tepat, memvalidasi urutan transmisi melalui verifikasi *source port*, membalikkan operasi XOR dan permutasi urutan byte, serta menyusun kembali berkas asli yang menyembunyikan flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penggunaan Pembangkit Bilangan Acak yang Tidak Aman secara Kriptografis (CWE-330):**
   Modul `random` pada Python mengimplementasikan algoritma Mersenne Twister (MT19937). Meskipun efisien untuk simulasi numerik, MT19937 sepenuhnya bersifat deterministik dan tidak dirancang untuk keamanan kriptografis. Jika penyerang mengetahui nilai awal (*seed*), seluruh barisan bilangan acak berikutnya dapat diprediksi secara mutlak.
2. **Kerapuhan Entropi Berbasis Waktu Sistem (Low Entropy Seeding via Epoch Timestamp):**
   Menggunakan `int(time())` sebagai seed menghasilkan ruang kunci yang sangat sempit. Timestamp UNIX dalam satuan detik hanya berubah satu kali per detik ($1 \text{ Hz}$). Penyerang tidak perlu melakukan pencarian *brute-force* besar di ruang bilangan 32-bit atau 64-bit, melainkan cukup mencocokkan waktu pembuatan paket yang terekam dalam metadata berkas pcap.
3. **Kebocoran Status Internal melalui Saluran Samping Port Jaringan (Side-Channel Verification):**
   Sebelum melakukan enkripsi XOR pada data (`b ^ random.randrange(256)`), pengirim mengeksekusi pemanggilan generator acak untuk menentukan nomor port asal: `UDP(sport=random.randrange(65536))`. Nilai *source port* ini terpancar secara telanjang dalam header paket IP/UDP di pcap. Hal ini memberikan *oracle* verifikasi langsung: penyerang dapat memastikan apakah seed tebakan benar tanpa harus menebak isi payload terlebih dahulu.
4. **Sifat Invertibel dari Algoritma Pengacakan Fisher-Yates (Deterministic Permutation Reversal):**
   Fungsi `random.shuffle()` menggunakan variasi modern dari algoritma pengocokan Fisher-Yates. Karena urutan operasi penukaran indeks bergantung sepenuhnya pada panggilan PRNG deterministik, penyerang dapat mengocok daftar indeks identitas `[0, 1, ..., N-1]` dengan generator yang telah disinkronkan untuk memetakan ke mana setiap byte asli berpindah.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Paket UDP Aliran Data Sensitif:**
   Menggunakan filter Wireshark/tshark:
   ```bash
   tshark -r capture.pcapng -Y "ip.src == 172.17.0.2 && ip.dst == 172.17.0.3 && udp.dstport == 56742 && data.len == 1"
   ```
   Ditemukan tepat 1.992 paket UDP payload tunggal yang dimulai pada Frame nomor 1921.
2. **Identifikasi Timestamp & Penentuan Seed PRNG:**
   Pemeriksaan rincian frame pertama (Frame 1921) mencatat:
   - Arrival Time: `Feb 23, 2021 03:44:10.913789387 IST`
   - Epoch Time: `1614044650.913789387` detik
   Nilai integer detik epoch adalah `1614044650`.
3. **Verifikasi Sinkronisasi PRNG melalui Source Port:**
   Menguji generator Python secara lokal dengan seed `1614044650`:
   ```python
   import random
   random.seed(1614044650)
   random.shuffle([None] * 1992)
   sport = random.randrange(65536)
   print(sport)  # Output: 45829
   ```
   Nilai `45829` cocok persis dengan `Source Port: 45829` pada Frame 1921 di pcap. Sinkronisasi PRNG terbukti 100% valid.
4. **Pembalikan Permutasi dan Dekripsi Keystream XOR:**
   Dijalankan algoritma pemulihan otomatis:
   - Buat array pelacak lokasi: `locations = list(range(1992))`, lalu kocok dengan `random.shuffle(locations)`.
   - Siapkan buffer keluaran berukuran 1.992 byte: `output = [None] * 1992`.
   - Iterasi setiap paket $i$:
     1. Baca `src_port = random.randrange(65536)`.
     2. Baca keystream mask: `mask = random.randrange(256)`.
     3. Hitung byte asli: `original_byte = packet_payload[i] ^ mask`.
     4. Tempatkan pada posisi semula: `output[locations[i]] = original_byte`.
5. **Pemeriksaan Hasil Carving dan Ekstraksi Flag:**
   Buffer biner disimpan sebagai berkas `output.bin`. Utilitas `file` mengidentifikasi berkas sebagai citra grafis valid:
   `PNG image data, 426 x 240, 1-bit grayscale, non-interlaced`.
   Gambar menampilkan teks flag grafis: `picoCTF{n0_t1m3_t0_w4st3_5hufflin9_ar0und}`.
6. **Batas Validasi Validator & Normalisasi Token:**
   Pengujian empiris langsung pada REST API CyLab menunjukkan bahwa validator tantangan ini (event `picoMini by redpwn`) menerima format wrapper asli `picoCTF{n0_t1m3_t0_w4st3_5hufflin9_ar0und}` dengan status HTTP 201 Created (`correct: true`). Sebaliknya, pengiriman dengan wrapper CyLab `academy{n0_t1m3_t0_w4st3_5hufflin9_ar0und}` ditolak dengan `{"correct": false}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `picoCTF{n0_t1m3_t0_w4st3_5hufflin9_ar0und}`
- **Wrapper Validator:** Native event wrapper (`picoCTF{...}`)
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_206_scrambled_bytes.py`.

### Re-verifikasi Audit Batch 184 (2026-11-09 UTC, sesi REST siswa `Arielwin` / user id 1072359)

| Token diuji | Wrapper | HTTP | Respons API |
| :--- | :--- | :--- | :--- |
| `picoCTF{n0_t1m3_t0_w4st3_5hufflin9_ar0und}` | native event | 201 | `{"user":1072359,"challenge":206,"flag":"picoCTF{n0_t1m3_t0_w4st3_5hufflin9_ar0und}","correct":true,"historical":false}` |
| `academy{n0_t1m3_t0_w4st3_5hufflin9_ar0und}` | CyLab rekey | 201 | `{"user":1072359,"challenge":206,"flag":"academy{n0_t1m3_t0_w4st3_5hufflin9_ar0und}","correct":false,"historical":false}` |

- **Temuan format validator:** Modul backport event `picoMini by redpwn` tidak direkey ke prefix `academy{...}`.
- **Reproduktifitas offline:** Solver `scripts/solve_206_scrambled_bytes.py` merekonstruksi state PRNG MT19937 secara deterministik dari seed timestamp 1614044650, membalikkan permutasi Fisher-Yates, dan menghasilkan token native terverifikasi.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Wajib Menggunakan CSPRNG untuk Operasi Keamanan (OWASP ASVS §6.2.1):**
   Jangan pernah menggunakan generator pseudo-random umum (`random` pada Python, `rand()` pada C/C++) untuk kebutuhan kriptografi, token sesi, masking, atau proteksi data transmisi. Selalu gunakan modul Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) seperti `secrets` pada Python atau `/dev/urandom` / `getrandom()` pada tingkat kernel OS.
2. **Eliminasi Side-Channel Telemetri Protokol:**
   Penyusunan parameter protokol jaringan (seperti pemilihan port dinamis acak) tidak boleh berbagi *state engine* yang sama dengan generator kunci enkripsi. Kebocoran satu parameter di lapisan transport (layer 4) langsung memaparkan seluruh status generator di lapisan aplikasi (layer 7).
3. **Penerapan Enkripsi Terotentikasi Standar (AEAD):**
   Pengacakan posisi byte dan operasi XOR tunggal bukanlah skema enkripsi yang aman (*security through obscurity*). Gunakan protokol standar seperti TLSv1.3 atau IPSec dengan algoritma enkripsi terotentikasi (AES-GCM / ChaCha20-Poly1305) untuk menjamin kerahasiaan (*confidentiality*) dan integritas (*integrity*) lalu lintas data.
