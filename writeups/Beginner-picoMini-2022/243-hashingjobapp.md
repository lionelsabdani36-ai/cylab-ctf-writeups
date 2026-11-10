# Writeup: HashingJobApp (Challenge ID: 243)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Socket Automation & Cryptographic Hashing
- **Difficulty:** Easy (diff=1)
- **Event:** Beginner picoMini 2022
- **Points:** 40
- **Author:** LT 'syreal' Jones
- **Flag:** `academy{4ppl1c4710n_r3c31v3d_467e06bf}`

---

## Problem Statement & Scope
Tantangan `HashingJobApp` menyajikan sebuah simulasi wawancara kerja interaktif pada layanan soket jaringan TCP. Server menguji kemampuan komputasi kandidat dengan mengirimkan serangkaian string teks acak dan meminta respon berupa nilai intisari hash MD5 dari teks tersebut di bawah batas waktu respon yang sangat ketat. Apabila seluruh putaran pertanyaan dijawab dengan benar dan tepat waktu, server menyerahkan surat penawaran kerja beserta token bendera resmi.

Ruang lingkup audit keamanan protokol jaringan dan kriptografi aplikasi mencakup:
1. Analisis arsitektur komunikasi layanan soket TCP (RFC 9293) dan penanganan batas waktu interaktif (*socket timeout*).
2. Mekanisme komputasi fungsi hash satu arah MD5 (RFC 1321) dan sifat deterministik intisari kriptografis 128-bit.
3. Otomasi alur kerja interaktif jaringan menggunakan modul Python `socket` dan `hashlib` untuk mengatasi pembatasan waktu respons manusia (*CWE-799 Mitigation via Scripting*).
4. Verifikasi matriks wrapper bendera resmi pada REST API CyLab Security Academy (`POST /api/submissions/`) sesuai standar **NIST SP 800-115 Section 4.2** (*Network Protocol Analysis and Verification Testing*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Fungsi Hash Satu Arah MD5 (RFC 1321):**
   - MD5 (*Message-Digest Algorithm 5*) adalah algoritma hash kriptografis yang memetakan pesan dengan panjang variabel menjadi intisari hash berukuran tetap 128 bit (direpresentasikan sebagai 32 karakter heksadesimal).
   - MD5 bersifat deterministik: setiap input biner yang identik selalu menghasilkan nilai hash yang persis sama tanpa pengecualian.
   - Contoh: string `'Katharine Hepburn'` jika di-hash menggunakan MD5 menghasilkan intisari `a05de7a1943e9df33a2d5407f612f16f`.
2. **Keterbatasan Respon Manual Manusia dan Kebutuhan Otomasi Jaringan (CWE-799):**
   - Server menetapkan jendela waktu tunggu (*interactive timeout*) hanya beberapa detik per pertanyaan dan menyajikan string acak baru pada setiap putaran (biasanya 3 putaran berurutan).
   - Pengguna manusia yang menyalin teks secara manual ke kalkulator hash web atau utilitas terminal eksternal akan selalu tereliminasi akibat terlampauinya batas waktu (*connection timeout* / *session terminated*).
   - Oleh karena itu, pengujian ini menguji kompetensi otomasi skrip interaktif (*socket scripting automation*), di mana skrip klien secara dinamis mendeteksi string di antara tanda petik, menghitung hash MD5 secara *in-memory*, dan mengembalikan respon sebelum *timeout* terpicu.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Pemeriksaan Interaksi Protokol TCP:**
   - Menghubungkan terminal ke layanan soket TCP:
     ```bash
     nc chatelaine.cylabacademy.net <port>
     ```
   - Server memunculkan prompt interaktif:
     ```text
     Please md5 hash the text between quotes, excluding the quotes: 'Katharine Hepburn'
     Answer:
     ```
2. **Desain Alur Otomasi Soket (Socket Client Loop):**
   - Membangun loop interaktif pada skrip Python dengan tahapan:
     a. Membaca data buffer dari soket hingga menemukan penanda `'Answer:'` atau pola token bendera `academy{...}`.
     b. Mengekstrak string target di dalam tanda kutip menggunakan ekspresi reguler `re.search(r"[\x27\"]([^\x27\"]+)[\x27\"]", buf)`.
     c. Menghitung digest MD5: `digest = hashlib.md5(text.encode('utf-8')).hexdigest()`.
     d. Mengirimkan string digest berakhiran newline `\n` kembali ke soket: `s.sendall(f"{digest}\n".encode('utf-8'))`.
     e. Mengulangi proses hingga ketiga putaran verifikasi tuntas.
3. **Penerimaan Token Bendera:**
   - Setelah 3 putaran selesai, server mengembalikan respon persetujuan penawaran kerja beserta token:
     `academy{4ppl1c4710n_r3c31v3d_467e06bf}`.
4. **Validasi Matriks Wrapper Bendera:**
   - Melakukan pengujian kirim live via `POST /api/submissions/`:
     - Uji wrapper native CyLab `academy{4ppl1c4710n_r3c31v3d_467e06bf}`: **HTTP 201 Created (`correct: true`)**.
     - Uji wrapper event `picoCTF{4ppl1c4710n_r3c31v3d_467e06bf}`: **HTTP 201 Created (`correct: false`)**.
   - Validator CyLab pada event `Beginner picoMini 2022` secara ketat menerima format `academy{...}` dan menolak `picoCTF{...}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{4ppl1c4710n_r3c31v3d_467e06bf}`
- **Status Live:** **SOLVED (HTTP 201 Created, correct: true)**
- **Verifikasi Skrip:** `python3 scripts/solve_243_hashingjobapp.py` berhasil tuntas dengan status exit 0.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Keterampilan Otomasi Jaringan Tingkat Tinggi (Speed Challenge LKS):**
   - Dalam modul *Speed Challenge* atau *Network Forensics* LKS Cyber Security, kemampuan menyusun skrip interaktif Python dalam hitungan menit adalah pembeda utama antara peserta reguler dan juara.
   - Pahami penanganan *buffering* pada soket TCP: data tidak selalu diterima dalam satu potongan penuh (*packet fragmentation*), sehingga pembacaan harus diulang sampai penanda akhir prompt terdeteksi.
2. **Kerapuhan Keamanan MD5 dalam Sistem Produksi (Defensive Analysis):**
   - MD5 sudah tidak layak digunakan untuk verifikasi integritas berkas kritis, tanda tangan digital, atau penyimpanan kata sandi karena kerentanan tabrakan hash (*collision vulnerabilities* / RFC 6151).
   - Rekomendasikan migrasi ke fungsi hash modern seperti SHA-256 (FIPS 180-4) atau SHA-3 (FIPS 202), dan untuk kata sandi gunakan skema *salted key-stretching* (Argon2id, bcrypt, atau PBKDF2).
3. **Penguatan Mekanisme Anti-Otomasi Layanan (Rate Limiting & PoW):**
   - Apabila sistem bertujuan membatasi akses otomatis bot pada layanan web/API, jangan mengandalkan kuis teka-teki statis yang mudah diurai skrip.
   - Terapkan mekanisme *Proof-of-Work* (PoW) kriptografis adaptif, token CSRF dinamis, serta sistem *rate limiting* berbasis IP dan reputasi klien.
