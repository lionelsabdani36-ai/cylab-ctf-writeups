# Writeup: Hidden Cipher 2 (Challenge ID: 751)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Dynamic Math-Keyed Keystream Reversal & Scalar Decoding (NIST SP 800-115 §4.2)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** Yahaya Meddy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{m4th_b3h1nd_c1ph3r_3c573aef}`
- **Flag Komunitas:** `CTF{m4th_b3h1nd_c1ph3r_3c573aef}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan reverse engineering biner ELF x86_64 terhadap skema kriptografi kustom:
> *"The flag is right in front of you... kind of. You just need to solve a basic math problem to see it. But to get the real flag, you’ll have to understand how that math answer is used.*
> *You can download the program files here."*

Peserta diberikan paket arsip `hiddencipher2.zip` yang memuat biner ELF 64-bit `hiddencipher2` dan berkas uji `flag.txt` lokal (`academy{fake_flag}`). Layanan yang sama di-host pada instans container interaktif via port TCP (netcat). Saat koneksi terjalin, program mengajukan pertanyaan aritmatika sederhana dan mencetak deretan angka integer acak sebagai representasi flag terenkripsi.

Tujuan audit adalah menganalisis alur komputasi biner, mengidentifikasi operasi matematika yang digunakan untuk mengenkripsi flag, dan merekonstruksi plaintext flag asli.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Insecure Custom Cryptographic Transformation (CWE-327 & CWE-330):**
   - Aplikasi menggunakan algoritma kriptografi buatan sendiri yang cacat secara fundamental (*Roll Your Own Crypto anti-pattern*).
   - Melalui dekompilasi dan analisis disassembly fungsi `encode_flag` (0x14eb), setiap byte $P_i$ dari buffer flag dikalikan langsung dengan integer jawaban kuis matematika $K$:
     ```text
     1523: movzx  eax, BYTE PTR [rax]       ; Mengambil byte flag P_i
     1529: imul   eax, DWORD PTR [rbp-0x1c] ; Mengalikan dengan jawaban kuis K
     152d: mov    esi, eax
     153e: call   11c0 <printf@plt>          ; Mencetak integer C_i
     ```
   - Transformasi matematis:
     $$C_i = P_i \times K$$
     di mana $C_i$ adalah bilangan bulat yang dicetak ke stdout, $P_i$ adalah nilai ASCII byte ke-$i$, dan $K$ adalah bilangan bulat hasil komputasi kuis.

2. **Kelemahan Reversibilitas Deterministik (Scalar Inversion):**
   - Operasi perkalian skalar terhadap bilangan bulat merupakan fungsi bijektif linier yang dapat dibalik secara trivial tanpa kehilangan presisi selama $K \neq 0$:
     $$P_i = \lfloor C_i / K \rfloor$$
   - Penyerang yang mengetahui jawaban kuis $K$ (karena penyerang sendiri yang menginputkannya) dapat langsung membagi setiap integer ciphertext $C_i$ dengan $K$ untuk memulihkan kode ASCII karakter $P_i$ dalam kompleksitas waktu $O(N)$.

3. **Absensi Difusi dan Konfusi (Shannon's Properties):**
   - Algoritma tidak memiliki prinsip *confusion* (substitusi non-linier) maupun *diffusion* (permutasi posisi atau keterkaitan antar-byte). Perubahan pada satu byte plaintext hanya mempengaruhi nilai integer pada indeks yang bersangkutan secara independen.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Statis Biner ELF (`objdump` & Disassembly):**
   - Periksa biner lokal dengan `objdump -d -M intel hiddencipher2`:
     - Fungsi `main` (0x1685):
       - Menginisialisasi PRNG via `srand(time(NULL))`.
       - Memanggil `generate_math_question(rax, rcx, rdx)` pada 0x1369 yang memilih operan acak $1 \le n_1, n_2 \le 10$ dan operator acak (`+`, `-`, `*`).
       - Menampilkan pertanyaan via `printf` dan membaca jawaban pengguna dengan `scanf("%d")`.
       - Membandingkan input pengguna dengan nilai return `generate_math_question`. Jika sama, memanggil `read_flag_file` (0x1593) lalu meneruskan buffer flag dan integer jawaban ke `encode_flag` (0x14eb).
     - Fungsi `encode_flag` (0x14eb):
       - Mencetak header `"Encoded flag values:\n"`.
       - Menjalankan loop byte-by-byte: mengalikan byte flag dengan parameter integer dan mencetak output format integer desimal.

2. **Ekstraksi Live via TCP Socket (Interaktif Remote):**
   - Menghubungkan soket TCP ke instans live CyLab:
     ```text
     What is 9 * 9?
     ```
   - Menghitung jawaban matematika secara dinamis: $9 \times 9 = 81$.
   - Mengirimkan string jawaban `81\n`.
   - Menerima deretan nilai terenkripsi dari server:
     ```text
     Encoded flag values:
     7857, 8019, 7857, 8100, 8181, 8829, 9801, 9963, 8829, 4212,
     9396, 8424, 7695, 7938, 4131, 8424, 3969, 8910, 8100, 7695,
     8019, 3969, 9072, 8424, 4131, 9234, 7695, 4131, 8019, 4293,
     4455, 4131, 7857, 8181, 8262, 10125
     ```

3. **Inversi Nilai Skalar Plaintext:**
   - Membagi setiap nilai dengan $K = 81$:
     - $7857 / 81 = 97 \rightarrow \text{'a'}$
     - $8019 / 81 = 99 \rightarrow \text{'c'}$
     - $7857 / 81 = 97 \rightarrow \text{'a'}$
     - $8100 / 81 = 100 \rightarrow \text{'d'}$
     - $8181 / 81 = 101 \rightarrow \text{'e'}$
     - $8829 / 81 = 109 \rightarrow \text{'m'}$
     - $9801 / 81 = 121 \rightarrow \text{'y'}$
     - $9963 / 81 = 123 \rightarrow \text{'\{'}$
     - ...
   - Plaintext flag lengkap terpulihkan: `academy{m4th_b3h1nd_c1ph3r_3c573aef}`.

4. **Otomasi Reproduktif & Submisi REST API:**
   - Skrip otomasi mandiri `scripts/solve_751_hidden_cipher_2.py` mendukung pengujian lokal terhadap biner ELF maupun eksploitasi live TCP socket.
   - Submisi token ke CyLab REST API `POST /api/submissions/` berhasil mengonfirmasi status `correct: true`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{m4th_b3h1nd_c1ph3r_3c573aef}`
- **Format Komunitas:** `CTF{m4th_b3h1nd_c1ph3r_3c573aef}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 751, "flag": "academy{m4th_b3h1nd_c1ph3r_3c573aef}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Larangan Algoritma Kriptografi Buatan Sendiri (CWE-327 Remediation):**
   - Jangan pernah mendesain atau mengimplementasikan cipher buatan sendiri berbasis transformasi aritmatika dasar (seperti perkalian skalar, rotasi tetap, atau penambahan modulo tanpa s-box).
   - Wajib gunakan modul kriptografi standar industri yang telah tersertifikasi FIPS (seperti AES-256-GCM atau ChaCha20-Poly1305) dengan panjang kunci minimal 256-bit dan Initialization Vector (IV) yang unik per operasi.

2. **Kepatuhan NIST SP 800-53 IA-7 & SC-13 (Cryptographic Module & Cryptographic Protection):**
   - Pastikan perlindungan kerahasiaan data menggunakan mekanisme autentikasi pesan terenkripsi (*Authenticated Encryption with Associated Data* / AEAD) untuk mendeteksi manipulasi cipher dan mencegah dekripsi tanpa kunci simetris rahasia.

3. **Pemisahan Logika Bisnis & Hak Akses Data Sensitif:**
   - Komponen kuis atau interaksi publik pengguna tidak boleh memiliki akses baca langsung ke berkas kredensial atau rahasia server (`flag.txt`). Akses terhadap data sensitif wajib melalui kontrol otorisasi berlapis (*authorization gate*).

---

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)

- **David (Leader):** Menetapkan metodologi audit reverse engineering statis dan dinamis berbasis System V AMD64 ABI serta standar NIST SP 800-115.
- **Charlie (Trend-hunter):** Mengidentifikasi pola soal reverse engineering berbasis math obfuscation yang lazim diujikan pada seleksi LKS Cyber Security tingkat provinsi dan nasional.
- **Alex (Fullstack-dev) & Omnirush (Coding Agent):** Mengimplementasikan skrip solver Python terpadu yang memadukan eksekusi proses lokal dan koneksi soket TCP interaktif.
- **Julius (QA-engineer):** Menjalankan verifikasi komputasi matematika terhadap biner lokal `/tmp/hiddencipher2_dir/hiddencipher2` dan memverifikasi token pada endpoint REST API CyLab.
- **Athena (Security-engineer):** Menganalisis kelemahan matematis CWE-327 dan merumuskan rekomendasi arsitektur kriptografi NIST SP 800-53 SC-13.
- **Judith (Guru LKS):** Menyusun studi kasus dekompilasi fungsi biner dan inversi skalar untuk modul pelatihan bimbingan teknis siswa calon kompetitor LKS.
