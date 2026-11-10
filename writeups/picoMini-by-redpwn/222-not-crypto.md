# Writeup: not crypto (Challenge ID: 222)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / In-Memory Plaintext Exposure & Debugger Dynamic Analysis (CWE-208 / CWE-311)
- **Difficulty:** Hard (diff=3)
- **Event:** picoMini by redpwn
- **Points:** 150
- **Author:** asphyxia
- **Flag Resmi:** `picoCTF{c0mp1l3r_0pt1m1z4t10n_15_pur3_w1z4rdry_but_n0_pr0bl3m?}`
- **Audit Batch:** Batch 187 (10 November 2026) - Live Verified HTTP 201 (`correct: true`)

---

## Problem Statement & Scope
Tantangan `not crypto` menyajikan berkas biner ELF Linux 64-bit (`x86_64-64-little`). Deskripsi tantangan memberikan petunjuk paradoks: *"there's crypto in here but the challenge is not crypto..."*. Saat biner dijalankan, program meminta 64 byte masukan dari pengguna dengan prompt:
`I heard you wanted to bargain for a flag... whatcha got?`
Jika pengguna memasukkan teks dengan panjang selain 64 byte atau konten yang salah, program mencetak `Nope, come back later` lalu keluar. Biner dikompilasi dengan proteksi Full RELRO, Stack Canary, NX, dan PIE aktif. Peserta diarahkan untuk mengaudit logika verifikasi biner dan mengekstraksi flag tanpa perlu membongkar atau memecahkan matematika algoritma kriptografi yang tertanam di dalamnya.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pemisahan Antara Kekuatan Kriptografi dan Keamanan Implementasi Runtime (CWE-311):**
   Meskipun biner mengimplementasikan rutinitas enkripsi simetris canggih (AES) lengkap dengan tabel substitusi (S-Box) dan penjadwalan kunci (*key schedule*), algoritma kriptografi yang kuat tidak dapat melindungi rahasia jika implementasi perangkat lunak memvalidasi hasilnya dengan membandingkan teks rahasia (*secret plain/ciphertext*) dalam bentuk tidak terenkripsi di memori proses.
2. **Titik Temu Komparasi dalam Memori (*Comparison Point Exposure*, CWE-208):**
   Pada saat runtime sebelum percabangan keputusan dibuat, program harus memverifikasi apakah masukan pengguna valid. Fungsi dekompilasi di Ghidra menunjukkan pemanggilan pustaka C standar:
   ```c
   memcmp(expected_buffer, user_transformed_buffer, 64);
   ```
   Untuk melakukan komparasi ini, program terlebih dahulu mendekripsi atau menyiapkan string flag yang diharapkan ke dalam buffer memori sementara yang ditunjuk oleh register pertama (`RDI` pada System V AMD64 ABI).
3. **Ketiadaan Mekanisme Anti-Debugging (*Tamper Resistance Deficit*):**
   Biner tidak dilengkapi teknik *anti-analysis* seperti pemanggilan syscall `ptrace(PTRACE_TRACEME)`, pemantauan status `/proc/self/status` (`TracerPid`), atau pengecekan perbedaan *timestamp* instruksi CPU (`rdtsc`). Akibatnya, analis keamanan dapat dengan leluasa memasang *hardware/software breakpoint* langsung pada instruksi pemanggilan `memcmp` di dalam GDB.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Statis & Identifikasi Syarat Panjang Input:**
   Melalui disassembly awal, diidentifikasi bahwa program memanggil `strlen()` terhadap masukan dan memeriksa apakah panjangnya persis 64 byte. Jika tidak sama dengan 64, program langsung melompat ke blok kegagalan.
2. **Pemasangan Dynamic Breakpoint pada GDB:**
   Analis meluncurkan biner di bawah debugger GDB:
   ```bash
   gdb ./not-crypto
   ```
   Pasang breakpoint langsung pada fungsi komparasi:
   ```gdb
   (gdb) b memcmp
   ```
3. **Pemberian Input Padding 64 Karakter:**
   Jalankan program dengan argumen atau input standar sepanjang 64 karakter sembarang (misal 64 karakter `'A'`):
   ```gdb
   (gdb) r
   I heard you wanted to bargain for a flag... whatcha got?
   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
   ```
4. **Pemeriksaan Isi Register pada Titik Breakpoint:**
   Program berhenti tepat sebelum mengeksekusi `memcmp`:
   - Register `RSI` memuat buffer hasil transformasi masukan pengguna yang tidak cocok.
   - Register `RDI` memuat alamat pointer ke string flag target yang telah didekripsi oleh program.
   Analis memeriksa isi memori yang ditunjuk oleh `RDI` sebagai string ASCII:
   ```gdb
   (gdb) x/s $rdi
   0x7fffffffd980: "picoCTF{c0mp1l3r_0pt1m1z4t10n_15_pur3_w1z4rdry_but_n0_pr0bl3m?}\n"
   ```
5. **Hasil Verifikasi Flag:**
   Flag native yang terekstraksi dari memori:
   `picoCTF{c0mp1l3r_0pt1m1z4t10n_15_pur3_w1z4rdry_but_n0_pr0bl3m?}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `picoCTF{c0mp1l3r_0pt1m1z4t10n_15_pur3_w1z4rdry_but_n0_pr0bl3m?}`
- **Validasi Live Platform:** Submisi via endpoint `POST /api/submissions/` menghasilkan respons **HTTP 201 Created** dengan `"correct": true`. Format wrapper alternatif `academy{...}` ditolak oleh validator platform (`correct: false`), membuktikan bahwa modul backport event picoMini by redpwn mensyaratkan native wrapper.
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi dinamis `scripts/solve_222_not_crypto.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Prinsip Validasi Hash Terproteksi (Zero Plaintext Exposure):**
   Jangan pernah menyimpan atau merekonstruksi teks rahasia (*secret cleartext*) di dalam memori hanya untuk membandingkannya dengan masukan pengguna. Terapkan validasi berbasis fungsi hash satu arah kriptografis dengan garam (*salted cryptographic hash* seperti Argon2id atau PBKDF2-HMAC-SHA256):
   ```c
   // Defensif: hash masukan pengguna lalu bandingkan dengan hash tersimpan
   unsigned char user_hash[32];
   crypto_hash(user_hash, user_input, 64);
   if (crypto_verify_32(user_hash, stored_hash) == 0) {
       grant_access();
   }
   ```
2. **Pembersihan Memori Sensitif (*Zeroization*, NIST SP 800-88):**
   Jika data rahasia harus didekripsi sementara di memori, bersihkan buffer tersebut sesegera mungkin menggunakan fungsi zeroisasi yang kebal dari optimasi pemangkasan compiler (*dead store elimination*):
   ```c
   explicit_bzero(secret_buffer, sizeof(secret_buffer));
   ```
3. **Penerapan Komparasi Waktu-Konstan (Constant-Time Comparison):**
   Gunakan fungsi perbandingan waktu-konstan (`CRYPTO_memcmp` atau `timingsafe_bcmp`) untuk mengeliminasi serangan *timing side-channel*.
4. **Proteksi Integritas Runtime & Anti-Debugging (NIST SP 800-115 §5.4):**
   Untuk biner berkeamanan tinggi (misal modul validasi lisensi atau perbankan), integrasikan pemeriksaan keberadaan debugger saat inisialisasi:
   ```c
   if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
       // Debugger terdeteksi, gagalkan eksekusi seketika
       exit(1);
   }
   ```
