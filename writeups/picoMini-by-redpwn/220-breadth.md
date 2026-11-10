# Writeup: breadth (Challenge ID: 220)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Binary Differential Analysis & Decoy Function Isolation (CWE-200 / CWE-697)
- **Difficulty:** Hard (diff=3)
- **Event:** picoMini by redpwn
- **Points:** 200
- **Author:** redpwn
- **Flag:** `picoCTF{VnDB2LUf1VFJkdfDJtdYtFlMexPxXS6X}`

---

## Problem Statement & Scope
Tantangan `breadth` menyajikan dua versi berkas biner ELF 64-bit (`breadth.v1` dan `breadth.v2`) yang berjalan pada arsitektur Linux x86_64. Kedua biner dikompilasi dengan proteksi Full RELRO, Stack Canary enabled, NX enabled, dan Position-Independent Executable (PIE), serta seluruh simbol debugging di-strip (`stripped`). 

Ketika dianalisis secara statis melalui utilitas `strings`, kedua biner memuat puluhan ribu fungsi acak yang masing-masing mereferensikan string umpan (*decoy*) berformat `picoCTF{...}`. Fungsi `main()` tidak mengeksekusi sebagian besar fungsi tersebut, sehingga pendekatan eksekusi dinamis langsung (*black-box execution*) tidak menghasilkan luaran flag. Peserta ditugaskan untuk menerapkan metodologi analisis diferensial biner (*patch analysis / differential reverse engineering*) untuk mengidentifikasi fungsi tunggal yang dimodifikasi oleh pembuat tantangan dan merekonstruksi flag valid dari bagian memori `.rodata`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Obfuskasi Berbasis Injeksi Decoy Skala Masif (CWE-200 / Anti-Analysis Noise):**
   Aplikasi dirancang dengan teknik disinformasi statis (*honeypot strings*). Dengan menyematkan ribuan string `picoCTF{<random_alphanumeric>}` pada seksi `.rodata`, pencarian berbasis ekspresi reguler teks murni (*grep pattern matching*) mengalami kegagalan karena menghasilkan ribuan false positives yang identik di kedua versi.
2. **Asimetri Modifikasi Patch & Titik Balik Logika Percabangan (CWE-697):**
   Penulis tantangan merilis versi koreksi (`breadth.v2`). Dalam analisis kerentanan dunia nyata (*vulnerability research & 1-day patch auditing*), perbedaan sekecil apa pun antara dua revisi biner menandakan logika fungsional inti atau perbaikan keamanan.
   Pada `breadth.v1`, fungsi target pada offset `0x9500c` memuat instruksi:
   ```assembly
   movq $0x41bc73e, -0x10(%rsp)
   mov  -0x10(%rsp), %rax
   cmp  $0xd037803a, %rax
   je   0x95070
   ret
   ```
   Instruksi `cmp` membandingkan nilai `0x41bc73e` dengan nilai acak `0xd037803a`, sehingga percabangan `je` tidak pernah diambil dan eksekusi langsung kembali via `ret`.
3. **Resolusi Instruksi Relatif PC (%rip-relative addressing) pada Biner PIE:**
   Pada `breadth.v2`, instruksi perbandingan diperbaiki menjadi:
   ```assembly
   cmp  $0x41bc73e, %rax
   je   0x95070
   ```
   Karena perbandingan kini bernilai benar (*branch satisfied*), aliran kontrol CPU melompat ke blok `0x95070`:
   ```assembly
   0x95070: lea 0xc0e91(%rip), %rdi    # Target: 0x95077 + 0xc0e91 = 0x155f08
   0x95077: jmp 0x1040                 # PLT stub puts()
   ```
   Blok ini memuat pointer string flag sejati dari seksi `.rodata` dan meneruskannya ke fungsi pencetak standar.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Komparatif Byte-by-Byte (Binary Diffing):**
   Menggunakan utilitas posix `cmp -bl` atau `radiff2 -u breadth.v1 breadth.v2`, ditemukan bahwa dari 2,6 MB ukuran biner, hanya terdapat 3 kelompok byte yang mengalami perbedaan:
   - Offset `724 - 743`: GNU Build-ID header hash (perubahan otomatis compiler).
   - Offset `610382` (`0x9504e`): 14 byte opcode logika perbandingan `cmp`.
   - Offset `2438995`: String nama file sumber `generated.v1.c` menjadi `generated.v2.c`.
2. **Pemetaan Alamat Virtual Segmen Kode (.text):**
   Berdasarkan pembacaan tabel ELF Program Header via `readelf -l`, segmen LOAD kedua dipetakan pada Virtual Address `0x1000` dengan ukuran `0xc01f5`. Offset disk `610382` (`0x9504e`) berada tepat di dalam segmen `.text`.
3. **Disassembly & Evaluasi Aliran Kontrol:**
   Disassembly pada rentang offset `0x95040 - 0x95080` mengungkap struktur *predicate check*:
   - Pada `breadth.v1`: perbandingan gagal, instruksi cetak tidak pernah tercapai.
   - Pada `breadth.v2`: perbandingan `0x41bc73e == 0x41bc73e` sukses, memicu eksekusi alamat `0x95070`.
4. **Resolusi Pointer String .rodata & Ekstraksi Flag:**
   Instruksi `lea 0xc0e91(%rip), %rdi` mengevaluasi alamat berbasis offset instruksi berikutnya (`0x95077`).
   Perhitungan: `0x95077 + 0xc0e91 = 0x155f08`.
   Membaca memori `.rodata` pada alamat `0x155ef8` (tepat 16 byte sebelum offset tengah) mengungkap string lengkap berterminasi null:
   `picoCTF{VnDB2LUf1VFJkdfDJtdYtFlMexPxXS6X}`.
5. **Batas Validasi Validator & Normalisasi Token:**
   Membaca memori `.rodata` pada alamat `0x155ef8` mengungkap string lengkap berterminasi null: `picoCTF{VnDB2LUf1VFJkdfDJtdYtFlMexPxXS6X}`.
   Pengujian empiris langsung pada REST API CyLab menunjukkan bahwa validator tantangan ini (event `picoMini by redpwn`) menerima format wrapper asli `picoCTF{VnDB2LUf1VFJkdfDJtdYtFlMexPxXS6X}` dengan status HTTP 201 Created (`correct: true`). Sebaliknya, pengiriman dengan wrapper CyLab `academy{VnDB2LUf1VFJkdfDJtdYtFlMexPxXS6X}` ditolak dengan `{"correct": false}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `picoCTF{VnDB2LUf1VFJkdfDJtdYtFlMexPxXS6X}`
- **Wrapper Validator:** Native event wrapper (`picoCTF{...}`)
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_220_breadth.py`.

### Re-verifikasi Audit Batch 186 (2026-11-10 UTC, sesi REST siswa `Arielwin` / user id 1072359)

| Token diuji | Wrapper | HTTP | Respons API |
| :--- | :--- | :--- | :--- |
| `picoCTF{VnDB2LUf1VFJkdfDJtdYtFlMexPxXS6X}` | native event | 201 | `{"user":1072359,"challenge":220,"flag":"picoCTF{VnDB2LUf1VFJkdfDJtdYtFlMexPxXS6X}","correct":true,"historical":false}` |
| `academy{VnDB2LUf1VFJkdfDJtdYtFlMexPxXS6X}` | CyLab rekey | 201 | `{"user":1072359,"challenge":220,"flag":"academy{VnDB2LUf1VFJkdfDJtdYtFlMexPxXS6X}","correct":false,"historical":false}` |

- **Temuan format validator:** Modul backport event `picoMini by redpwn` tidak direkey ke prefix `academy{...}`.
- **Reproduktifitas offline:** Solver `scripts/solve_220_breadth.py` merekonstruksi analisis diferensial biner byte-level untuk mengekstrak token native secara deterministik.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Metodologi Patch Analysis & Vulnerability Research (NIST SP 800-115 §5.2):**
   Dalam skenario kompetisi LKS Cyber Security maupun investigasi insiden riil, analis sering kali berhadapan dengan biner rilis tambalan (*security patch update*) tanpa dokumentasi CVE. Keterampilan melakukan diferensiasi byte dan dekompilasi terarah (*targeted diffing*) memungkinkan identifikasi kelemahan yang diperbaiki secara instan tanpa harus mengaudit jutaan baris kode secara manual.
2. **Bahaya Obfuscation through Noise / Decoy Dead Code:**
   Menyematkan ribuan fungsi palsu atau *dead code insertion* bukan merupakan mekanisme keamanan kriptografis yang tangguh (*security through obscurity*). Penyerang dengan kapabilitas biner diffing tingkat lanjut dapat menyaring kebisingan tersebut dalam hitungan detik.
3. **Penerapan Integritas Perangkat Lunak & Verifikasi Build:**
   Setiap rilis biner produksi wajib disertai tanda tangan digital kriptografis (GPG/Code Signing) dan *deterministic build pipeline* (Reproducible Builds) guna menjamin bahwa tidak ada artefak biner yang disisipi fungsi tersembunyi atau termanipulasi antara versi rilis.
