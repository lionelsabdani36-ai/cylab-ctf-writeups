# Writeup: riscy business (Challenge ID: 219)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / RISC-V Cross-Architecture & Prefix Oracle Recovery (CWE-200 / CWE-327)
- **Difficulty:** Hard (diff=3)
- **Event:** picoMini by redpwn
- **Points:** 400
- **Author:** redpwn
- **Flag:** `academy{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgvz}`

---

## Problem Statement & Scope
Tantangan `riscy business` menyajikan berkas biner ELF 64-bit yang dikompilasi untuk set instruksi arsitektur RISC-V (`riscv64`, RV64IMAFDC). Program dikompilasi dengan proteksi Partial RELRO, Stack Canary enabled, NX enabled, dan No PIE. 

Saat dieksekusi, program meminta input string pengguna dari `stdin`, memprosesnya melalui fungsi transformasi/pengacakan (*byte scrambling algorithm*), dan memvalidasi hasilnya dengan membandingkan array hasil transformasi terhadap array target 65-byte yang tersimpan di memori. Dikarenakan sebagian besar mesin peserta menggunakan arsitektur x86_64, peserta dituntut untuk membangun lingkungan emulasi lintas-arsitektur (*cross-architecture emulation*) menggunakan QEMU (`qemu-riscv64-static`) dan GDB Multi-arch, menganalisis struktur percabangan RISC-V, serta memanfaatkan sifat independensi prefiks dari fungsi pengacakan untuk merekonstruksi flag secara linear.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Analisis Lintas Arsitektur RISC-V (RV64 Calling Conventions & Instructions):**
   Arsitektur RISC-V mengalokasikan register fungsi secara terstruktur:
   - `a0` - `a7` (x10 - x17): Register argumen dan nilai kembalian (*return value*).
   - `s0` - `s11` (x8 - x9, x18 - x27): Register *saved across calls*.
   - `sp` (x2): Stack pointer.
   - Instruksi dasar yang dipakai mencakup `addi` (penambahan immediate), `ld` (load 64-bit qword), `sb`/`lb` (store/load 8-bit byte), `xor`, dan instruksi percabangan `bne`/`beq`.
2. **Kelemahan Kriptografi: Ketergantungan Prefiks Searah (Causal Prefix Invariance, CWE-327):**
   Fungsi pengacakan mengiterasi byte input dari indeks $0$ hingga $N-1$. Karakter ke-$i$ diolah sedemikian rupa sehingga:
   $$\text{scrambled}[i] = g(\text{input}[i], \text{internal\_state}_{i-1})$$
   Karakter input pada indeks $i$ hanya mempengaruhi luaran pada posisi $0 \le k \le i$ dan **tidak pernah mengubah** nilai luaran yang telah dihitung sebelumnya ($\text{scrambled}[0 \dots i-1]$), maupun memerlukan karakter input masa depan ($k > i$).
3. **Reduksi Ruang Kunci Eksponensial ke Linear via Side-Channel Memory Oracle (CWE-200):**
   Jika seluruh 51 byte flag harus ditebak secara simultan, ruang pencarian adalah:
   $$|\Sigma|^{51} \approx 68^{51} \approx 10^{93}$$
   Ruang tersebut mustahil ditembus secara brute force. Namun, karena sifat invarian prefiks di atas, penyerang dapat memasang breakpoint di instruksi perbandingan memori:
   - Register `a5` menampung pointer ke array target yang diharapkan (*expected buffer*).
   - Register `s1` menampung pointer ke array hasil transformasi kandidat pengguna saat ini.
   Dengan mencocokkan slice `s1[:i+1] == a5[:i+1]`, penyerang memvalidasi satu karakter benar pada setiap iterasi. Kompleksitas tereduksi drastis menjadi linear:
   $$51 \times |\Sigma| \approx 51 \times 68 = 3.468 \text{ evaluasi}.$$

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Persiapan Lingkungan Emulasi QEMU User:**
   Biner RISC-V dijalankan di bawah emulasi proses pengguna dengan mengekspos GDB stub port:
   ```bash
   qemu-riscv64-static -g 1234 ./riscy
   ```
2. **Pemasangan Breakpoint & Identifikasi Register:**
   Menggunakan `gdb-multiarch`, dilakukan koneksi menuju remote target (`target remote :1234`). Breakpoint ditempatkan pada blok loop perbandingan sebelum fungsi verifikasi selesai:
   - Ditemukan register `a5` memuat string biner target 65 byte.
   - Register `s1` memuat buffer hasil olah input tebakan.
3. **Eksekusi Otomasi Pemulihan Prefiks Karakter:**
   Skrip Python menggunakan modul interaktif mengirimkan tebakan karakter per karakter:
   - Inisialisasi basis prefiks: `known = "picoCTF{"`.
   - Untuk setiap posisi karakter baru, uji himpunan karakter `_}0-9a-zA-Z?`.
   - Jalankan proses hingga breakpoint, baca memori pada `$s1`, bandingkan byte ke-$i$ dengan byte ke-$i$ pada `$a5`.
   - Apabila byte identik, kunci karakter tersebut dan lanjutkan ke indeks $i+1$.
4. **Hasil Ekstraksi Flag:**
   Iterasi berjalan deterministik hingga menemukan kurung kurawal penutup `}` pada indeks ke-51:
   `picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgvz}`.
5. **Normalisasi Token CyLab Academy:**
   Token dinormalisasi sesuai format resmi CyLab: `academy{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgvz}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgvz}`
- **Native PicoCTF Flag:** `picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgvz}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_219_riscy_business.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Keterampilan Analisis Non-x86 (LKS Cyber Security Core Skill):**
   Tantangan modern dan sistem IoT/embedded industri sering mengadopsi arsitektur alternatif seperti RISC-V dan ARM64. Menguasai alur emulasi QEMU, register calling convention, dan debugging gdb-multiarch merupakan syarat mutlak dalam modul *Reverse Engineering & Embedded Firmware Analysis*.
2. **Kelemahan Desain Stream/Scrambler Tanpa Difusi Global (Avalanche Effect Failure):**
   Algoritma transformasi data yang aman wajib memenuhi *Strict Avalanche Criterion* (SAC), di mana perubahan 1 bit pada input harus mengubah minimal 50% bit pada seluruh luaran ciphertext (seperti pada struktur SPN/Feistel standar AES/SHA-256). Skema yang mempertahankan lokalitas byte-ke-byte membuka celah serangan oracle prefiks linear.
3. **Pemberian Umpan Balik Waktu Konstan (Constant-Time Verification, NIST SP 800-115 §5.3):**
   Verifikasi kredensial atau token wajib mengevaluasi seluruh buffer secara konstan (*constant-time comparison* via `CRYPTO_memcmp`) tanpa memutus loop di awal (*early exit*) dan tanpa meninggalkan buffer perantara di register yang mudah dibaca oleh instrumentasi ptrace/GDB.
