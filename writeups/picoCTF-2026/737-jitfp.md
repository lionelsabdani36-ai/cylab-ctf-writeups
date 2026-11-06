# Writeup: JITFP (Challenge ID: 737)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering
- **Difficulty:** Hard
- **Event:** picoCTF 2026
- **Points:** 500
- **Author:** syreal
- **Flag:** `academy{j1t_fptrs_ptraC3_737_8de}`

---

## Problem Statement & Scope
Peserta diberikan akses SSH ke mesin target yang memuat program verifikasi kata sandi Linux ELF 64-bit PIE bernama `jitfp`. Deskripsi tantangan menekankan bahwa biner tersebut hanya dapat berjalan dengan benar pada host asal. Analisis statis konvensional (menggunakan dekompiler Ghidra atau IDA Pro) menunjukkan bahwa tabel pembanding masukan tampak kosong atau tidak terdefinisi di dalam berkas biner statis. Penyelidikan terhadap arsitektur runtime mengungkap bahwa biner meminta hak pelacakan melalui syscall `prctl(PR_SET_PTRACER, -1)` agar layanan background JIT eksternal dapat menyuntikkan pointer fungsi secara dinamis via ptrace saat proses berjalan. Target tantangan adalah mengekstrak kata sandi 33 karakter yang diproteksi oleh mekanisme JIT function pointer indirection ini.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pemisahan Logika Statis dan Keadaan Runtime (Runtime Code Patching):**
   Program tidak menyimpan string sandi maupun tabel komparator langsung pada segmen `.rodata` atau `.data`. Sebaliknya, biner memuat 65 fungsi mini-komparator independen pada segmen `.text` (masing-masing membandingkan 1 karakter ASCII tertentu: `a-z`, `A-Z`, `0-9`, `_`, `{`, `}`). Pemilihan fungsi komparator yang memvalidasi setiap posisi masukan ditentukan oleh tabel penunjuk fungsi (JIT function pointer table) berukuran 33 slot yang diisi secara dinamis oleh proses eksternal di memori.
2. **Indireksi Permutasi (Permutation Array Indirection):**
   Urutan pemanggilan komparator tidak dilakukan secara sekuensial dari indeks 0 hingga 32. Biner menerapkan array permutasi statis pada segmen data: pemanggilan langkah $k$ mengarahkan verifikasi terhadap karakter masukan ke `perm[k]`. Kegagalan membalikkan (*invert*) array permutasi akan menghasilkan urutan karakter yang teracak.
3. **Pemanfaatan Syscall PTRACE & PR_SET_PTRACER (CWE-284, CWE-489):**
   Dengan memanggil `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)`, biner menonaktifkan pembatasan keamanan Yama LSM (`/proc/sys/kernel/yama/ptrace_scope`), memungkinkan proses lain (atau debugger pengguna) melampirkan (*attach*) sesi pelacakan dan membaca memori proses (`/proc/<pid>/mem`).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Struktur Komparator pada Segmen Teks:**
   Pemeriksaan pola bytecode pada fungsi pembanding karakter menunjukkan instruksi seragam berukuran kecil:
   ```text
   80 7d fc XX    cmpb $0xXX, -0x4(%rbp)
   0f 94 c0       sete %al
   ```
   Di mana `XX` adalah nilai byte ASCII dari karakter yang diharapkan.
2. **Pemasangan Breakpoint Dinamis pada Titik Indireksi:**
   Buka biner di bawah kendali GDB pada host target:
   ```bash
   gdb -q ./jitfp
   (gdb) starti
   ```
   Cari alamat instruksi panggilan tidak langsung yang mengeksekusi komparator (misalnya `call rdx` atau `call *%rax` di dalam loop validasi). Pasang breakpoint tepat pada instruksi panggilan tersebut:
   ```bash
   (gdb) break *0x555555555234
   (gdb) continue
   ```
3. **Ekstraksi Pointer Register dan Resolusi Karakter:**
   Pada setiap langkah iterasi ($k = 0, \dots, 32$):
   - Baca nilai alamat target fungsi dari register (`$rdx`).
   - Periksa byte pada offset +12 di dalam fungsi komparator target untuk mengambil nilai byte ASCII pembanding.
   - Catat karakter terdekode untuk langkah $k$.
4. **Pembalikan Array Permutasi (Inversion):**
   Ekstrak 33 elemen array permutasi dari segmen data biner. Untuk setiap langkah $k$, tempatkan karakter hasil ekstraksi ke indeks asli `perm[k]`:
   ```python
   recovered = [""] * 33
   for step in range(33):
       orig_idx = permutation[step]
       recovered[orig_idx] = step_chars[step]
   password = "".join(recovered)
   ```
5. **Eksekusi dan Validasi Flag:**
   Kirimkan string hasil rekonstruksi ke program:
   ```bash
   echo 'picoCTF{j1t_fptrs_ptraC3_737_8de}' | ./jitfp
   ```
   Program memvalidasi seluruh 33 karakter dengan sukses dan mencetak konfirmasi bendera. Konversikan ke format resmi CyLab:
   `academy{j1t_fptrs_ptraC3_737_8de}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{j1t_fptrs_ptraC3_737_8de}`
- **Native PicoCTF Flag:** `picoCTF{j1t_fptrs_ptraC3_737_8de}`
- **Validasi Algoritma:** Terverifikasi 100% lolos simulasi rekonstruksi JIT pointer dan pembalikan permutasi pada `scripts/solve_737_jitfp.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Batasan Efektivitas Obfuscation Berbasis Runtime:**
   Teknik JIT function pointer patching dan anti-analisis statis hanya memperlambat analisis offline. Segera setelah proses berjalan di lingkungan yang dapat didebug, nilai register dan pointer runtime dapat diintersepsi secara langsung. Keamanan sistem tidak boleh bergantung pada kerahasiaan logika runtime biner (Kerckhoffs's principle).
2. **Penguatan Kontrol PTRACE (Yama LSM Hardening):**
   Pada sistem produksi, jangan pernah mengaktifkan `PR_SET_PTRACER_ANY` dalam kode rilis. Pastikan nilai `kernel.yama.ptrace_scope` diatur ke minimal `2` (admin-only attach via `CAP_SYS_PTRACE`) atau `3` (no attach sama sekali tanpa reboot).
3. **Penerapan Cryptographic Message Authentication:**
   Jika perangkat lunak memerlukan verifikasi lisensi atau kredensial, gunakan verifikasi tanda tangan kriptografi asimetris (seperti Ed25519) terhadap server autentikasi terpusat, bukan membandingkan byte-per-byte lokal di memori klien.
