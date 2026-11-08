# Writeup: JITFP (Challenge ID: 737)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2026
- **Points:** 500
- **Author:** syreal
- **Flag:** `academy{pr0cf5_d36ugg3r_d43a8ae7}`

---

## Problem Statement & Scope
Peserta diberikan akses SSH ke mesin target periphery network (`chatelaine.cylabacademy.net`) yang memuat program verifikasi kata sandi Linux ELF 64-bit PIE bernama `ad7e550b`. Deskripsi tantangan menekankan bahwa biner hanya berfungsi semestinya pada host asal tempat biner ditemukan ("*it only functions properly on the host on which we found it*").

Penyelidikan arsitektur runtime mengungkap bahwa pada background host berjalan layanan `python3 /root/jitfp-service.py`. Biner `ad7e550b` memanggil `prctl(PR_SET_PTRACER, -1)` untuk menonaktifkan kontrol Yama LSM, memungkinkan layanan JIT eksternal melampirkan sesi ptrace dan menyuntikkan function pointer pembanding secara dinamis ke tabel 33 slot di memori (`func_ptr_table` pada offset `.bss` 0x4120). Verifikasi setiap karakter dilakukan bertahap dengan jeda `sleep(1)` per langkah. Target tantangan adalah mengekstrak kata sandi 33 karakter yang diproteksi oleh mekanisme JIT function pointer indirection ini.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pemisahan Logika Statis dan Keadaan Runtime (Runtime Dynamic JIT Patching):**
   Program tidak menyimpan string sandi maupun tabel komparator langsung pada segmen `.rodata` atau `.data`. Segmen `.text` memuat 65 fungsi mini-komparator independen (masing-masing membandingkan 1 karakter ASCII: `a-z`, `A-Z`, `0-9`, `_`, `{`, `}`). Pemilihan fungsi komparator yang memvalidasi setiap posisi masukan ditentukan oleh tabel penunjuk fungsi (`func_ptr_table`) berukuran 33 slot yang diisi secara bertahap saat biner tidur selama 1 detik di setiap iterasi loop verifikasi.
2. **Indireksi Permutasi (Permutation Array Indirection):**
   Urutan pemanggilan komparator tidak sekuensial. Biner menerapkan array permutasi statis pada segmen `.data` (offset 0x4020):
   ```text
   indices = [30, 22, 11, 32, 25, 4, 9, 7, 19, 23, 5, 26, 18, 27, 16, 1, 8, 15, 2, 14, 3, 13, 24, 21, 12, 17, 6, 10, 29, 28, 20, 31, 0]
   ```
   Langkah verifikasi $i$ memanggil penunjuk fungsi pada slot `func_ptr_table[indices[i]]` untuk menguji karakter masukan `argv[1][i]`.
3. **Pemanfaatan Syscall PTRACE & PR_SET_PTRACER (CWE-284, CWE-489):**
   Dengan memanggil `prctl(0x59616d61, -1)` (`PR_SET_PTRACER_ANY`), biner menonaktifkan pembatasan keamanan Yama LSM (`/proc/sys/kernel/yama/ptrace_scope`). Hal ini memungkinkan proses lain di bawah hak pengguna biasa membaca dan memanipulasi memori proses target (`/proc/<pid>/mem`).
4. **Pad Stars Anti-Timing Trap:**
   Fungsi `pad_stars(33 - i)` selalu mencetak sisa tanda bintang `*` dan tidur 1 detik per sisa karakter bila masukan salah. Ini memastikan biner selalu berjalan tepat 33–34 detik terlepas dari titik kegagalan masukan, meniadakan serangan *timing attack* konvensional.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Pola Komparator pada Segmen Teks:**
   Pemeriksaan pola bytecode pada fungsi pembanding karakter menunjukkan instruksi seragam berukuran 29 byte:
   ```text
   55                   push %rbp
   48 89 e5             mov  %rsp,%rbp
   89 f8                mov  %edi,%eax
   88 45 fc             mov  %al,-0x4(%rbp)
   80 7d fc XX          cmpb $0xXX,-0x4(%rbp)
   74 07                je   match
   b8 00 00 00 00       mov  $0x0,%eax
   eb 05                jmp  end
   match:
   b8 01 00 00 00       mov  $0x1,%eax
   end:
   5d                   pop  %rbp
   c3                   ret
   ```
   Di mana `XX` adalah nilai byte ASCII dari karakter pembanding. Skrip memetakan seluruh 65 alamat offset fungsi ke karakter ASCII masing-masing.

2. **Deteksi Alamat Runtime & Buffer Masukan pada Stack:**
   - Jalankan biner target di bawah kendali proses anak Python dengan argumen dummy 33 karakter (`"X" * 33`).
   - Ekstrak basis alamat PIE teks melalui `/proc/<pid>/maps`.
   - Cari alamat buffer `argv[1]` pada segmen memori `[stack]`.

3. **Sinkronisasi Loop Runtime & Penulisan Memori In-Place:**
   Pada setiap langkah $i = 0, \dots, 32$:
   - Program tidur selama 1 detik (`sleep(1)`).
   - Tunggu 0.3 detik agar layanan `jitfp-service.py` selesai memperbarui pointer untuk slot `indices[i]`.
   - Baca pointer fungsi dari `/proc/<pid>/mem` pada alamat `text_base + 0x4120 + (indices[i] * 8)`.
   - Konversikan pointer ke offset biner dan petakan ke karakter ASCII yang dicocokkan oleh komparator.
   - Tulis karakter yang cocok secara langsung ke memori stack `argv[1] + i`.
   - Program bangun dari tidur, memanggil komparator dengan byte masukan yang telah disesuaikan, mengembalikan nilai 1 (sukses), mencetak `*`, dan melangkah ke iterasi berikutnya tanpa terminasi.

4. **Ekstraksi Token dan Bukti Validasi:**
   Setelah 33 iterasi selesai, program mencetak:
   ```text
   ================================v
   *********************************
   Correct
   ```
   Token lengkap yang berhasil diekstraksi adalah:
   `academy{pr0cf5_d36ugg3r_d43a8ae7}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{pr0cf5_d36ugg3r_d43a8ae7}`
- **Status API Live:** Validasi langsung via `POST https://learn.cylabacademy.org/api/submissions/` mengembalikan `HTTP 201 {"correct": true}`.
- **Skrip Reproduktif:** Terverifikasi 100% pada `scripts/solve_737_jitfp.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Batasan Efektivitas Obfuscation Berbasis Runtime:**
   Teknik JIT function pointer patching dan anti-analisis statis hanya memperlambat analisis offline. Segera setelah proses berjalan di lingkungan yang dapat diinspeksi, memori proses (`/proc/<pid>/mem`) dapat dimonitor dan dimodifikasi secara real-time. Keamanan sistem tidak boleh bergantung pada kerahasiaan logika runtime biner (Kerckhoffs's principle).
2. **Penguatan Kontrol PTRACE (Yama LSM Hardening):**
   Pada sistem produksi, jangan pernah memanggil `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)`. Pastikan nilai `kernel.yama.ptrace_scope` diatur ke minimal `2` (admin-only attach via `CAP_SYS_PTRACE`) atau `3` (no attach sama sekali tanpa reboot).
3. **Penerapan Cryptographic Message Authentication:**
   Jika perangkat lunak memerlukan verifikasi lisensi atau kredensial, gunakan verifikasi tanda tangan kriptografi asimetris (seperti Ed25519) terhadap server autentikasi terpusat, bukan membandingkan byte-per-byte lokal di memori klien.
