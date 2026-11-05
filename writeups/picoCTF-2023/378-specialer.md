# Writeup: Specialer (Challenge ID: 378)

- **Platform:** CyLab Security Academy (picoCTF 2023)
- **Category:** General Skills
- **Difficulty:** Medium
- **Event:** picoCTF 2023
- **Flag:** `academy{y0u_d0n7_4ppr3c1473_wh47_w3r3_d01ng_h3r3_17ec7048}`

---

## Problem Statement & Scope

Tantangan ini menyajikan shell SSH interaktif dengan lingkungan Bash yang diperketat (*restricted shell*). Seluruh binary standar Linux seperti `cat`, `ls`, `grep`, `more`, atau `find` telah dihapus dari `$PATH`, menyisakan `/bin/bash` dan shell builtins.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Restricted Shell Environment (CWE-250):**
   Meskipun binary eksternal dihapus, proses pengguna tetap berjalan dalam shell `/bin/bash` penuh.
2. **Bash Builtin Redirection & Command Substitution:**
   Bash menyediakan konstruksi internal bawaan untuk membaca konten berkas tanpa mengeksekusi program eksternal seperti `cat`:
   ```bash
   $(< filename)
   ```
   Fitur ini membaca seluruh isi berkas dan menggantikannya sebagai string argumen untuk perintah internal seperti `echo` atau `printf`.
3. **Globbing / Pathname Expansion:**
   Karakter wildcard `*` dievaluasi langsung oleh Bash tanpa memerlukan utilitas `ls`. Menjalankan `echo */*` menampilkan seluruh nama berkas di subdirektori.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Koneksi SSH ke instans container aktif:
   `ssh -p <port> ctf-player@<host>`
2. Enumerasi struktur direktori menggunakan fitur ekspansi pathname Bash:
   `echo *; echo */*`
   Ditemukan subdirektori `abra/`, `ala/`, dan `sim/` berisi berkas `.txt`.
3. Membaca berkas secara batch menggunakan loop internal Bash dan ekspansi file `<`:
   ```bash
   for f in */*.txt; do
       echo "=== $f ==="
       echo "$(< $f)"
   done
   ```
4. Berkas `ala/kazam.txt` mengembalikan string flag:
   `return 0 academy{y0u_d0n7_4ppr3c1473_wh47_w3r3_d01ng_h3r3_17ec7048}`

---

## Flag & Verifikasi

- **Flag:** `academy{y0u_d0n7_4ppr3c1473_wh47_w3r3_d01ng_h3r3_17ec7048}`
- **Hasil Submission:**
  ```json
  {"user": 1072359, "challenge": 378, "flag": "academy{y0u_d0n7_4ppr3c1473_wh47_w3r3_d01ng_h3r3_17ec7048}", "correct": true, "historical": false}
  ```

---

## Remediasi & Mitigasi (Perspektif Defensive LKS)

1. Jika memerlukan lingkungan shell terbatas (*jailed shell*), gunakan shell khusus seperti `rbash` dengan opsi penguncian `set -r` yang menonaktifkan pengalihan input/output (`<`, `>`).
2. Terapkan containerisasi berbasis Linux Namespaces, chroot jail yang terisolasi, atau gVisor untuk memisahkan ruang berkas sensitif dari pengguna tidak tepercaya.
