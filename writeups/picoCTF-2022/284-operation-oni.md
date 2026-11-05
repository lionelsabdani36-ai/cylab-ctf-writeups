# Writeup: Operation Oni (Challenge ID: 284)

- **Platform:** CyLab Security Academy (picoCTF 2022)
- **Category:** Forensics / Disk Forensics
- **Difficulty:** Medium
- **Event:** picoCTF 2022
- **Flag:** `academy{k3y_5l3u7h_0e000cd7}`

---

## Problem Statement & Scope

Diberikan sebuah *raw disk image* Linux berukuran ~230MB (`disk.img.gz`). Tantangan menginstruksikan analis untuk menemukan kunci otentikasi yang tersembunyi di dalam citra sistem berkas tersebut, lalu menggunakan kunci tersebut untuk melakukan login SSH ke mesin jarak jauh dan membaca flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Digital Disk Forensics & File System Parsing (The Sleuth Kit):**
   Citra partisi disk menggunakan format MBR dengan dua partisi Linux native (0x83). Partisi kedua (offset sektor 206848) adalah partisi root (`/`).
2. **Residual Artifact Exposure (SSH Key Pairs):**
   Kunci privat SSH (`id_ed25519`) tersimpan pada direktori `/root/.ssh/` di dalam sistem berkas tanpa enkripsi passphrase.
3. **Ekstraksi Langsung Berbasis Inode:**
   Menggunakan utilitas Sleuth Kit (`fls` dan `icat`), artefak sistem berkas dapat ditelusuri dan diekstraksi tanpa memerlukan hak istimewa *root mount* (`mount -o loop`).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Dekompresi & Analisis Tabel Partisi:**
   ```bash
   gunzip disk.img.gz
   mmls disk.img
   ```
   Partisi Linux utama terletak pada offset sektor `206848`.
2. **Enumerasi Direktori dengan `fls`:**
   ```bash
   fls -o 206848 disk.img
   # Menemukan direktori root pada Inode 470
   fls -o 206848 disk.img 470
   # Menemukan direktori .ssh pada Inode 3916
   fls -o 206848 disk.img 3916
   # Menemukan berkas id_ed25519 pada Inode 2345
   ```
3. **Ekstraksi Kunci Privat menggunakan `icat`:**
   ```bash
   icat -o 206848 disk.img 2345 > /tmp/oni_key
   chmod 600 /tmp/oni_key
   ```
4. **Otentikasi SSH Jarak Jauh:**
   ```bash
   ssh -i /tmp/oni_key -p 11622 ctf-player@xebec.cylabacademy.net 'cat flag.txt'
   ```
   Mengembalikan string flag: `academy{k3y_5l3u7h_0e000cd7}`.

---

## Flag & Verifikasi

- **Flag:** `academy{k3y_5l3u7h_0e000cd7}`
- **Hasil Submission:**
  ```json
  {"user": 1072359, "challenge": 284, "flag": "academy{k3y_5l3u7h_0e000cd7}", "correct": true, "historical": false}
  ```

---

## Remediasi & Mitigasi (Perspektif Defensive LKS)

1. Enkripsi seluruh kunci privat SSH menggunakan passphrase kuat berbasis algoritma derivasi kunci modern (misalnya argon2id atau bcrypt).
2. Jangan pernah menyimpan salinan kunci akses master atau root SSH di dalam citra sistem publik atau media yang tidak terlindungi enkripsi disk penuh (LUKS/dm-crypt).
3. Terapkan prinsip rotasi kunci berkala dan nonaktifkan akses SSH berbasis kunci yang telah terkompromi melalui revocation list / authorized_keys scrubbing.
