# Writeup: Bitlocker-1 (Challenge ID: 453)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics
- **Difficulty:** Medium
- **Event:** picoCTF 2025
- **Points:** 200
- **Author:** CyLab Engineering Team
- **Flag:** `academy{us3_b3tt3r_p4ssw0rd5_pl5!_3242adb1}`

---

## Problem Statement & Scope
Peserta diberikan sebuah citra disk mentah (`bitlocker-1.dd`) yang diamankan menggunakan BitLocker Full Volume Encryption (FVE). Deskripsi tantangan menyebutkan bahwa pemilik drive (Jacky) memilih kata sandi yang sederhana untuk mengenkripsi volume tersebut. Tujuan forensik adalah mengekstrak artefak protektor BitLocker, melakukan audit kekuatan kredensial, mendekripsi volume virtual, dan membaca file `flag.txt` yang tersimpan di dalamnya.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Weak Password Protector & Offline Dictionary Vulnerability (CWE-521 / CWE-326):**
   Mekanisme BitLocker membungkus Full Volume Encryption Key (FVEK) menggunakan Volume Master Key (VMK), yang selanjutnya dapat dilindungi oleh berbagai jenis protektor, termasuk User Password (PIN/Password). Metadata protektor ini disimpan secara terstruktur di area metadata header volume BitLocker. Jika kata sandi pengguna memiliki entropi rendah atau berbasis kata kamus (dictionary word), penyerang dapat mengekstrak hash protektor dan melakukan serangan kamus secara luring (offline brute-force attack) tanpa batas percobaan lockout.
2. **Kepatuhan NIST SP 800-63B & NIST SP 800-115:**
   Sesuai standar verifikasi autentikasi NIST SP 800-63B, penggunaan kata sandi yang mudah ditebak tanpa proteksi perangkat keras (TPM/Hardware Token) melanggar prinsip ketahanan autentikator. Dalam metodologi pengujian teknis NIST SP 800-115 Bagian 5 (Forensics Analysis), ekstraksi protektor dan pengujian kekuatan hash merupakan prosedur standar untuk mengevaluasi efektivitas enkripsi at-rest.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Verifikasi Citra Disk dan Header Enkripsi:**
   Periksa tipe file citra menggunakan utilitas `file`:
   ```bash
   file bitlocker-1.dd
   # Output: bitlocker-1.dd: DOS/MBR boot sector, code offset 0x58+2, OEM-ID "-FVE-FS-", sectors/track 0, heads 0, sectors 2097152 (volumes <=32 MB), FAT (0 bit), sectors/FAT 0, serial number 0x0, unlabeled
   ```
   Tanda `-FVE-FS-` menegaskan bahwa partisi ini diproteksi oleh Windows Full Volume Encryption (BitLocker).

2. **Ekstraksi Hash Protektor BitLocker:**
   Gunakan alat forensik `bitlocker2john` untuk mengekstrak hash protektor kata sandi pengguna dari metadata citra:
   ```bash
   bitlocker2john -i bitlocker-1.dd > bitlocker_hash.txt
   cat bitlocker_hash.txt
   # $bitlocker$0$16$cb4809fe9628471a411f8380e0f668db$1048576$12$d04d9c58eed6da010a000000$60$68156e51...
   ```

3. **Pemecahan Hash Luring (Offline Hash Cracking):**
   Jalankan Hashcat dengan mode BitLocker User Password (`22100`) menggunakan daftar kata `rockyou.txt`:
   ```bash
   hashcat -m 22100 -a 0 bitlocker_hash.txt /usr/share/wordlists/rockyou.txt
   ```
   Dalam waktu singkat, Hashcat menemukan kata sandi asli:
   ```text
   $bitlocker$0$16$...:jacqueline
   Status...........: Cracked
   ```

4. **Dekripsi dan Mount Volume Disk:**
   Gunakan utilitas `dislocker` pada Linux untuk mendekripsi volume dengan kata sandi yang ditemukan:
   ```bash
   sudo mkdir -p /mnt/dislocker /mnt/decrypted
   sudo dislocker -V bitlocker-1.dd -ujacqueline -- /mnt/dislocker
   sudo mount -o loop /mnt/dislocker/dislocker-file /mnt/decrypted
   ```

5. **Ekstraksi Flag:**
   Setelah direktori berhasil di-mount, baca file `flag.txt`:
   ```bash
   cat /mnt/decrypted/flag.txt
   # picoCTF{us3_b3tt3r_p4ssw0rd5_pl5!_3242adb1}
   ```
   Disesuaikan ke format platform CyLab: `academy{us3_b3tt3r_p4ssw0rd5_pl5!_3242adb1}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{us3_b3tt3r_p4ssw0rd5_pl5!_3242adb1}`
- **Native PicoCTF Flag:** `picoCTF{us3_b3tt3r_p4ssw0rd5_pl5!_3242adb1}`
- **Password Volume:** `jacqueline`
- **Status Solver:** Terverifikasi melalui skrip reproduktif `scripts/solve_453_bitlocker_1.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Penerapan TPM (Trusted Platform Module) Hardware Security:**
  Hindari mengandalkan protektor berbasis kata sandi murni untuk enkripsi disk penuh. Terapkan proteksi berbasis TPM 2.0 dengan PIN alfanumerik yang diperkuat agar kunci dekripsi dilindungi secara fisik di dalam silicon modul hardware.
- **Kebijakan Kompleksitas Kredensial Enkripsi:**
  Terapkan Group Policy Objects (GPO) untuk mewajibkan panjang minimum password BitLocker setidaknya 20 karakter alfanumerik acak, atau gunakan Recovery Key 48-digit acak deterministik.
- **Pertahanan Terhadap Serangan Forensik Luring:**
  Pastikan perangkat membatasi akses DMA (Direct Memory Access) eksternal dan mengaktifkan BitLocker Network Unlock dalam jaringan korporat terisolasi guna meminimalisasi risiko ekstraksi header volume saat perangkat dalam status non-aktif.
