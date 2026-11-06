# Writeup: Bitlocker-2 (Challenge ID: 454)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics
- **Difficulty:** Medium
- **Event:** picoCTF 2025
- **Points:** 300
- **Author:** CyLab Engineering Team
- **Flag:** `academy{B1tl0ck3r_dr1v3_d3crypt3d_9029ae5b}`

---

## Problem Statement & Scope
Setelah menyadari kelemahan kata sandi sederhana pada tantangan sebelumnya, pengguna (Jacky) memperbarui pengamanan volume BitLocker dengan kata sandi yang sangat panjang dan berkekuatan kriptografi tinggi sehingga serangan brute-force atau kamus luring menjadi tidak fisibel. Namun, tim investigator forensik berhasil menangkap dump memori volatil fisik (`memdump.mem.gz`) pada saat drive terenkripsi (`bitlocker-2.dd`) sedang dalam kondisi terbuka dan terpasang (mounted). Tujuan analisis adalah melakukan forensik memori untuk merekonstruksi kunci enkripsi Full Volume Encryption Key (FVEK) atau mengekstrak isi plaintext `flag.txt` yang tersimpan dalam cache memori fisik.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Volatile Memory Residuals & Key Material Exposure (CWE-312 / CWE-214):**
   Arsitektur BitLocker bekerja pada tingkat filter driver (`fvevol.sys`) di atas driver disk (`volmgr.sys`). Saat volume BitLocker dalam status aktif/unlocked, kunci enkripsi simetris AES-XTS (FVEK) harus disimpan di memori non-paged pool kernel Windows agar sistem operasi dapat mengenkripsi dan mendekripsi blok disk secara real-time. Jika penyerang memperoleh akses ke citra memori fisik (melalui serangan cold-boot, DMA injection, atau live acquisition), material kunci FVEK dapat dipulihkan secara langsung.
2. **File System Cache & Buffer Residue in Physical RAM:**
   Selain kunci FVEK, subsistem manajemen cache file Windows (`Cache Manager` / `ntfs.sys`) menyimpan blok data file yang baru saja dibaca atau ditulis di dalam physical memory pages. Akibatnya, isi file rahasia yang telah diakses saat volume terbuka tetap tertinggal di RAM dalam bentuk plaintext hingga ditimpa oleh aktivitas alokasi memori berikutnya.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Metode 1: Rapid Forensic Triage (Memory Buffer Carving)
Karena berkas `flag.txt` sempat dibuka saat volume terpasang, string bendera kompetisi berada di buffer cache memori fisik:
1. Ekstrak kompresi berkas memori:
   ```bash
   gzip -d memdump.mem.gz
   # atau stream langsung: zcat memdump.mem.gz
   ```
2. Ekstraksi string dengan pengkodean ASCII dan UTF-16LE:
   ```bash
   strings -el memdump.mem | grep -iE 'picoCTF\{' | sort -u
   # atau pola byte raw:
   strings memdump.mem | grep -oE 'picoCTF\{[^}]+\}' | sort -u
   ```
3. Perintah di atas langsung menghasilkan bendera rahasia yang tersisa di memory cache:
   ```text
   picoCTF{B1tl0ck3r_dr1v3_d3crypt3d_9029ae5b}
   ```

### Metode 2: Rekonstruksi FVEK via Volatility Framework
Untuk merekonstruksi alur forensik disk penuh:
1. Jalankan plugin Volatility BitLocker terhadap citra RAM:
   ```bash
   python2 vol.py -f memdump.mem --profile=Win10x64_19041 bitlocker --dislocker ./dumps
   ```
   Output analisis memvalidasi FVEK yang aktif:
   ```text
   [FVEK] Address : 0x8087865bead0
   [FVEK] Cipher  : AES-XTS 128 bit (Win 10+)
   [FVEK] FVEK    : 5b6ff64e4a0ee8f89050b7ba532f6256
   [DISL] FVEK for Dislocker dumped to file: ./dumps/0x8087865bead0-Dislocker.fvek
   ```
2. Mount citra disk BitLocker `bitlocker-2.dd` menggunakan kunci FVEK hasil ekstraksi memori:
   ```bash
   sudo mkdir -p /mnt/bitlocker /mnt/decrypted
   sudo dislocker -V bitlocker-2.dd -k ./dumps/0x8087865bead0-Dislocker.fvek -- /mnt/bitlocker
   sudo mount -t ntfs-3g -o loop /mnt/bitlocker/dislocker-file /mnt/decrypted
   ```
3. Akses berkas yang berhasil didekripsi:
   ```bash
   cat /mnt/decrypted/flag.txt
   # picoCTF{B1tl0ck3r_dr1v3_d3crypt3d_9029ae5b}
   ```
   Disesuaikan ke format resmi platform CyLab: `academy{B1tl0ck3r_dr1v3_d3crypt3d_9029ae5b}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{B1tl0ck3r_dr1v3_d3crypt3d_9029ae5b}`
- **Native PicoCTF Flag:** `picoCTF{B1tl0ck3r_dr1v3_d3crypt3d_9029ae5b}`
- **FVEK Key:** `5b6ff64e4a0ee8f89050b7ba532f6256` (AES-XTS 128-bit)
- **Status Solver:** Terverifikasi melalui skrip pengujian reproduktif `scripts/solve_454_bitlocker_2.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Perlindungan Terhadap Direct Memory Access (DMA Attacks):**
  Aktifkan proteksi Kernel DMA Protection (IOMMU / VT-d) pada firmware UEFI untuk memblokir perangkat eksternal (Thunderbolt, PCIe, FireWire) membaca memori fisik tanpa otorisasi sistem operasi.
- **Konfigurasi State Daya Rendah (Sleep vs Hibernate):**
  Hindari membiarkan sistem enterprise dalam mode Modern Standby atau Standby biasa (S3) saat membawa volume terenkripsi di lingkungan publik. Terapkan mode Hibernate (S4) dengan proteksi TPM+PIN sehingga memori fisik dibersihkan atau dienkripsi sebelum shutdown daya.
- **Zeroization Kunci pada Volume Dismount:**
  Terapkan kebijakan penonaktifan/unmount volume sensitif otomatis setelah periode idle tertentu untuk memastikan bahwa blok FVEK segera di-zeroized (dibersihkan) dari memori kernel non-paged pool.
