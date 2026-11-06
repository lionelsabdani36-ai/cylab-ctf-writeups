# Writeup: Disk, disk, sleuth! II (Challenge ID: 137)

- Platform: CyLab Security Academy (picoCTF)
- Category: Forensics / SleuthKit Alpine Linux Inode Carving
- Difficulty: Medium (diff=2)
- Author: syreal
- Event: picoCTF 2021
- Points: 130
- Flag: `academy{f0r3ns1c4t0r_n0v1c3_95c645ad}` (Komunitas: `CTF{f0r3ns1c4t0r_n0v1c3_95c645ad}`)

---

## Problem Statement & Scope

Tantangan menguji kompetensi investigasi sistem berkas Linux (*Linux Filesystem Forensics*) menggunakan perangkat *The Sleuth Kit* (TSK):
> *"All we know is the file with the flag is named `down-at-the-bottom.txt`..."*
> 
> File target: `dds2-alpine.flag.img.gz`
> 
> Petunjuk:
> 1. *"The sleuthkit has some great tools for this challenge as well."*
> 2. *"Sleuthkit docs here are so helpful: [TSK Tool Overview](http://wiki.sleuthkit.org/index.php?title=TSK_Tool_Overview)"*
> 3. *"This disk can also be booted with qemu!"*

Peserta diberikan citra disk Alpine Linux terkompresi Gzip. Berbeda dengan tantangan edisi pertama yang dapat dipecahkan melalui *bulk string carving*, pada skenario ini teks flag telah dienkapsulasi ke dalam struktur berkas tersembunyi `down-at-the-bottom.txt` dengan format ASCII art yang terpecah antarkarakter, menuntut navigasi struktur *inode* dan pemetaan sektor partisi secara tepat.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Partisi DOS MBR & Offset Sektor Fisik (NIST SP 800-115 Section 5.4):**
   - Berdasarkan NIST SP 800-115 (*Section 5.4: Media Analysis and Data Recovery*), analisis forensik citra disk mentah (*raw image*) diawali dengan identifikasi skema partisi (Master Boot Record / DOS Partition Table).
   - Perkakas TSK `mmls` membaca *partition table* pada sektor 0 untuk menentukan batas awal (*start sector*) dari partisi sistem berkas yang dapat diakses. Pada citra ini, partisi Linux native (tipe `0x83`) berawal pada sektor 2048 (offset fisik: $2048 \times 512 = 1{,}048{,}576$ byte).
   - Analisis forensik memerlukan parameter `-o 2048` agar perintah tingkat lanjut membaca metadata relatif terhadap awal partisi Linux, bukan MBR.

2. **Hierarki Direktori Ext3/Ext4 & Resolusi Inode TSK:**
   - Dalam arsitektur sistem berkas Linux, direktori memetakan nama berkas ke nomor *inode* tertentu. Perintah `fls` melintasi (*traverses*) struktur pohon direktori tanpa memerlukan hak akses *root* atau *loopback mounting* (`mount -o loop`).
   - Berkas `down-at-the-bottom.txt` dialokasikan pada inode `18291`. Menggunakan utilitas `icat`, analis forensik dapat mengekstraksi aliran data mentah (*data streams*) langsung dari blok data inode target tanpa mengeksekusi sistem operasi tamu.

3. **Obfuskasi Visual Berbasis Balon Teks ASCII:**
   - Penulis tantangan mengonstruksi isi berkas dalam bentuk *ASCII balloon art* di mana setiap karakter diapit tanda kurung `( c )`. Pendekatan ini menggagalkan pencarian string linear sederhana (`grep "academy{"`), namun rentan terhadap parsing ekspresi reguler struktural.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Dekompresi Arsip Citra Disk:**
   - Unduh dan dekompresi arsip target:
     ```bash
     gzip -d dds2-alpine.flag.img.gz
     # Menghasilkan citra mentah berukuran 134,217,728 bytes (128 MB)
     ```

2. **Inspeksi Tata Letak Partisi Menggunakan `mmls`:**
   - Jalankan pemeriksaan MBR:
     ```bash
     mmls dds2-alpine.flag.img
     ```
   - *Output:*
     ```text
     DOS Partition Table
     Offset Sector: 0
     Units are in 512-byte sectors

           Slot      Start        End          Length       Description
     000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
     001:  -------   0000000000   0000002047   0000002048   Unallocated
     002:  000:000   0000002048   0000262143   0000260096   Linux (0x83)
     ```
   - Partisi Linux berada pada sektor awal **2048**.

3. **Pelacakan Inode Berkas `down-at-the-bottom.txt` Melalui `fls`:**
   - Lakukan pencarian rekursif berkas dalam partisi sektor 2048:
     ```bash
     fls -r -o 2048 dds2-alpine.flag.img | grep "down-at-the-bottom.txt"
     ```
   - *Output:*
     ```text
     + r/r 18291:    down-at-the-bottom.txt
     ```
   - Ditemukan penanda inode: **18291**.

4. **Ekstraksi Data Inode Menggunakan `icat`:**
   - Ekstrak isi berkas berdasarkan offset sektor dan nomor inode:
     ```bash
     icat -o 2048 dds2-alpine.flag.img 18291
     ```
   - *Output:*
     ```text
     _     _     _     _     _     _     _     _     _     _     _     _     _  
       / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \ 
      ( a ) ( c ) ( a ) ( d ) ( e ) ( m ) ( y ) ( { ) ( f ) ( 0 ) ( r ) ( 3 ) ( n )
       \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/ 
        _     _     _     _     _     _     _     _     _     _     _     _     _  
       / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \ 
      ( s ) ( 1 ) ( c ) ( 4 ) ( t ) ( 0 ) ( r ) ( _ ) ( n ) ( 0 ) ( v ) ( 1 ) ( c )
       \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/ 
        _     _     _     _     _     _     _     _     _     _     _  
       / \   / \   / \   / \   / \   / \   / \   / \   / \   / \   / \ 
      ( 3 ) ( _ ) ( 9 ) ( 5 ) ( c ) ( 6 ) ( 4 ) ( 5 ) ( a ) ( d ) ( } )
       \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/   \_/
     ```

5. **Rekonstruksi Karakter Flag:**
   - Mengambil karakter di dalam tanda kurung baris 3, 7, dan 11 menghasilkan string utuh:
     `academy{f0r3ns1c4t0r_n0v1c3_95c645ad}`

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{f0r3ns1c4t0r_n0v1c3_95c645ad}`
- **Flag Komunitas:** `CTF{f0r3ns1c4t0r_n0v1c3_95c645ad}`
- **Bukti Validasi:** REST API CyLab `POST /api/submissions/` mengembalikan konfirmasi HTTP 201:
  ```json
  {"user": 1072359, "challenge": 137, "flag": "academy{f0r3ns1c4t0r_n0v1c3_95c645ad}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Penerapan Toolset TSK untuk Triage Cepat di LKS Cyber Security:**
   - Pada kompetensi LKS modul *Host Forensics*, peserta sering kali diuji untuk menemukan berkas bukti tersembunyi (*hidden/deleted files*) dalam citra berukuran gigabyte dalam batasan waktu ketat. Kombinasi `mmls`, `fls`, dan `icat` memberikan waktu respons jauh lebih cepat dibandingkan pengindeksan penuh (*full indexing*) GUI forensik.
2. **Pengawasan Hak Akses Sistem Berkas & Atribut Immutability:**
   - Lindungi berkas sensitif dari pengubahan atau penghapusan oleh *threat actor* dengan menetapkan izin ketat (`chmod 600`) serta atribut *immutable* sistem berkas Linux (`chattr +i`).
3. **Penyimpanan Kredensial & Secrets Management:**
   - Hindari menyimpan berkas rahasia berbasis teks di dalam direktori penyimpanan statis. Gunakan solusi berkubah seperti HashiCorp Vault atau Docker Secrets dengan rotasi otomatis.

---

## Solver Script

Solusi reproduktif terverifikasi tersedia pada:
`scripts/solve_137_disk_disk_sleuth_2.py`
