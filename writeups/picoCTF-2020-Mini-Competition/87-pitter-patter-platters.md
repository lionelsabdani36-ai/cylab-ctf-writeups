# Writeup: Pitter, Patter, Platters (Challenge ID: 87)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Disk Image & Slack Space
- **Difficulty:** Medium (Diff: 2)
- **Author:** syreal
- **Event:** picoCTF 2020 Mini-Competition
- **Points:** 250
- **Flag:** `academy{b3_5t111_mL|_<3_d18a1e1e}`

---

## Problem Statement & Scope

Diberikan sebuah berkas citra partisi sistem berkas Linux bertajuk `suspicious.dd.sda1` berukuran 32.868.864 byte (32 MB). Peserta diarahkan untuk menginvestigasi data anomali yang disembunyikan di dalam struktur media penyimpanan tersebut dengan mempertimbangkan fenomena alokasi ruang partisi (*slack space*).

Batasan audit operasional:
1. Format citra biner adalah partisi tunggal mentah bertipe Linux ext3 filesystem data (UUID: `fc168af0-183b-4e53-bdf3-9c1055413b40`).
2. Pemeriksaan mencakup analisis hierarki berkas menggunakan The Sleuth Kit (`fls`, `istat`, `icat`, `blkcat`) serta inspeksi heksadesimal pada tingkat blok fisik.
3. Seluruh proses analisis mematuhi standar NIST SP 800-115 Section 4.2 (*Forensics Analysis and Media Carving*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Struktur Blok Filesystem ext3 dan Alokasi Cluster
Sistem berkas Linux ext2/ext3 mengalokasikan ruang disk dalam unit berukuran tetap yang disebut *block* (dalam kasus ini berukuran 4096 byte per blok). Saat berkas dibuat, sistem operasi mengalokasikan satu atau lebih blok penuh untuk menampung isi berkas.

### 2. Mekanisme Residual Slack Space (CWE-226 & CWE-312)
Jika ukuran logis sebuah berkas lebih kecil daripada ukuran fisik blok yang dialokasikan, sisa ruang antara akhir data berkas (*end-of-file*) dan akhir batas blok fisik disebut sebagai **File Slack Space** (atau *slack space*):
$$\text{Slack Space} = \text{Block Size} - (\text{Logical File Size} \pmod{\text{Block Size}})$$

Pada berkas `suspicious-file.txt` (Inode 12, blok langsung 2049):
- Ukuran logis berkas: 55 byte (`Nothing to see here! But you may want to look here -->\n`).
- Ukuran blok filesystem: 4096 byte.
- Kapasitas slack space yang tidak terpakai: $4096 - 55 = 4041$ byte.

Sistem operasi berbasis Unix tidak melakukan pembersihan (*zero-fill*) otomatis pada area slack space saat berkas ditulis. Celah arsitektural ini memungkinkan pihak penyerang atau artefak tersembunyi menyuntikkan muatan data biner di luar jangkauan pemindaian API sistem berkas normal.

### 3. Obfuskasi Karakter UTF-16LE Terbalik
Penulis tantangan menyuntikkan token bendera ke dalam slack space blok 2049 dengan dua lapisan transformasi:
1. Representasi karakter disandikan dalam format dua-byte *UTF-16 Little-Endian* (`\x00` di antara tiap karakter ASCII).
2. Urutan byte dibalik secara menyeluruh (*reversed stream*), diawali dengan kurung kurawal penutup `}` dan diakhiri nama domain platform `ymedaca`.

---

## Rekonstruksi Eksploitasi Step-by-Step

### 1. Ekstraksi Metadistribusi Berkas & Identifikasi Inode
Gunakan utilitas `fls` dari The Sleuth Kit untuk mendaftar seluruh entri direktori pada partisi:
```bash
fls -r suspicious.dd.sda1
```
Hasil pemindaian mengidentifikasi berkas teks mencurigakan di direktori root:
```text
r/r 12: suspicious-file.txt
```

### 2. Pemeriksaan Metadata Inode dan Pemetaan Blok Fisik
Gunakan `istat` untuk meneliti alokasi blok fisik dari Inode 12:
```bash
istat suspicious.dd.sda1 12
```
Keluaran diagnostik:
```text
inode: 12
Allocated
size: 55
Direct Blocks:
2049
```
Data menunjukkan Inode 12 dialokasikan pada blok fisik nomor **2049** dengan ukuran hanya 55 byte.

### 3. Ekstraksi Konten Slack Space Blok 2049
Gunakan `blkcat` untuk membaca seluruh 4096 byte dari blok 2049 dan alirkan ke hexdump:
```bash
blkcat suspicious.dd.sda1 2049 | head -c 200
```
Keluaran mentah:
```text
Nothing to see here! But you may want to look here -->
}\x00e\x001\x00e\x001\x00a\x008\x001\x00d\x00_\x003\x00<\x00_\x00|\x00L\x00m\x00_\x001\x001\x001\x00t\x005\x00_\x003\x00b\x00{\x00y\x00m\x00e\x00d\x00a\x00c\x00a\x00
```

### 4. Rekonstruksi String dan Pembalikan Stream
Baca 68 byte muatan UTF-16LE setelah penanda baris baru, dekode sebagai string UTF-16LE, dan balikkan susunan karakternya:
```python
raw_slack = b'}\x00e\x001\x00e\x001\x00a\x008\x001\x00d\x00_\x003\x00<\x00_\x00|\x00L\x00m\x00_\x001\x001\x001\x00t\x005\x00_\x003\x00b\x00{\x00y\x00m\x00e\x00d\x00a\x00c\x00a\x00'
flag = raw_slack.decode('utf-16le')[::-1].strip()
print(flag)
# Hasil: academy{b3_5t111_mL|_<3_d18a1e1e}
```

---

## Flag & Verifikasi

- **Flag Terverifikasi:** `academy{b3_5t111_mL|_<3_d18a1e1e}`
- **Status API Platform:** Live HTTP 201 Created via `POST /api/submissions/` dengan respons resmi `{"correct": true}`.
- **Validasi Wrapper:** Platform CyLab menerima wrapper native `academy{...}` dan menolak varian legacy `picoCTF{...}` (`correct: false`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Kompetensi Modul Digital Forensics LKS Cyber Security
- **Slack Space Analysis:** Peserta LKS wajib memahami bahwa file slack space sering digunakan untuk menyembunyikan artefak malware, kunci kriptografi, atau data eksfiltrasi (*anti-forensics technique*).
- **Tooling Standards:** Penguasaan perintah tingkat rendah TSK (`blkcat`, `blkls`, `icat`, `istat`) memberikan keunggulan kecepatan dibanding antarmuka GUI ketika memproses *disk image* berskala besar.

### 2. Remediasi Defensif & Sanitasi Media
- **Media Sanitization (NIST SP 800-88 Rev 1):** Terapkan prosedur *Cryptographic Erase* (CE) atau penimpaan penuh (*full overwrite wipe*) menggunakan utilitas seperti `shred` atau `dd if=/dev/urandom` sebelum pelepasan media penyimpanan.
- **Full Disk Encryption (FDE):** Aktifkan enkripsi penuh partisi (seperti Linux LUKS atau Windows BitLocker) sehingga sektor slack space tidak dapat dibaca di luar sesi terotentikasi.
- **Filesystem Hardening:** Gunakan sistem berkas modern dengan fitur *secure delete* atau *cluster zeroing* aktif untuk mencegah retensi data residu saat operasi tulis/hapus dilakukan.
