# Writeup: DISKO 1 (Challenge ID: 505)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Disk Image Analysis
- **Difficulty:** Easy
- **Author:** Darkraicg492
- **Event:** General
- **Points:** 1
- **Flag:** `academy{1t5_ju5t_4_5tr1n9_19d7626c}`

---

## Deskripsi Tantangan
> Can you find the flag in this disk image?
> Download the disk image `disko-1.dd.gz`.
> Hints:
> 1. Maybe Strings could help? If only there was a way to do that?

---

## Analisis Kerentanan & Konsep Teknis
Citra disk mentah (*raw image* `.dd`) merupakan salinan bit-by-bit dari media penyimpanan fisik (hard disk, flash drive). Pada investigasi forensik disk, artefak teks yang belum terhapus, berkas sementara, atau unallocated space sering kali masih menyimpan string sensitif dalam teks biasa (*plaintext*).

Sebelum melakukan analisis sistem berkas mendalam menggunakan The Sleuth Kit (`fls`, `icat`) atau Autopsy, langkah triase awal forensik adalah melakukan pemindaian string langsung (*bulk string extraction*) terhadap keseluruhan citra biner.

---

## Tahapan Eksploitasi & Solusi
1. Dekompresi berkas arsip `disko-1.dd.gz`:
   ```bash
   gunzip -k disko-1.dd.gz
   ```
2. Ekstraksi string yang mengandung pola flag `academy{`:
   ```bash
   strings disko-1.dd | grep "academy{"
   ```
   Atau dengan pencarian langsung pada offset biner:
   ```bash
   grep -a -b -o "academy{[^}]*}" disko-1.dd
   ```
3. Flag langsung ditemukan pada offset biner `29779344`:
   ```text
   academy{1t5_ju5t_4_5tr1n9_19d7626c}
   ```

---

## Pembelajaran Defensif & Mitigasi LKS
- **Data Sanitization & Disk Wiping:** Menghapus berkas melalui file manager atau perintah `rm` hanya melepaskan pointer metadata (inode), sedangkan data aktual tetap berada pada disk. Untuk mencegah pemulihan data forensik, disk wajib di-wipe menggunakan standar sanitasi (seperti DoD 5220.22-M atau NIST SP 800-88 `shred`/`blkdiscard`).
- **Enkripsi Penuh Media (Full Disk Encryption):** Menerapkan LUKS atau BitLocker memastikan bahwa pembacaan fisik/mentah dari citra disk tidak membocorkan data teks biasa kepada pihak tidak berwenang.
