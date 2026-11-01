# Writeup: Operation Orchid (Challenge ID: 285)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Disk Image Analysis & Artifact Decryption
- **Difficulty:** Medium
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 400
- **Flag:** `academy{h4un71ng_p457_0b36d810}`

---

## Problem Statement & Scope
Diberikan sebuah berkas citra disk terkompresi (`disk.flag.img.gz`). Peserta diminta menganalisis struktur partisi dan sistem berkas citra disk untuk menemukan flag tersembunyi. Pelaku diasumsikan telah mengenkripsi berkas flag dan menghapus berkas sumber sebelum mematikan mesin.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyimpanan Jejak Eksekusi Perintah (.ash_history):** Pada distribusi Linux berbasis BusyBox / Alpine Linux, riwayat perintah shell yang dijalankan pengguna dicatat dalam berkas `.ash_history` di direktori profil pengguna. Meskipun berkas data asli (`flag.txt`) telah dihapus secara aman menggunakan utilitas penghapus secure deletion (`shred`), riwayat eksekusi perintah masih tersimpan utuh di disk karena pelaku tidak membersihkan berkas riwayat shell sebelum menghentikan sistem (`halt`).
2. **Ketergantungan Keamanan pada Kunci Simetris Plaintext:** Pelaku melakukan enkripsi data menggunakan OpenSSL dengan cipher AES-256-CBC, namun menyematkan kunci sandi langsung pada baris perintah via parameter `-k unbreakablepassword1234567`. Hal ini meninggalkan kunci enkripsi terekspos langsung pada riwayat proses dan berkas konfigurasi shell pengguna.
3. **Persistensi Inode Sistem Berkas Ext4:** Operasi penghapusan berkas melalui `shred -u` merusak isi blok data berkas sumber dan membatalkan alokasi inode, namun berkas hasil enkripsi (`flag.txt.enc`) tetap dialokasikan secara sempurna pada tabel inode sistem berkas partisi Linux.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Dekompresi berkas citra disk:
   ```bash
   gunzip -k disk.flag.img.gz
   ```
2. Analisis tabel partisi menggunakan `mmls` dari The Sleuth Kit:
   ```bash
   mmls disk.flag.img
   ```
   Ditemukan tabel partisi DOS dengan partisi Linux pada sektor 411648 (panjang 407552 sektor).
3. Inspeksi sistem berkas pada partisi Linux (offset sektor 411648) menggunakan `fls`:
   ```bash
   fls -o 411648 -r disk.flag.img | grep -E "(flag|\.ash_history)"
   ```
   Daftar inode yang relevan:
   - Inode `1875`: `.ash_history` di direktori root
   - Inode `1782`: `flag.txt.enc`
   - Inode `1876`: `flag.txt` (terhapus dan teralokasi ulang)
4. Ekstraksi riwayat perintah root via `icat`:
   ```bash
   icat -o 411648 disk.flag.img 1875
   ```
   Output riwayat perintah:
   ```text
   touch flag.txt
   nano flag.txt 
   apk get nano
   apk --help
   apk add nano
   nano flag.txt 
   openssl
   openssl aes256 -salt -in flag.txt -out flag.txt.enc -k unbreakablepassword1234567
   shred -u flag.txt
   ls -al
   halt
   ```
5. Ekstraksi berkas ciphertext `flag.txt.enc`:
   ```bash
   icat -o 411648 disk.flag.img 1782 > flag.txt.enc
   ```
6. Dekripsi berkas `flag.txt.enc` menggunakan OpenSSL dengan cipher AES-256-CBC dan message digest SHA-256:
   ```bash
   openssl enc -d -aes-256-cbc -salt -in flag.txt.enc -k unbreakablepassword1234567 -md sha256
   ```
   Hasil dekripsi menampilkan flag resmi:
   ```text
   academy{h4un71ng_p457_0b36d810}
   ```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{h4un71ng_p457_0b36d810}`
- **Verifikasi:** Endpoint REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 285, "flag": "academy{h4un71ng_p457_0b36d810}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Forensik Citra Disk dan Analisis Antiforensik:** Pada modul Digital Forensics LKS Cyber Security, investigasi jejak penghapusan data sering kali menemukan teknik antiforensik seperti *secure file shredding*. Analis harus selalu memeriksa artefak sekunder seperti riwayat shell (`.bash_history`, `.ash_history`), syslog, dan swap space yang berpotensi menyimpan kunci kriptografi atau parameter eksekusi.
- **Pembersihan Lingkungan Shell dan Key Management:** Dari perspektif pengerasan sistem (*defensive hardening*), administrator tidak boleh memasukkan kredensial atau passphrase secara langsung melalui argumen baris perintah karena dapat terekam dalam process list (`ps aux`) dan riwayat shell. Pastikan opsi `HISTFILESIZE=0` atau redirect `/dev/null` diaktifkan pada sesi penanganan data sensitif, serta gunakan manajemen kunci berbasis KMS atau berkas terproteksi dengan hak akses ketat (chmod 600).
