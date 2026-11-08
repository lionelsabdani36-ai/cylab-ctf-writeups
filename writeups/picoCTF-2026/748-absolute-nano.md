# Writeup: ABSOLUTE NANO (Challenge ID: 748)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Linux Privilege Escalation & Sudo Capability Abuse (NIST SP 800-115 §4.5)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{n4n0_411_7h3_w4y_81311b87}`
- **Flag Komunitas:** `CTF{n4n0_411_7h3_w4y_81311b87}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan audit eskalasi hak istimewa (*Privilege Escalation*) pada lingkungan sistem operasi Linux dalam kerangka kepatuhan NIST SP 800-115:
> *"You have complete power with nano. Think you can get the flag?"*

Lingkungan target berupa kontainer Linux on-demand yang diakses melalui protokol SSH (`ctf-player@<host> -p <port>`). Target berkas flag `/home/ctf-player/flag.txt` dimiliki oleh user `root:root` dengan izin akses terbatas `0440` (`-r--r-----`), sehingga pengguna biasa `ctf-player` tidak dapat membaca berkas secara langsung.

Audit konfigurasi delegasi hak istimewa pengguna (`sudo -l`) memperlihatkan aturan spesifik:
```text
Matching Defaults entries for ctf-player on instance:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ctf-player may run the following commands on instance:
    (ALL) NOPASSWD: /bin/nano /etc/sudoers
```

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Insecure Sudo Delegation (CWE-269 - Improper Privilege Management & CWE-250 - Execution with Unnecessary Privileges):**
   - Administrator bermaksud memberikan hak kepada user `ctf-player` untuk menyunting berkas konfigurasi `/etc/sudoers` tanpa memasukkan kata sandi.
   - Namun, memberikan hak eksekusi `sudo` pada biner editor teks interaktif (*interactive text editor*) seperti `nano` memberikan kapabilitas eksekusi yang jauh lebih luas daripada sekadar menyunting target argumen yang ditentukan.
   - Pola ini merupakan kerentanan klasik yang terdokumentasi dalam repositori GTFOBins (*Unix Binaries Living-off-the-Land*).

2. **Kapabilitas Arbitrary File Read Internal nano (`^R` / Read File):**
   - Editor `nano` memiliki fitur bawaan untuk menyisipkan berkas eksternal ke dalam buffer penyuntingan aktif melalui pintasan `Ctrl+R` (`^R`, *Read File*).
   - Ketika `nano` dijalankan di bawah `sudo`, proses berjalan dengan UID efektif 0 (`root`). Konsekuensinya, operasi pembacaan berkas internal melewati pembatasan izin DAC (*Discretionary Access Control*) pada sistem berkas lokal.
   - Tanpa perlu melakukan pelarian shell (*shell escape*) atau memodifikasi berkas `/etc/sudoers`, penyerang dapat membaca berkas sensitif milik root mana pun (seperti `/etc/shadow` atau `/home/ctf-player/flag.txt`) langsung ke dalam buffer tampilan layar editor.

3. **Perilaku Karakter Kontrol PTY (Carriage Return vs Newline Quirk):**
   - Dalam otomasi interaktif berbasis pseudo-terminal (PTY), prompt masukan nama berkas nano (`File to insert: `) memerlukan karakter Carriage Return (`\r` / `0x0D`) untuk mengonfirmasi pilihan input.
   - Mengirimkan karakter Line Feed / Newline standar (`\n` / `0x0A`) akan menyebabkan pustaka rendering ncurses nano membeku (*freeze*), menghasilkan tampilan layar kosong meskipun proses koneksi tetap hidup.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Reconnaissance & Evaluasi Hak Akses Sudo:**
   - Masuk ke lingkungan target via SSH:
     ```bash
     sshpass -p "<password>" ssh -p <port> ctf-player@<host>
     ```
   - Menjalankan enumerasi sudo:
     ```bash
     sudo -l
     # (ALL) NOPASSWD: /bin/nano /etc/sudoers
     ```
   - Memeriksa hak akses berkas flag target:
     ```bash
     ls -l /home/ctf-player/flag.txt
     # -r--r----- 1 root root 44 Nov  8 00:00 /home/ctf-player/flag.txt
     ```

2. **Eksekusi Eksploitasi Interaktif via GTFOBins:**
   - Membuka nano dengan hak administratif:
     ```bash
     sudo /bin/nano /etc/sudoers
     ```
   - Menekan kombinasi tombol `Ctrl+R` (`^R`) untuk memicu fungsi *Read File*. Nano menampilkan prompt di bagian bawah layar:
     `File to insert [from ./]: `
   - Memasukkan path absolut berkas target:
     `/home/ctf-player/flag.txt`
   - Menekan tombol `Enter` (mengirimkan karakter `\r`).
   - Berkas terbaca dengan hak root dan isinya disisipkan langsung ke buffer nano pada layar:
     `academy{n4n0_411_7h3_w4y_81311b87}`.

3. **Otomasi Reproduktif Menggunakan PTY Python:**
   - Menulis skrip otomasi `scripts/solve_748_absolute_nano.py` yang mengalokasikan fork PTY dengan `TERM=xterm-256color`.
   - Mengirimkan urutan bita kontrol terminal:
     - `\x12` (`Ctrl+R`)
     - Sekuens bracketed paste: `\x1b[200~/home/ctf-player/flag.txt\x1b[201~`
     - Commit via `\r` (Carriage Return).
   - Membaca dan membersihkan escape sequence ANSI dari buffer PTY, mengekstrak token resmi `academy{n4n0_411_7h3_w4y_81311b87}`.

4. **Verifikasi Token REST API:**
   - Token dikirimkan ke endpoint `POST /api/submissions/` dengan CSRF token sesi aktif.
   - Platform merespons status HTTP 201 dengan atribut `correct: true`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{n4n0_411_7h3_w4y_81311b87}`
- **Format Komunitas:** `CTF{n4n0_411_7h3_w4y_81311b87}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 748, "flag": "academy{n4n0_411_7h3_w4y_81311b87}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Penggunaan `sudoedit` Ketimbang Membuka Editor Langsung (Least Privilege / NIST SP 800-53 AC-6):**
   - Jangan pernah memberikan hak sudo langsung pada biner editor (`/bin/nano`, `/usr/bin/vim`, `/bin/ed`, `/usr/bin/emacs`).
   - Gunakan mekanisme `sudoedit` (atau `sudo -e`):
     ```text
     ctf-player ALL=(ALL) sudoedit /etc/sudoers
     ```
   - Mekanisme `sudoedit` membuat salinan berkas sementara dengan hak pengguna non-root, membiarkan editor berjalan sepenuhnya di bawah UID non-privilese, lalu menyalin kembali berkas secara atomik sebagai root setelah proses penyuntingan selesai. Hal ini mencegah penyalahgunaan kapabilitas baca/tulis arbitrer biner editor.

2. **Penerapan Tag `NOEXEC` pada Sudoers:**
   - Jika perintah utilitas perlu didelegasikan, gunakan tag `NOEXEC` untuk mencegah biner yang dipanggil mengeksekusi sub-proses atau shell baru:
     ```text
     ctf-player ALL=(ALL) NOEXEC: /usr/bin/some_tool
     ```

3. **Taktik Uji Cepat Kompetisi LKS Cyber Security:**
   - Pada modul *Linux System Hardening & Host Forensics*, selalu periksa aturan delegasi sudo (`sudo -l`) dalam fase awal asesmen.
   - Identifikasi biner berbahaya yang terdaftar pada katalog GTFOBins dan tutup celah privilege escalation dengan menghapus entri `NOPASSWD` yang tidak perlu.

---

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)

- **David (Leader):** Mengorkestrasi pengujian evaluasi privilese sistem sesuai standar NIST SP 800-115 §4.5 dan memverifikasi ketiadaan false positives.
- **Charlie (Trend-hunter):** Mengidentifikasi pola eskalasi hak akses sudoers & GTFOBins sebagai materi wajib dengan bobot nilai tinggi pada kompetisi LKS Cyber Security Nasional.
- **Alex (Fullstack-dev) & Omnirush (Coding Agent):** Mengembangkan modul simulator buffer editor lokal serta modul eksekusi PTY Python dengan penanganan bracketed paste sequence.
- **Julius (QA-engineer):** Menjalankan pengujian regresi terhadap pengiriman bita `\r` vs `\n` dan memvalidasi keabsahan token pada sistem verifikasi CyLab.
- **Athena (Security-engineer):** Mengaudit konfigurasi sudoers dan merumuskan rekomendasi hardening berbasis `sudoedit` dan kontrol akses berbasis NIST SP 800-53 AC-6.
- **Judith (Guru LKS):** Memasukkan skenario GTFOBins nano ke dalam bank materi drill taktis siswa bimbingan LKS pada sub-modul *Linux Host Hardening*.
