# Writeup: Forensics Git 1 (Challenge ID: 706)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Version Control System Forensics & Commit History Navigation
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** CyLab Forensics Team
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{g17_r3m3mb3r5_d4ddf904}`
- **Flag Komunitas:** `CTF{g17_r3m3mb3r5_d4ddf904}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), ISO/IEC 27037:2012 (Guidelines for Identification, Collection, Acquisition and Preservation of Digital Evidence), NIST SP 800-86 (Guide to Integrating Forensic Techniques into Incident Response), CWE-212 (Improper Removal of Sensitive Information Before Storage or Transfer), CWE-312 (Cleartext Storage of Sensitive Information), & MITRE ATT&CK T1552.001 (Credentials in Files / Information Repositories).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis LKS Cyber Security `Forensics Git 1`, peserta diuji dalam melakukan rekonstruksi investigasi forensik digital terhadap citra penyimpanan fisik (*raw disk image*) yang menyimpan repositori sistem kendali versi Git (*Version Control System* / VCS). Modul ini merupakan tahap kedua dari trilogi pembelajaran *Forensics Git* (705, 706, 707):
- **Skenario Lingkungan:** Diberikan citra disk mentah berukuran 1 GB: `706-disk.img` berpartisi sistem berkas Linux ext4.
- **Struktur Artefak:** Di dalam sistem berkas disk image terdapat direktori proyek perangkat lunak yang dikelola oleh Git.
- **Anomali Operasional:**
  1. Pada commit aktif (`HEAD` / cabang utama), berkas rahasia (`secrets` atau berkas konfigurasi) telah ditimpa atau dihapus oleh pengembang aplikasi dalam upaya pembersihan data rahasia (*anti-forensics attempt*).
  2. Pembacaan langsung pada berkas kerja di direktori aktif (`cat secrets`) hanya menampilkan teks umpan/placeholder kosong.
  3. Pengembang meyakini bahwa menimpa konten berkas dan membuat commit baru sudah cukup untuk melenyapkan kredensial dari repositori.
- **Sasaran Pengujian:**
  1. Melakukan identifikasi partisi dan akuisisi sistem berkas dari citra disk `706-disk.img`.
  2. Menganalisis riwayat rantai commit Git (`git log`, `git reflog`, `git rev-list`) pada cabang lokal.
  3. Mengidentifikasi commit historis tempat data rahasia pertama kali dimasukkan ke dalam basis data objek Git.
  4. Mengekstrak snapshot pohon berkas atau objek blob pada versi historis (`git show <commit>:<file>` atau `git checkout <commit>`).
  5. Menemukan kembali token rahasia resmi dan memvalidasinya secara live ke REST API CyLab Academy (`POST /api/submissions/`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Imutabilitas Objek Git (Content-Addressed DAG Storage):**
   Git mengelola seluruh riwayat repositori menggunakan graf asiklik terarah (*Directed Acyclic Graph* / DAG) yang bersifat kekal (*immutable*). Setiap komponen disimpan dalam `.git/objects/` sebagai objek terkompresi zlib dengan pengalamatan hash kriptografis SHA-1 160-bit (atau SHA-256 pada Git modern):
   - **Commit Object:** Menyimpan metadata pohon direktori utama (*root tree*), author, committer, cap waktu (*timestamp*), log perubahan, serta hash parent commit.
   - **Tree Object:** Representasi direktori yang memetakan nama berkas/subdirektori ke hash SHA objek blob atau tree anak.
   - **Blob Object:** Menyimpan konten biner mentah dari suatu berkas tanpa menyimpan metadata nama berkas maupun izin akses.

2. **Mekanika Pembaruan / Penimpaan Berkas (CWE-212 / CWE-312):**
   Ketika seorang pengembang menyadari kebocoran kredensial dan melakukan penimpaan berkas (misalnya `echo "" > secrets && git commit -m "remove secrets"`), Git **tidak menimpa objek blob lama di disk**:
   - Git membuat objek blob baru yang berisi teks kosong.
   - Git membuat objek tree baru yang menunjuk ke blob kosong tersebut.
   - Git membuat objek commit baru dengan referensi parent mengarah ke commit sebelumnya.
   - **Objek commit dan blob lama yang memuat kredensial tetap utuh, terindeks, dan dapat diakses** secara penuh melalui penelusuran riwayat commit (`git log --all`).

3. **Vektor Serangan & Paparan Kredensial (MITRE ATT&CK T1552.001):**
   Penyerang atau auditor yang memiliki akses ke repositori (atau ke citra disk yang memuat folder `.git`) tidak dibatasi oleh kondisi cabang aktif (`HEAD`). Dengan memeriksa seluruh graf commit historis, penyerang dapat merekonstruksi setiap perubahan kode pada setiap titik waktu sejak inisialisasi repositori.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Akuisisi dan Ekstraksi Direktori Proyek dari Citra Disk:**
   Menghitung offset partisi ext4 pada `706-disk.img` menggunakan `fdisk` / `mmls`, kemudian melakukan mount loopback atau ekstraksi artefak:
   ```bash
   mmls 706-disk.img
   # Offset sektor partisi Linux: misal sektor 2048 (offset 1048576)
   sudo mount -o loop,ro,offset=1048576 706-disk.img /mnt/analysis
   cd /mnt/analysis/target-repo
   ```

2. **Inspeksi Riwayat Rantai Commit Lengkap:**
   Menjalankan penelusuran riwayat commit untuk melihat seluruh aktivitas yang pernah dicatat:
   ```bash
   git log --all --oneline --graph --decorate
   ```
   Ditemukan riwayat commit yang mencurigakan, misalnya:
   - `e7b41a2` (HEAD -> master) Sanitize sensitive secrets and cleanup config
   - `8c39d01` Add initial credentials and secrets
   - `3f18b45` Initial commit

3. **Inspeksi Konten Historis (Time-Travel Recovery):**
   Memeriksa perbedaan diff atau langsung menampilkan berkas pada commit `8c39d01`:
   ```bash
   git show 8c39d01:secrets
   # Atau membandingkan perubahan antar commit:
   git diff 8c39d01 e7b41a2
   ```
   Output menampilkan baris yang dihapus:
   ```diff
   - academy{g17_r3m3mb3r5_d4ddf904}
   + [REDACTED]
   ```

4. **Automasi Pemulihan Skrip Python Standalone:**
   Mengimplementasikan solver mandiri (`scripts/solve_706_forensics_git_1.py`) yang membaca riwayat commit secara menyeluruh via `git log -p --all` atau traversi `ls-tree`, mengekstrak pola regex `academy\{g17_r3m3mb3r5_[0-9a-f]+\}`, dan melakukan validasi integritas token.

5. **Verifikasi Token Live CyLab REST API:**
   Mengirimkan token bukti verifikasi resmi ke REST API CyLab Academy:
   ```bash
   python3 scripts/solve_706_forensics_git_1.py --submit
   ```
   API merespons dengan HTTP 201:
   ```json
   {"user": 1072359, "challenge": 706, "flag": "academy{g17_r3m3mb3r5_d4ddf904}", "correct": true, "historical": false}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{g17_r3m3mb3r5_d4ddf904}`
- **Flag Komunitas:** `CTF{g17_r3m3mb3r5_d4ddf904}`
- **Status Validasi:** Terverifikasi 100% via live API endpoint `POST https://learn.cylabacademy.org/api/submissions/` (HTTP 201 Created, `correct: true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Relevansi Modul LKS Cyber Security (Defensive / Incident Response):**
   - Peserta LKS harus memahami hierarki forensik Git:
     - *Tingkat 1 (Forensics Git 0):* Data berada di commit aktif (`HEAD` atau commit message).
     - *Tingkat 2 (Forensics Git 1):* Data berada di commit lampau (*historic commit* yang ditimpa).
     - *Tingkat 3 (Forensics Git 2):* Data berada di objek terlantar (*dangling blob/commit* akibat rebase/reset).
   - Penguasaan perintah tingkat rendah Git (`git rev-list`, `git ls-tree`, `git cat-file -p`) sangat penting ketika antarmuka GUI tidak tersedia dalam kompetisi.

2. **Mitigasi Pencegahan Kebocoran (Preventive Controls):**
   - **Pre-commit Hooks:** Wajib memasang alat pemindai rahasia otomatis seperti `gitleaks` atau `trufflehog` pada alur kerja pengembang lokal:
     ```bash
     gitleaks protect --staged
     ```
   - **Environment Variables & Secret Managers:** Jangan pernah menyimpan kredensial atau kunci privat dalam repositori kode sumber. Gunakan Vault, AWS Secrets Manager, atau file `.env` lokal yang terdaftar ketat di `.gitignore`.

3. **Remediasi Insiden Kebocoran Git (Corrective Controls & History Sanitization):**
   - **Rotasi Seketika:** Kredensial yang pernah ter-commit ke repositori (bahkan selama 1 detik) harus dianggap telah terkompromi secara penuh dan wajib dirotasi/dibatalkan segera di sistem target.
   - **Pembersihan Riwayat Repositori:** Menggunakan `git-filter-repo` atau BFG Repo-Cleaner untuk menghapus berkas dan string rahasia dari seluruh rantai histori commit:
     ```bash
     git-filter-repo --invert-paths --path secrets
     git reflog expire --expire=now --all
     git gc --prune=now --aggressive
     git push origin --force --all
     ```
