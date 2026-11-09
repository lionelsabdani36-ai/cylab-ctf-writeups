# Writeup: Forensics Git 0 (Challenge ID: 705)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Version Control System Forensics & Commit Message Acquisition
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** CyLab Forensics Team
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{g17_1n_7h3_d15k_041217d8}`
- **Flag Komunitas:** `CTF{g17_1n_7h3_d15k_041217d8}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), ISO/IEC 27037:2012 (Guidelines for Identification, Collection, Acquisition and Preservation of Digital Evidence), NIST SP 800-86 (Guide to Integrating Forensic Techniques into Incident Response), CWE-212 (Improper Removal of Sensitive Information Before Storage or Transfer), CWE-532 (Insertion of Sensitive Information into Log File), & MITRE ATT&CK T1552.001 (Credentials in Files / Information Repositories).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis LKS Cyber Security `Forensics Git 0`, peserta diuji dalam melakukan tahap awal investigasi forensik digital terhadap citra penyimpanan fisik (*raw disk image*) yang memuat instalasi sistem berkas Linux dan repositori kendali versi Git (*Version Control System* / VCS). Modul ini merupakan fondasi dasar dari rangkaian trilogi *Forensics Git* (705, 706, 707):
- **Skenario Lingkungan:** Diberikan citra mentah disk berukuran 1 GB: `705-disk.img` berpartisi sistem berkas Linux ext4.
- **Struktur Artefak:** Di dalam partisi disk terdapat direktori pengguna sistem yang memuat repositori Git proyek internal.
- **Anomali Operasional:**
  1. Pengembang aplikasi secara tidak sengaja memasukkan token autentikasi/kunci rahasia ke dalam pesan log commit (*commit message*) atau berkas commit inisial saat melakukan peluncuran repositori.
  2. Citra disk didistribusikan tanpa proses sanitasi forensik (*forensic sanitization*), meninggalkan artefak riwayat lengkap yang dapat diakses oleh siapa pun yang memperoleh citra media penyimpanan tersebut.
- **Sasaran Pengujian:**
  1. Mengidentifikasi struktur tata letak partisi (*partition table layout*) dan menghitung sektor offset awal sistem berkas ext4 pada `705-disk.img`.
  2. Melakukan ekstraksi partisi atau mounting berorientasi forensik (*read-only loopback mount*).
  3. Menemukan repositori Git yang tersembunyi pada direktori pengguna.
  4. Menganalisis metadata objek commit pada repositori menggunakan perintah inspeksi riwayat Git standar (`git log`, `git cat-file`).
  5. Mengekstrak string flag resmi dan memvalidasinya secara langsung ke REST API CyLab Academy (`POST /api/submissions/`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Objek Commit Git (Git Commit Object Specification):**
   Dalam Git, setiap aksi commit menghasilkan objek commit yang disimpan di direktori `.git/objects/`. Objek commit adalah teks terformat yang dikompresi menggunakan zlib dengan struktur:
   ```text
   commit <size>\0tree <tree-sha1>
   parent <parent-sha1>
   author <name> <<email>> <timestamp> <tz>
   committer <name> <<email>> <timestamp> <tz>

   <commit message body>
   ```
   Pesan commit (*commit message*) adalah bagian tak terpisahkan dari header commit yang menghasilkan nilai hash SHA-1 unik. Menghapus atau mengubah pesan commit akan mengubah hash SHA-1 dan memutus relasi turunan rantai commit.

2. **Penyisipan Informasi Sensitif ke dalam Log (CWE-532 / CWE-212):**
   Pengembang perangkat lunak sering kali menganggap pesan commit sebagai catatan informal internal. Ketika token sensitif, kata sandi konfigurasi, atau kunci API ditempelkan ke dalam pesan commit (misalnya `git commit -m "feat: add token academy{...}"`), informasi rahasia tersebut:
   - Tersimpan dalam teks jelas (*plaintext*) di dalam basis data objek `.git`.
   - Terdistribusi secara otomatis ke setiap pihak yang melakukan klon atau memiliki salinan berkas `.git`.
   - Tidak terhapus oleh filter `.gitignore`, karena `.gitignore` hanya mencegah pelacakan berkas baru, bukan menyaring pesan commit atau objek yang sudah masuk basis data.

3. **Integritas Citra Disk & Bukti Forensik (ISO/IEC 27037:2012):**
   Dalam investigasi insiden, akuisisi citra bit-stream (`.img`/`.dd`) menjaga keaslian bukti digital. Memeriksa riwayat VCS pada citra tersangka adalah prosedur standar untuk menetapkan kronologi kejadian (*timeline analysis*) dan atribusi pelaku (*user attribution*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Identifikasi Partisi & Offset Sektor Citra Disk:**
   Menggunakan alat utilitas The Sleuth Kit (`mmls`) atau `fdisk` untuk memeriksa tata letak partisi pada `705-disk.img`:
   ```bash
   mmls 705-disk.img
   # Output memperlihatkan partisi Linux pada sektor 2048 (offset 2048 * 512 = 1048576 byte)
   ```

2. **Mounting Citra Forensik / Ekstraksi Repositori:**
   Melakukan mounting partisi dalam mode *read-only* untuk mencegah kontaminasi bukti digital:
   ```bash
   sudo mkdir -p /mnt/evidence_705
   sudo mount -o loop,ro,offset=1048576 705-disk.img /mnt/evidence_705
   cd /mnt/evidence_705/home/user/project
   ```
   *(Alternatif menggunakan Sleuth Kit tanpa mount: `fls -r -o 2048 705-disk.img` dan `icat`)*.

3. **Inspeksi Riwayat Commit Git (Reconnaissance):**
   Menjalankan penelusuran ringkas terhadap seluruh riwayat commit beserta pesannya:
   ```bash
   git log --all --format="%H %s"
   ```
   Atau mencetak pesan lengkap beserta bodi log:
   ```bash
   git log --format="%s%n%b"
   ```
   Salah satu pesan commit secara langsung memaparkan token:
   ```text
   Commit: 4a12b8...
   Message: Added flag to production deployment: academy{g17_1n_7h3_d15k_041217d8}
   ```

4. **Automasi Pemulihan Skrip Python Standalone:**
   Mengimplementasikan skrip solver deterministik (`scripts/solve_705_forensics_git_0.py`) yang secara otonom membaca log Git melalui `subprocess`, mencocokkan ekspresi reguler `academy\{g17_1n_7h3_d15k_[0-9a-f]+\}`, dan memverifikasi integritas hash flag.

5. **Verifikasi Token Live CyLab REST API:**
   Mengirimkan token verifikasi ke REST API CyLab Academy:
   ```bash
   python3 scripts/solve_705_forensics_git_0.py --submit
   ```
   Respons API mengonfirmasi keabsahan token dengan HTTP 201:
   ```json
   {"user": 1072359, "challenge": 705, "flag": "academy{g17_1n_7h3_d15k_041217d8}", "correct": true, "historical": false}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{g17_1n_7h3_d15k_041217d8}`
- **Flag Komunitas:** `CTF{g17_1n_7h3_d15k_041217d8}`
- **Status Validasi:** Terverifikasi 100% via endpoint REST API `POST https://learn.cylabacademy.org/api/submissions/` (HTTP 201 Created, `correct: true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Relevansi Modul LKS Cyber Security (Digital Forensics & Incident Response):**
   - Langkah paling mendasar dalam forensik repositori adalah **selalu membaca log dan metadata komit terlebih dahulu** sebelum melangkah ke teknik yang lebih kompleks seperti *carving* blok atau ekstraksi objek melayang (*dangling*).
   - Penyelidik harus memeriksa seluruh cabang (*all branches*), tag, stash, dan reflog, bukan hanya cabang `master` atau `HEAD` terkini.

2. **Mitigasi Pencegahan Kebocoran (Preventive Controls):**
   - **Commit-msg Hooks & Commitlint:** Terapkan hook validasi `commit-msg` di lingkungan lokal dan pipeline CI untuk memblokir pesan commit yang mengandung pola regex token rahasia, password, atau API key format:
     ```bash
     # Contoh regex penolak token pada commit-msg hook
     if grep -E -q '(api[_-]?key|secret|password|bearer|academy\{)' "$1"; then
         echo "[!] ERROR: Pesan commit terdeteksi memuat token rahasia!"
         exit 1
     fi
     ```
   - **Edukasi Praktik Aman Git:** Tekankan kepada tim pengembang bahwa Git adalah basis data arsip permanen dan bukan saluran catatan sementara (*scratchpad*).

3. **Remediasi Insiden (Incident Response & Remediation):**
   - Kredensial yang tertulis di pesan commit harus segera dirotasi di sistem hilir (*downstream systems*).
   - Ubah pesan commit lokal jika belum di-push dengan `git commit --amend`.
   - Jika sudah ter-push ke remote, lakukan rewrite history menggunakan `git-filter-repo` atau squash commit lama, diikuti force-push yang terkontrol.
