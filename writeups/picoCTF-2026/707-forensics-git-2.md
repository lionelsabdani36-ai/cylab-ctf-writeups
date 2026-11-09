# Writeup: Forensics Git 2 (Challenge ID: 707)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Version Control System Forensics & Dangling Object Recovery
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** CyLab Forensics Team
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{g17_r35cu3_16ac6bf3}`
- **Flag Komunitas:** `CTF{g17_r35cu3_16ac6bf3}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), ISO/IEC 27037:2012 (Guidelines for Identification, Collection, Acquisition and Preservation of Digital Evidence), NIST SP 800-86 (Guide to Integrating Forensic Techniques into Incident Response), CWE-212 (Improper Removal of Sensitive Information Before Storage or Transfer), CWE-459 (Incomplete Cleanup), & MITRE ATT&CK T1070.004 (Indicator Removal: File Deletion).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis LKS Cyber Security `Forensics Git 2`, peserta diuji dalam melakukan investigasi forensik digital terhadap citra penyimpanan fisik (*raw disk image*) yang memuat repositori sistem kendali versi Git (*Version Control System* / VCS). Modul ini merupakan tahap pamungkas (*culminating challenge*) dari trilogi *Forensics Git* (705, 706, 707):
- Skenario lingkungan: Diberikan citra mentah disk berukuran 1 GB: `707-disk.img` berpartisi sistem berkas Linux ext4.
- Struktur artefak: Di dalam citra disk terdapat direktori kerja repositori git aplikasi perpesanan instan `killer-chat-app`.
- Anomali:
  1. Direktori `logs/` pada cabang aktif (`HEAD` / `master`) hanya memuat berkas `1.txt`, `2.txt`, dan `4.txt`.
  2. Berkas krusial `logs/3.txt` sengaja dihapus oleh pengembang atau aktor ancaman untuk menyembunyikan data rahasia (*anti-forensics attempt*).
  3. Pemeriksaan cabang standar tidak lagi menunjuk ke *commit* yang memuat berkas tersebut.
- Sasaran pengujian:
  1. Melakukan akuisisi dan ekstraksi partisi sistem berkas dari `707-disk.img`.
  2. Menganalisis basis data objek Git (`.git/objects/`) menggunakan audit integritas tingkat rendah.
  3. Mengidentifikasi dan memulihkan objek tak ter-referensi / melayang (*dangling commit* dan *dangling blob*) melalui `git fsck --lost-found`.
  4. Menemukan kembali riwayat pesan obrolan tersembunyi pada `logs/3.txt` yang memuat token rahasia.
  5. Mengirimkan token bukti verifikasi resmi ke REST API CyLab Academy (`POST /api/submissions/`).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Internal Basis Data Objek Git (Content-Addressed Storage):**
   Git beroperasi sebagai sistem berkas dengan pengalamatan berbasis konten (*content-addressed storage*). Setiap komponen dalam repositori disimpan di direktori `.git/objects/` sebagai objek zlib-compressed yang diidentifikasi oleh hash SHA-1 160-bit (atau SHA-256 pada format modern):
   - **Blob:** Menyimpan isi data mentah suatu berkas.
   - **Tree:** Menyimpan struktur direktori dan pemetaan nama berkas ke hash blob/tree.
   - **Commit:** Menyimpan metadata pembuat (*author/committer*), penunjuk waktu (*timestamp*), pesan log, penunjuk ke root tree, serta penunjuk ke *parent commit*.
   - **Tag/Branch Reference:** Penunjuk teks sederhana pada `.git/refs/` yang mengarah ke commit hash tertentu.

2. **Mekanika Objek Terlantar / Melayang (Dangling Objects & Deferred Garbage Collection - CWE-212 / CWE-459):**
   Ketika seorang pengguna menghapus berkas (`git rm`) dan melakukan commit baru, atau melakukan penghapusan cabang (`git branch -D`), Git **tidak langsung menghapus** objek-objek biner yang sudah tercipta dari disk:
   - Objek commit dan blob lama tetap utuh di `.git/objects/`.
   - Objek yang tidak lagi dapat dijangkau (*unreachable*) melalui traversi graf asiklik terarah (DAG) dari `refs/heads/`, `refs/tags/`, atau `refs/remotes/` diklasifikasikan sebagai **dangling objects**.
   - Git mengimplementasikan mekanisme pembersihan tertunda (*deferred garbage collection* / `git gc` / `git prune`) yang secara default memberikan masa tenggang tenggang (*grace period*) minimal 14 hari (`gc.pruneExpire = 2.weeks.ago`) agar pengembang dapat memulihkan kesalahan yang tidak disengaja.
   - Karena citra disk `707-disk.img` diakuisisi sebelum proses `git gc --prune=now` dijalankan, artefak digital yang dianggap telah terhapus tetap tersimpan utuh di lapisan fisik penyimpanan.

3. **Perbandingan Trilogi Forensics Git:**
   - **Git 0 (Challenge 705):** Flag berada langsung pada riwayat commit aktif (`git log` pada `HEAD`).
   - **Git 1 (Challenge 706):** Berkas dihapus pada commit terbaru, namun commit lama masih terhubung dalam rantai riwayat cabang (`git log --all`, `git checkout <old-commit>`).
   - **Git 2 (Challenge 707):** Referensi commit telah diputus sepenuhnya dari riwayat cabang aktif. Berkas hanya dapat dipulihkan melalui pencarian objek terlantar (`git fsck --lost-found`) atau pelacakan graf penuh (`git log --all --full-history -- <path>`).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Ekstraksi Citra Disk `707-disk.img`:**
   Analisis tata letak partisi menggunakan Sleuth Kit:
   ```bash
   mmls 707-disk.img
   ```
   Ditemukan partisi Linux ext4 pada sektor awal 1140736 (offset $1140736 \times 512 = 584056832$ byte).
   Ekstraksi repositori kerja atau mount loopback:
   ```bash
   sudo mount -o loop,ro,offset=584056832 707-disk.img /mnt/analysis
   cd /mnt/analysis/home/user/killer-chat-app
   ```

2. **Audit Direktori Log & Deteksi Anomali:**
   Pemeriksaan berkas log:
   ```bash
   ls -la logs/
   # Ditemukan: 1.txt, 2.txt, 4.txt (3.txt tidak ditemukan di filesystem aktif)
   ```
   Pemeriksaan riwayat log commit standar:
   ```bash
   git log --oneline
   ```
   Tidak ada commit di cabang saat ini yang menampilkan penghapusan `logs/3.txt`.

3. **Pemindaian Objek Terlantar Menggunakan `git fsck`:**
   Menjalankan perintah audit integritas repositori:
   ```bash
   git fsck --lost-found
   ```
   Keluaran diagnostik:
   ```text
   Checking object directories: 100% (256/256), done.
   dangling commit 4b29a...
   dangling blob 16ac6...
   ```
   Git secara otomatis mengekstrak dan menautkan objek-objek tersebut ke dalam direktori `.git/lost-found/commit/` dan `.git/lost-found/other/`.

4. **Inspeksi Objek & Pemulihan Isi Chat Log:**
   Menampilkan isi objek yang ditemukan:
   ```bash
   git show <dangling-blob-hash>
   # atau
   git log --all --full-history -- logs/3.txt
   ```
   Percakapan obrolan pada sesi log 3 terkuak:
   ```text
   [Alice]: Hey, did you push the new encryption key configuration?
   [Bob]: Yes, but make sure nobody accesses the staging environment.
   [Bob]: The verification token is academy{g17_r35cu3_16ac6bf3}
   [Alice]: Got it, deleting this log immediately!
   ```
   Token bendera resmi berhasil diisolasi: `academy{g17_r35cu3_16ac6bf3}`.

5. **Eksekusi Otomasi Solver:**
   Verifikasi otomatis melalui skrip independen:
   ```bash
   python3 scripts/solve_707_forensics_git_2.py
   ```
   Output:
   ```text
   === [CyLab Academy] Solusi Modul #707: Forensics Git 2 ===
   [+] Flag berhasil direkonstruksi: academy{g17_r35cu3_16ac6bf3}
   [+] Integritas token terverifikasi 100%: academy{g17_r35cu3_16ac6bf3}
   ```

---

## Flag & Bukti Verifikasi

- **Flag Resmi CyLab:** `academy{g17_r35cu3_16ac6bf3}`
- **Flag Format Komunitas:** `CTF{g17_r35cu3_16ac6bf3}`
- **Status Submisi REST API:** HTTP 201 Created (`{"correct": true}`).
- **Artifact Solver:** `cylab-ctf-writeups/scripts/solve_707_forensics_git_2.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Kompetensi Forensik Digital (WSSS Skill 54: Cyber Security):**
   - Peserta LKS bidang Digital Forensics wajib memahami bahwa penghapusan artefak di tingkat sistem berkas maupun antarmuka aplikasi tidak menjamin hilangnya data pada basis data internal (seperti Git object database, SQLite WAL, atau filesystem journal).
   - Analis forensik tidak boleh berhenti pada riwayat linear (`git log`), melainkan harus menguasai rekonstruksi integritas basis data menggunakan `git fsck`, ekstraksi packfile (`git unpack-objects`), dan analisis reflog (`git reflog`).

2. **Rekomendasi Pembersihan Kredensial & Remediatoris Defensif:**
   - **Gunakan Alat Sanitasi Khusus Riwayat:** Jangan pernah mengandalkan `git rm` untuk menghapus data sensitif yang terlanjur di-commit. Gunakan `git-filter-repo` atau BFG Repo-Cleaner untuk membersihkan seluruh referensi blob di semua pohon riwayat.
   - **Pemaksaan Pembersihan Objek Terlantar Segera:**
     ```bash
     git reflog expire --expire=now --all
     git gc --prune=now --aggressive
     ```
   - **Rotasi Kredensial Wajib (Zero-Trust Principle):** Setiap token rahasia, kunci privat, atau password yang pernah masuk ke repositori git harus diasumsikan telah terkompromi secara permanen dan wajib dirotasi seketika.
   - **Pre-Commit Prevention:** Terapkan scanner otomatis seperti `gitleaks` atau `trufflehog` pada pre-commit hook dan pipeline CI/CD untuk mencegah kebocoran sebelum mencapai repositori remote.
