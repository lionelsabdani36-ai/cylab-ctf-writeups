# Writeup: FindAndOpen (Challenge ID: 348)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / PCAP Network Analysis & ZipCrypto Stream Cipher (CWE-312 / CWE-327)
- **Difficulty:** Medium (diff=2)
- **Event:** picoCTF 2023
- **Points:** 200
- **Author:** Mubarak Mikail
- **Flag Resmi:** `academy{R34DING_LOKd_fil56_succ3ss_9989a41b}`
- **Standar Audit:** NIST SP 800-115 § 4.2 (Vulnerability Analysis) & § 4.3 (Verification)

---

## Problem Statement & Scope

Tantangan `FindAndOpen` menyediakan dua artefak investigasi forensik digital:
1. `dump.pcap`: Berkas tangkapan lalu lintas jaringan format libpcap yang berisi serangkaian frame Ethernet tiruan.
2. `flag.zip`: Arsip terkompresi ZIP terenkripsi yang memuat berkas teks bernama `flag` (berukuran 45 byte).

Skenario menantang peserta untuk menemukan kunci pembuka arsip di dalam rekaman lalu lintas jaringan tanpa melakukan serangan brute force kata sandi secara membuta (*Don't try to use a password cracking tool, there are easier ways here*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Eksfiltrasi Saluran Terselubung (*Covert Channel Traffic Analysis*):**
   Pada berkas `dump.pcap`, paket-paket jaringan tidak merepresentasikan komunikasi protokol TCP/IP standar yang sah, melainkan frame Ethernet mentah di mana field payload disisipi untaian teks ASCII dan Base64 secara terbuka. Analis forensik harus mampu membedakan paket jebakan (*decoy streams*) seperti `"Could the flag have been splitted?"`, `"Maybe try checking the other file"`, dan `"ababab..."` dari paket data operasional yang membawa muatan autentik.

2. **Diferensiasi Kredensial vs Token Final (*Credential vs Flag Disambiguation*):**
   Salah satu paket Ethernet memuat string Base64:
   `VGhpcyBpcyB0aGUgc2VjcmV0OiBhY2FkZW15e1IzNERJTkdfTE9LZF8=`
   Hasil dekode Base64 menghasilkan teks:
   `This is the secret: academy{R34DING_LOKd_`
   Pola teks tersebut sengaja dirancang menyerupai awalan flag platform. Namun, token ini belum memiliki penutup kurung kurawal `}` karena sebenarnya berfungsi sebagai kata sandi (*passphrase*) enkripsi arsip `flag.zip`, bukan bendera akhir. Kesalahan umum pemula adalah menyerahkan string ini langsung ke portal tanpa membuka kontainer arsip.

3. **Kelemahan Skema Enkripsi Warisan ZipCrypto (CWE-327):**
   Arsip `flag.zip` diproteksi menggunakan skema enkripsi bawaan PKZIP tradisional (ZipCrypto stream cipher) yang mengandalkan tiga register 32-bit internal. Karena kata sandi plaintext berhasil dipulihkan dari kanal jaringan, arsip dapat diekstrak secara deterministik tanpa memerlukan serangan *known-plaintext attack* (Biham-Kocher).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi dan Ekstraksi Header PCAP:**
   Gunakan utilitas baris perintah atau pustaka Python untuk memeriksa paket:
   ```bash
   strings dump.pcap | grep -E "secret|academy"
   ```
   Ditemukan baris payload Base64 `VGhpcyBpcyB0aGUgc2VjcmV0OiBhY2FkZW15e1IzNERJTkdfTE9LZF8=`.

2. **Dekode Kredensial Arsip:**
   ```bash
   echo "VGhpcyBpcyB0aGUgc2VjcmV0OiBhY2FkZW15e1IzNERJTkdfTE9LZF8=" | base64 -d
   # Output: This is the secret: academy{R34DING_LOKd_
   ```

3. **Ekstraksi Kontainer flag.zip:**
   Gunakan kata sandi yang dipulihkan untuk mendekripsi berkas arsip:
   ```bash
   unzip -P 'academy{R34DING_LOKd_' flag.zip
   cat flag
   ```
   Isi berkas `flag` menghasilkan token akhir:
   `academy{R34DING_LOKd_fil56_succ3ss_9989a41b}`.

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{R34DING_LOKd_fil56_succ3ss_9989a41b}`
- **Status Submisi REST API:** HTTP 201 Created (`correct: true`, `historical: false`).
- **Skrip Solver:** `scripts/solve_348_findandopen.py` (eksekusi deterministik mandiri exit 0).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Analisis Protokol Jaringan & Deteksi Saluran Terselubung (NIST SP 800-115 § 4.2):**
   Peserta LKS Cyber Security bidang Forensics harus terlatih membedakan lalu lintas jaringan normal dari covert channel. Inspeksi mendalam paket (*Deep Packet Inspection / DPI*) dan pembedahan frame Ethernet manual sangat krusial saat protokol standar tidak terdeteksi oleh penganalisis otomatis.

2. **Prinsip Isolasi Kredensial dan Data Sensitif (CWE-312):**
   Kata sandi atau kunci kriptografis tidak boleh ditransmisikan melalui kanal komunikasi yang sama dengan berkas terenkripsi tanpa enkripsi transport lapis kedua (seperti TLS atau VPN). Transmisi kunci secara terbuka menghancurkan keamanan enkripsi data diam (*data at rest*).

3. **Migrasi Standar Enkripsi Arsip Modern (NIST SP 800-38A / NIST SP 800-132):**
   Tinggalkan skema ZipCrypto konvensional pada arsip ZIP. Wajib gunakan standar enkripsi modern seperti AES-256 (WinZip AES specification) dengan fungsi derivasi kunci yang diperkuat (*Key Derivation Function*) seperti PBKDF2 atau Argon2 untuk mencegah serangan kamus cepat maupun analisis kriptanalisis komputasi tinggi.
