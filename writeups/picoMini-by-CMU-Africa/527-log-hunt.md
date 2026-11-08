# Writeup: Log Hunt (Challenge ID: 527)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Log Analysis & Forensics (CWE-532 / NIST SP 800-115 §4.1)
- **Difficulty:** Easy (1)
- **Event:** picoMini by CMU-Africa
- **Points:** 50
- **Author:** Yahaya Meddy
- **Flag:** `academy{us3_y0urlinux_sk1lls_cedfa5fb}`

---

## Problem Statement & Scope
Tantangan `Log Hunt` mensimulasikan insiden kebocoran data sensitif (*Information Disclosure*) melalui berkas log server operasional:
> "Our server seems to be leaking pieces of a secret flag in its logs. The parts are scattered and sometimes repeated. Can you reconstruct the original flag? Download the logs `server.log` and figure out the full flag from the fragments."

Tantangan ini menguji keahlian forensik log Linux (*log analysis*) dan penyaringan aliran teks (*stream filtering & parsing*) peserta kompetisi LKS Cyber Security dalam kerangka evaluasi operasional SOC/SIEM dan standar NIST SP 800-115 Bagian 4.1.

Tautan artefak resmi CyLab CDN:
`https://challenge-files.cylabacademy.net/library/fefc39d7d9da79e3c3f78f0d7f12f520ca703a48a89fa1cac6856a5c2127a4e9/server.log`

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kegagalan Sanitasi Logging & Information Exposure (CWE-532):**
   Aplikasi mencatat jejak eksekusi internal dan data sensitif (potongan token autentikasi) ke dalam aliran log standar. Dalam siklus hidup perangkat lunak, kesalahan konfigurasi logging level (`DEBUG`/`INFO` aktif di produksi) dapat mengekspos token sesi, kunci API, atau PII kepada pengguna atau sistem pengumpul log yang tidak berwenang.
2. **Karakteristik Format Syslog (RFC 5424):**
   Setiap baris log membawa metadata waktu (*timestamp*), level fasilitas, dan pesan muatan:
   ```text
   [YYYY-MM-DD hh:mm:ss] LEVEL MESSAGE
   ```
   Penyebaran token rahasia secara berkala menyebabkan fragmentasi data. Namun, urutan kemunculan pertama (*first occurrence*) dari setiap fragmen unik mengikuti struktur pembacaan linier token target.
3. **Analisis Kronologis & Eliminasi Duplikasi Aliran Teks:**
   Menghindari kesalahan interpretasi akibat duplikasi periodik membutuhkan pemfilteran deterministik: memilah baris dengan penanda kata kunci spesifik (`FLAGPART:`), mengekstraksi kolom data, dan mempertahankan urutan pertama kemunculan tanpa mengubah urutan kronologis asli.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Pemeriksaan dan Analisis Karakteristik `server.log`:**
   Menganalisis pola baris menggunakan `grep`:
   ```bash
   grep "FLAGPART:" server.log | head -n 10
   ```
   Keluaran sampel:
   ```text
   [1990-08-09 10:00:10] INFO FLAGPART: academy{us3_
   [1990-08-09 10:02:55] INFO FLAGPART: y0urlinux_
   [1990-08-09 10:05:54] INFO FLAGPART: sk1lls_
   [1990-08-09 10:10:54] INFO FLAGPART: cedfa5fb}
   [1990-08-09 11:04:12] INFO FLAGPART: academy{us3_
   ```

2. **Ekstraksi Fragmen Unik dengan Pipeline Linux:**
   Menggabungkan `grep` untuk isolasi baris, `awk` untuk ekstraksi kolom token dan deduplikasi berbasis hash array asosiatif:
   ```bash
   grep "FLAGPART:" server.log | awk '{print $4}' | awk '!seen[$0]++' | tr -d '\n'
   ```
   - `awk '{print $4}'`: Mengambil kata setelah label `FLAGPART:` (menyesuaikan posisi kolom indeks).
   - `awk '!seen[$0]++'`: Memfilter duplikat pertama kali terlihat tanpa melakukan pengurutan ulang (`sort -u` merusak urutan waktu).
   - `tr -d '\n'`: Menghilangkan karakter *newline* untuk menggabungkan string.

3. **Rekonstruksi Programatik Menggunakan Python:**
   Skrip mandiri `scripts/solve_527_log_hunt.py` mengunduh langsung dari CDN, memproses baris demi baris, dan merekonstruksi token utuh:
   ```python
   parts = []
   seen = set()
   for line in lines:
       if "FLAGPART:" in line:
           part = line.split("FLAGPART:")[1].strip()
           if part not in seen:
               seen.add(part)
               parts.append(part)
           if part.endswith("}"):
               break
   flag = "".join(parts)
   ```
   Hasil rekonstruksi:
   `academy{us3_y0urlinux_sk1lls_cedfa5fb}`

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{us3_y0urlinux_sk1lls_cedfa5fb}`
- **Format Token Komunitas:** `CTF{us3_y0urlinux_sk1lls_cedfa5fb}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_527_log_hunt.py` (HTTP 201 correct=True via `POST /api/submissions/`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Data Masking & Redaction pada Logging Framework:**
   Semua data sensitif (kata sandi, token otentikasi, nomor kartu kredit, PII) harus disanitasi atau disamarkan (*masked*, misalnya `acc********`) sebelum diteruskan ke *logger appender* (Log4j, Winston, Python logging).
2. **Penegakan Level Log Produksi:**
   Pada lingkungan produksi, level pencatatan wajib diatur minimal pada tingkat `WARN` atau `ERROR`. Tingkat pencatatan `DEBUG` dan `INFO` harus dinonaktifkan untuk mencegah kebocoran alur eksekusi internal.
3. **Penerapan Aturan Deteksi SIEM (SOC Detection Rule):**
   Membangun aturan korelasi SIEM (misalnya Sigma Rule atau Elastic Query) untuk mendeteksi penulisan string bernilai sensitif atau token otentikasi ke dalam berkas log publik:
   ```yaml
   detection:
     selection:
       message|contains:
         - 'token='
         - 'FLAGPART:'
         - 'password='
     condition: selection
   ```
