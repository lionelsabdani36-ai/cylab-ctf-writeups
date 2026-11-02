# Writeup: Event-Viewing (Challenge ID: 456)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Windows Event Log (.evtx) Analysis & Malware Persistence
- **Difficulty:** Medium
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2025
- **Points:** 200
- **Flag:** `academy{Ev3nt_vi3wv3r_1s_a_pr3tty_us3ful_t00l_81ba3fe9}`

---

## Problem Statement & Scope
Seorang karyawan melaporkan bahwa komputernya terinfeksi program berbahaya (malware). Setiap kali komputer dinyalakan dan pengguna melakukan login, sebuah jendela command prompt hitam terbuka sesaat dan langsung mematikan (*shut down*) komputer secara instan.
Kronologi insiden:
1. Pengguna mengunduh dan menjalankan paket instalasi perangkat lunak dari internet (`Totally_Legit_Software.msi`).
2. Program yang diinstal tidak menampilkan antarmuka grafis atau aktivitas yang jelas.
3. Komputer mengalami mati paksa (*immediate shutdown*) setiap kali sistem dinyalakan ulang dan login berhasil.

Tugas analis adalah meneliti berkas log peristiwa Windows (`Windows_Logs.evtx`), mengidentifikasi ketiga tahapan serangan, dan merekonstruksi 3 pecahan flag yang disisipkan oleh pembuat tantangan.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Struktur Format Log Biner Windows Event Log (.evtx):**
   Berkas `.evtx` menyimpan data kejadian sistem dalam bentuk potongan chunk berukuran 64 KB yang dipadatkan dengan representasi string UTF-16 Little Endian (UTF-16LE). Informasi kejadian mencakup Application, Security, dan System logs.
2. **Vektor Persistensi Malware (Registry Run Keys):**
   Malware memanfaatkan kunci registri Windows `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` atau `HKCU\...\Run` untuk mengeksekusi payload jahat (`custom_shutdown.exe`) secara otomatis setiap kali pengguna masuk (*logon trigger*).
3. **Penyelidikan Forensik Berdasarkan Event ID (Triage Analysis):**
   - **MsiInstaller (Event ID 1033):** Mencatat instalasi aplikasi Windows Installer (MSI). Log menyimpan parameter produk, versi, dan konfigurasi awal.
   - **Audit Security & Object Access (Event ID 4657 / 4688):** Mencatat perubahan nilai kunci registri Windows (Registry Value Modification) dan pembuatan proses baru (*Process Creation*).
   - **User32 Shutdown Event (Event ID 1074):** Mencatat pemicu pematian sistem, proses pemanggil (`custom_shutdown.exe`), alasan pematian (*Shutdown Reason*), dan tipe pematian (*power off / restart*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Inspeksi Artefak Log Instalasi (Event ID 1033 / MsiInstaller):**
   Pencarian string UTF-16LE terhadap entitas `Totally_Legit_Software` pada log aplikasi mengungkap parameter instalasi:
   ```text
   Product: Totally_Legit_Software 1.3.3.7 0 0 YWNhZGVteXtFdjNudF92aTN3djNyXw==
   ```
   Dekode Base64 menghasilkan pecahan ke-1:
   $$\text{YWNhZGVteXtFdjNudF92aTN3djNyXw==} \longrightarrow \texttt{academy\{Ev3nt\_vi3wv3r\_}$$

2. **Inspeksi Artefak Eksekusi & Persistensi (Security Audit / Run Key):**
   Pemeriksaan aktivitas proses `Totally_Legit_Software.exe` menunjukkan penambahan entri autorun registri yang menunjuk ke executable `custom_shutdown.exe`. Parameter deskripsi pencatatan mencakup string:
   ```text
   Immediate Shutdown (MXNfYV9wcjN0dHlfdXMzZnVsXw==)
   ```
   Dekode Base64 menghasilkan pecahan ke-2:
   $$\text{MXNfYV9wcjN0dHlfdXMzZnVsXw==} \longrightarrow \texttt{1s\_a\_pr3tty\_us3ful\_}$$

3. **Inspeksi Peristiwa Pematian Sistem (User32 Event ID 1074):**
   Penyaringan log sistem terhadap pemicu shutdown mengungkap pencatatan oleh proses `custom_shutdown.exe` dengan pesan komentar alasan:
   ```text
   shutdowndDAwbF84MWJhM2ZlOX0=
   ```
   Dekode Base64 menghasilkan pecahan ke-3:
   $$\text{dDAwbF84MWJhM2ZlOX0=} \longrightarrow \texttt{t00l\_81ba3fe9\}}$$

4. **Penggabungan Seluruh Token Flag:**
   $$\texttt{academy\{Ev3nt\_vi3wv3r\_} + \texttt{1s\_a\_pr3tty\_us3ful\_} + \texttt{t00l\_81ba3fe9\}} \longrightarrow \texttt{academy\{Ev3nt\_vi3wv3r\_1s\_a\_pr3tty\_us3ful\_t00l\_81ba3fe9\}}$$

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{Ev3nt_vi3wv3r_1s_a_pr3tty_us3ful_t00l_81ba3fe9}`
- **Verifikasi:** Endpoint REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 456, "flag": "academy{Ev3nt_vi3wv3r_1s_a_pr3tty_us3ful_t00l_81ba3fe9}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Korelasi Linier Rantai Serangan pada Forensik Windows:** Dalam modul *Threat Hunting & Incident Response* LKS Cyber Security, analis harus mampu menghubungkan tiga titik kritis: titik masuk (*Initial Access / Installation*), mekanisme bertahan (*Persistence / Registry Modification*), dan dampak operasional (*Impact / Denial of Service via Shutdown*).
- **Pengerasan Kebijakan Eksekusi & Audit Lanjutan:**
  1. Aktifkan *Command Line Process Auditing* (Event ID 4688) dan integrasikan monitoring Sysmon (Event ID 1: Process Creation, Event ID 13: RegistryEvent).
  2. Terapkan *Application Whitelisting* (AppLocker / Windows Defender Application Control) untuk memblokir eksekusi biner yang tidak sah dari direktori pengguna atau non-standar.
  3. Batasi hak akses penulisan ke kunci registri autorun `Run` / `RunOnce` melalui Group Policy Object (GPO).
