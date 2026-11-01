# Writeup: timer (Challenge ID: 381)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Android APK Reversing & Dalvik Executable Analysis
- **Difficulty:** Medium
- **Author:** Collin
- **Event:** picoCTF 2023
- **Points:** 100
- **Flag:** `academy{t1m3r_r3v3rs3d_succ355fully_17496}`

---

## Problem Statement & Scope
Diberikan paket aplikasi Android (`timer.apk`). Peserta diminta menganalisis struktur internal aplikasi mobile tersebut untuk menemukan flag rahasia yang tersimpan di dalam berkas eksekusi Dalvik atau sumber daya aplikasi.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Struktur Kontainer Android Package (APK Structure):** Berkas APK pada dasarnya merupakan arsip terkompresi berbasis ZIP yang mengemas bytecode Android Runtime (berkas `.dex` / Dalvik Executable), tabel sumber daya (`resources.arsc`), pustaka native, dan manifes XML biner (`AndroidManifest.xml`).
2. **Multi-DEX Architecture & Hardcoded Secrets:** Pada aplikasi Android berukuran menengah hingga besar yang menggunakan Multi-DEX, kode aplikasi dipecah ke dalam beberapa berkas DEX (`classes.dex`, `classes2.dex`, `classes3.dex`). Pengembang yang tidak menerapkan praktik keamanan menyimpan string sensitif atau konstanta rahasia secara plaintext langsung di dalam kode Java/Kotlin tanpa enkripsi maupun obfuskasi string.
3. **Ketiadaan Obfuskasi DEX (Missing ProGuard/R8 Obfuscation):** Tanpa perlindungan obfuskator, tabel konstan string pada header DEX mempertahankan semua representasi string literal UTF-8 utuh yang dapat diekstrak langsung melalui utilitas pengarsipan (`zipfile`, `unzip`) atau inspeksi string statis.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis konten paket APK sebagai arsip ZIP:
   ```bash
   unzip -l timer.apk | grep "\.dex"
   # Output: classes.dex, classes2.dex, classes3.dex
   ```
2. Lakukan pencarian string berformat flag pada seluruh berkas DEX yang diekstrak:
   ```bash
   strings classes3.dex | grep -E "academy\{|picoCTF\{|CTF\{"
   # Output: academy{t1m3r_r3v3rs3d_succ355fully_17496}
   ```
3. Alternatif menggunakan dekompiler `jadx`:
   ```bash
   jadx -d out timer.apk
   grep -rn "academy{" out/
   ```
4. Flag resmi berhasil diisolasi dari blok konstanta kelas pada `classes3.dex`:
   $$\text{Flag} = \text{academy\{t1m3r\_r3v3rs3d\_succ355fully\_17496\}}$$

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{t1m3r_r3v3rs3d_succ355fully_17496}`
- **Verifikasi:** Endpoint REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 381, "flag": "academy{t1m3r_r3v3rs3d_succ355fully_17496}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Android Hardening & String Encryption:** Pada modul pengujian keamanan aplikasi mobile LKS Cyber Security, nilai konfigurasi sensitif, token API, dan rahasia aplikasi tidak boleh disimpan sebagai string literal di dalam kode sumber. Terapkan pustaka enkripsi string (seperti StringFog atau DexGuard) dan gunakan Android Keystore System / Hardware-backed security.
- **R8 / ProGuard Shrinking & Minification:** Aktifkan `minifyEnabled true` dan `shrinkResources true` pada `build.gradle` untuk menghapus kelas dan metode diagnostik yang tidak terpakai serta mengaburkan nama kelas, bidang, dan identifier bytecode.
