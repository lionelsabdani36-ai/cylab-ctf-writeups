# Writeup: Mob psycho (Challenge ID: 420)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Mobile Android Artifact Carving
- **Difficulty:** Medium (diff=2)
- **Author:** NGIRIMANA Schadrack
- **Event:** picoCTF 2024
- **Points:** 200
- **Flag:** `academy{ax8mC0RU6ve_NX85l4ax8mCl_054e3cc4}`

---

## Problem Statement & Scope

Tantangan menyediakan sebuah paket aplikasi Android (*Android Package Kit* / APK) bernama `mobpsycho.apk`. Peserta diminta mengeksplorasi dan membedah artefak internal paket APK untuk menemukan flag rahasia yang tersimpan.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Paket Android (APK Packaging Specification):** Berkas APK merupakan kontainer terkompresi yang mengimplementasikan spesifikasi format berkas ZIP standar (RFC 1951 / APPNOTE). Struktur APK mencakup kode terkompilasi Dalvik Executable (`classes.dex`), pustaka native (`lib/`), manifest aplikasi (`AndroidManifest.xml`), serta direktori sumber daya aset (`res/` dan `assets/`).
2. **Penyimpanan Artefak Sensitif Tanpa Enkripsi (Unprotected Resource Storage):** Meskipun berkas biner `.dex` sering diobfuskasi menggunakan ProGuard atau R8, direktori `res/` sering kali menyimpan berkas teks mentah (*raw files*) atau format non-terkompilasi. Pada kasus ini, pengembang menyematkan berkas `res/color/flag.txt` langsung ke dalam paket aplikasi tanpa perlindungan enkripsi atau integritas kriptografis yang valid.
3. **Penyembunyian Informasi Sederhana (Trivial Hex Encoding):** Konten teks di dalam `flag.txt` hanya dienkode dalam bentuk heksadesimal polos (`61636164656d...`), yang dapat diidentifikasi dan dipulihkan secara instan melalui analisis heksadesimal standar.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh paket `mobpsycho.apk` dari repositori tantangan CyLab Academy:
   ```bash
   curl -s -L https://challenge-files.cylabacademy.net/library/03425ca32581a113283d4b3270dc798c848e4b4512c28e30c88887c3183b9967/mobpsycho.apk -o mobpsycho.apk
   ```
2. Periksa struktur isi arsip APK menggunakan utilitas `unzip` tanpa mengekstrak keseluruhan biner:
   ```bash
   unzip -l mobpsycho.apk | grep -i flag
   # 85  2026-09-23 05:16   res/color/flag.txt
   ```
3. Ekstraksi konten berkas sumber daya `res/color/flag.txt`:
   ```bash
   unzip -p mobpsycho.apk res/color/flag.txt
   # 61636164656d797b6178386d433052553676655f4e5838356c346178386d436c5f30353465336363347d
   ```
4. Dekode muatan heksadesimal ke representasi ASCII:
   ```python
   bytes.fromhex('61636164656d797b6178386d433052553676655f4e5838356c346178386d436c5f30353465336363347d').decode()
   # academy{ax8mC0RU6ve_NX85l4ax8mCl_054e3cc4}
   ```
5. Otomasi proses ekstraksi via skrip Python mandiri `scripts/solve_420_mob_psycho.py`.
6. Lakukan submisi validasi ke endpoint REST API CyLab: `POST /api/submissions/` dengan payload `{"challenge": 420, "flag": "academy{ax8mC0RU6ve_NX85l4ax8mCl_054e3cc4}"}` menghasilkan respon HTTP 201 `correct: true`.

---

## Flag & Verifikasi

- **Flag:** `academy{ax8mC0RU6ve_NX85l4ax8mCl_054e3cc4}`
- **Bukti Validasi:** Submisi REST API `/api/submissions/` mengembalikan status sukses: `{"correct": true, "user": 1072359, "challenge": 420}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS:** Dekonstruksi paket aplikasi mobile Android (APK/ZIP structure carving), inspeksi tabel resource `res/`, dan deteksi kebocoran informasi pada aset aplikasi klien.
- **Mitigasi Defensif (NIST SP 800-115 & OWASP Mobile Top 10):**
  - **M9: Reverse Engineering & Insecure Data Storage:** Hindari menyimpan informasi rahasia, API key berhak akses tinggi, atau token autentikasi di dalam bundel aplikasi klien (baik di dalam folder `assets/`, `res/`, maupun hardcoded di Java/Kotlin bytecode).
  - Terapkan *Android App Bundle* (AAB) audit untuk memastikan berkas uji coba (*test/debug artifacts*) tidak ikut terdistribusi ke rilis produksi.
