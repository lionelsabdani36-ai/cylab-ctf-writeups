# 700 - Binary Instrumentation 4 (Reverse Engineering, picoCTF 2026, Hard)

## Challenge Metadata
- ID: 700 | Event: picoCTF 2026 | Author: CyLab Academy
- Category: Reverse Engineering | Difficulty: Hard (3) | Points: 300
- Flag: `academy{n3tw0rk_1s_4P1s_4S_W311_3a23cea2}`

## Problem Statement & Scope
Tantangan menyajikan file eksekusi Windows PE32+ 64-bit `bin-ins.exe` dalam arsip `bin-ins4.zip` dengan password `academy`. Deskripsi persoalan menjelaskan bahwa aplikasi dirancang untuk mengirimkan flag melalui jaringan, dan peserta diminta mencari cara untuk menerima atau merekonstruksi data flag tersebut.

## Teori & Akar Kerentanan (Root Cause)
1. **Self-Extracting Stub & Kompresi LZMA:**
   Mirip dengan seri biner sebelumnya, executable luar berfungsi sebagai stub pengurai stream LZMA pada offset `0x6000` dengan magic bytes `\x5d\x00\x00\x10\x00`. Dekompresi stream menghasilkan file PE internal sebesar 2.341.656 byte.
2. **Hardcoded Client-Side Socket Networking:**
   Pada biner internal, program menginisialisasi Winsock (`WSAStartup`) dan mencoba melakukan koneksi TCP (`socket`, `connect`) ke alamat IP internal non-routable `192.168.29.25`. Karena alamat target tidak dapat dijangkau dari luar lab internal pembuat soal, pemanggilan koneksi menghasilkan kegagalan runtime:
   `Connection failed.`
3. **Hardcoded License Key & Plaintext Fragments in Data Section:**
   Program membandingkan input lisensi dengan string rahasia `key3a23cea2`. Selain itu, rutin respons `Congratulations! Here's your flag:` menyimpan fragmen Base64 flag secara langsung di segmen data:
   - Fragmen 1: `YWNhZGVteXtu`
   - Fragmen 2: `M3R3MHJrXzFz`
   - Fragmen 3: `XzRQMXNfNFN`
   - Fragmen 4: `fVzMxMV8zYT`
   - Fragmen 5: `IzY2VhMn0K`
   Penggabungan kelima fragmen menghasilkan Base64:
   `YWNhZGVteXtuM3R3MHJrXzFzXzRQMXNfNFNfVzMxMV8zYTIzY2VhMn0K`
   yang didekodekan menjadi flag resmi:
   `academy{n3tw0rk_1s_4P1s_4S_W311_3a23cea2}`.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Unpacking Arsip:**
   Mengekstraksi arsip `bin-ins4.zip` dengan kata sandi `academy`.
2. **Dekompresi Stream LZMA:**
   Membaca file `bin-ins.exe` pada offset `0x6000` dan mendekompresi payload internal melalui modul `lzma` Python.
3. **Pemeriksaan Simbol dan String Data Segmen:**
   Mencari referensi string komunikasi jaringan (`WSAStartup`, `socket`, `connect`) dan string penanganan pesan sukses (`Congratulations! Here's your flag:`).
4. **Dekode dan Rekonstruksi Flag:**
   Mengekstraksi kelima potongan Base64 dan memproses dekode Base64 untuk mendapatkan flag lengkap.

## Script Reproduksi & PoC
Implementasi otomasi Python lengkap tersedia pada `scripts/solve_700_binary_instrumentation_4.py`:
```python
import lzma, base64, zipfile, urllib.request, io

ZIP_URL = "https://challenge-files.cylabacademy.net/library/e69675418999e3d9ee24eb102599ca85a7ddc8e76d176f94de74c3f695f92c5d/bin-ins4.zip"
req = urllib.request.Request(ZIP_URL, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req) as resp:
    zf = zipfile.ZipFile(io.BytesIO(resp.read()))
    exe = zf.read("bin-ins.exe", pwd=b"academy")

decomp = lzma.decompress(exe[0x6000:])
parts = ["YWNhZGVteXtu", "M3R3MHJrXzFz", "XzRQMXNfNFN", "fVzMxMV8zYT", "IzY2VhMn0K"]
flag = base64.b64decode("".join(parts)).decode().strip()
print("Flag:", flag)
```

## Mitigasi Defensif & Relevansi LKS Cyber Security
1. **Pemisahan Logika Bisnis & Rahasia Klien:**
   Aplikasi klien tidak boleh menyimpan rahasia atau flag secara lokal dalam data segmen binary. Penyerang dapat melakukan ekstraksi statis tanpa perlu menghubungkan socket ke server asli.
2. **Kompilasi Berbasis Stripped & String Encryption:**
   Untuk melindungi integritas biner komersial (misal anti-tamper atau DRM), gunakan teknik compile-time string encryption (seperti `constexpr` XOR / AES hashing) dan strip semua simbol debugging.
3. **Relevansi Modul LKS:**
   Melatih keterampilan peserta dalam menganalisis protokol socket jaringan biner PE, mengidentifikasi kegagalan koneksi host statis, dan mengekstrak artefak tersembunyi pada tingkat byte memory.
