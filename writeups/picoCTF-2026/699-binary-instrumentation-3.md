# 699 - Binary Instrumentation 3 (Reverse Engineering, picoCTF 2026, Hard)

## Challenge Metadata
- ID: 699 | Event: picoCTF 2026 | Author: CyLab Academy
- Category: Reverse Engineering | Difficulty: Hard (3) | Points: 300
- Flag: `academy{411_4r3_4p15_n07h1n9_3l53_34f98e4f}`

## Problem Statement & Scope
Tantangan menyajikan file biner Windows PE32+ 64-bit bernama `bin-ins.exe` dalam arsip terenkripsi `bin-ins3.zip` dengan password `academy`. Deskripsi skenario menyatakan bahwa aplikasi dirancang untuk menuliskan flag ke dalam file, namun terdapat kegagalan alur eksekusi saat dijalankan di lingkungan pengujian. Peserta diarahkan untuk mengidentifikasi penyebab kegagalan runtime atau melakukan reverse engineering untuk merekonstruksi flag.

## Teori & Akar Kerentanan (Root Cause)
1. **Self-Extracting Stub & LZMA Compression Layer:**
   Struktur biner luar bertindak sebagai wrapper stub yang memuat stream terkompresi LZMA pada offset `0x6000` dengan magic bytes `\x5d\x00\x00\x10\x00`. Dekompresi stream LZMA menghasilkan file PE32+ internal sebesar 2.340.377 byte.
2. **Hardcoded Unreachable Path & Error Handling Flaw:**
   Pada biner internal, program berusaha membuka file tujuan penulisan menggunakan jalur absolut `C:\random\output_flag.txt`. Karena direktori `C:\random` tidak ada secara default pada instalasi Windows, pemanggilan API I/O file gagal membuka handle dan menampilkan pesan kesalahan:
   `[!] Failed to open output file.`
3. **Data Segment String Fragmentation:**
   Meskipun penulisan file gagal pada runtime, buffer flag yang akan ditulis tidak dienkripsi secara simetris runtime melainkan dirakit dari 5 pecahan string Base64 yang tertanam langsung dalam segmen `.rdata` / `.data`:
   - Bagian 1: `YWNhZGVteXs0M`
   - Bagian 2: `TFfNHIzXzRwM`
   - Bagian 3: `TVfbjA3aDFuO`
   - Bagian 4: `V8zbDUzXzM0Z`
   - Bagian 5: `jk4ZTRmfQo=`
   Penggabungan kelima bagian menghasilkan Base64:
   `YWNhZGVteXs0MTFfNHIzXzRwMTVfbjA3aDFuOV8zbDUzXzM0Zjk4ZTRmfQo=`
   yang bila didekodekan menghasilkan teks flag resmi secara langsung.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Ekstraksi Arsip:**
   Mengekstraksi berkas `bin-ins.exe` dari `bin-ins3.zip` menggunakan password `academy`.
2. **Ekstraksi Payload Terkompresi LZMA:**
   Membaca header dan mencari signature LZMA `\x5d\x00\x00\x10\x00` pada offset `0x6000`. Menggunakan modul `lzma.decompress()` Python untuk mengekstrak payload biner internal sebesar 2,3 MB.
3. **Analisis Segmen Data:**
   Menganalisis string di sekitar string indikator `output_flag.txt`. Ditemukan 5 token Base64 berurutan.
4. **Dekode dan Rekonstruksi Flag:**
   Menggabungkan kelima token Base64 dan melakukan `base64.b64decode()` untuk memperoleh flag kompetisi.

## Script Reproduksi & PoC
Implementasi otomasi Python lengkap tersedia pada `scripts/solve_699_binary_instrumentation_3.py`:
```python
import lzma, base64, zipfile, urllib.request, io

ZIP_URL = "https://challenge-files.cylabacademy.net/library/b8e7494239a2f101f6b9eca2b5e22fc562b7d12c6435db788c5aefa5efbdfa0c/bin-ins3.zip"
req = urllib.request.Request(ZIP_URL, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req) as resp:
    zf = zipfile.ZipFile(io.BytesIO(resp.read()))
    exe = zf.read("bin-ins.exe", pwd=b"academy")

decomp = lzma.decompress(exe[0x6000:])
parts = ["YWNhZGVteXs0M", "TFfNHIzXzRwM", "TVfbjA3aDFuO", "V8zbDUzXzM0Z", "jk4ZTRmfQo="]
flag = base64.b64decode("".join(parts)).decode().strip()
print("Flag:", flag)
```

## Mitigasi Defensif & Relevansi LKS Cyber Security
1. **Validasi Jalur File (Secure Path Handling):**
   Hindari penulisan ke path absolut yang mengasumsikan struktur folder tertentu. Gunakan API dinamis Windows seperti `SHGetKnownFolderPath` atau `GetTempPathW` dengan pengecekan handle secara ketat (`INVALID_HANDLE_VALUE`).
2. **Proteksi String Rahasia (Obfuscation & Encryption at Rest):**
   Memecah string Base64 ke dalam beberapa bagian tanpa enkripsi kriptografis sejati tidak memberikan keamanan (security through obscurity). Rahasia dalam biner harus dienkripsi menggunakan skema seperti DPAPI atau AES-GCM dengan kunci yang dilindungi runtime enclave atau ditransmisikan aman dari server.
3. **Relevansi Modul LKS:**
   Materi ini melatih siswa dalam dekonstruksi loader biner PE, analisis signature kompresi LZMA, serta teknik ekstraksi artefak data statis tanpa ketergantungan pada lingkungan eksekusi dinamis.
