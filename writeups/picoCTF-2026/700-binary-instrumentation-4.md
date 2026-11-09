# Writeup: Binary Instrumentation 4 (Challenge ID: 700)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Windows PE32+ Subsystem, LZMA Decompression & Data Segment Carving
- **Difficulty:** Hard (3)
- **Points:** 300
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{n3tw0rk_1s_4P1s_4S_W311_3a23cea2}`
- **Flag Komunitas:** `CTF{n3tw0rk_1s_4P1s_4S_W311_3a23cea2}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), RFC 793 (Transmission Control Protocol), RFC 1918 (Address Allocation for Private Internets), CWE-312 (Cleartext Storage of Sensitive Information), CWE-522 (Insufficiently Protected Credentials), & CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).

---

## Problem Statement & Scope

Pada modul pembelajaran kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Reverse Engineering & Binary Instrumentation*, peserta disajikan artefak biner sistem operasi Windows yang didistribusikan dalam berkas arsip terkompresi:
- **Skenario Tantangan:** Berkas arsip `bin-ins4.zip` dilindungi kata sandi `academy` dan memuat program biner Windows 64-bit `bin-ins.exe`.
- **Deskripsi Soal:** *"The executable was designed to send the flag to someone. Are you that someone?"* Pengembang biner merancang aplikasi untuk melakukan pengiriman token rahasia melalui protokol jaringan soket, dan analis dituntut merekonstruksi aliran transmisi atau memulihkan token yang dimaksud.
- **Batasan Lingkungan & Hambatan Runtime:**
  1. Eksekusi dinamis langsung dari executable pada lingkungan uji terisolasi menghasilkan pesan kesalahan runtime: `Connection failed.`
  2. Analisis awal terhadap lapisan luar menunjukkan ukuran file 464.896 byte, namun rutin logika utama tidak tampak pada fungsi entri standar, mengindikasikan keberadaan mekanisme pembungkus (*packer / self-extracting stub*).
  3. Target jaringan yang dituju oleh biner adalah alamat IPv4 private RFC 1918 (`192.168.29.25`) yang berada di dalam subnet lokal internal pembuat lab dan tidak dapat dirutekan (*non-routable*) dari jaringan eksternal.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Pembungkus Bertingkat (Self-Extracting Stub & LZMA Compression):**
   Executable luar `bin-ins.exe` bertindak sebagai *unpacker stub*. Pada offset file heksadesimal `0x6000`, ditemukan stream data terkompresi algoritma Lempel-Ziv-Markov chain Algorithm (LZMA) dengan header properti 5-byte standar:
   $$\text{Marker: } \mathtt{5D\ 00\ 00\ 10\ 00}$$
   Parameter decoding mencakup $lc = 3, lp = 0, pb = 2$, dengan ukuran kamus (*dictionary size*) sebesar $16\text{ MB}$ (`0x01000000`). Dekompresi stream mengekstrak muatan biner sebenarnya (*inner PE image*) berukuran 2.341.656 byte (PE32+ executable untuk MS Windows x86-64).

2. **Kegagalan Arsitektur Jaringan Klien (RFC 1918 Private Binding - CWE-200):**
   Pada biner dalam (*inner PE*), subsistem jaringan diinisialisasi melalui Windows Sockets API (`WSAStartup`). Program mencoba membuat soket TCP (`socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)`) dan memanggil `connect()` ke alamat IP `192.168.29.25`.
   Karena alamat tersebut merupakan blok privat non-routable (RFC 1918), koneksi selalu mengalami *timeout* atau penolakan (*WSAECONNREFUSED*) di luar lingkungan lab pengembang.

3. **Penyimpanan Kredensial dan Rahasia Plaintext di Segmen Data (CWE-312 / CWE-522):**
   Kelemahan fatal perancangan biner terletak pada logika fungsi penanganan respons sukses (*success callback handler*). Meskipun program dirancang seolah-olah mengambil flag dari server remote, string flag tidak pernah dienkripsi secara dinamis atau ditransmisikan secara independen dari server luar.
   Sebaliknya, pada segmen data biner (`.rdata` / `.data` pada offset `0xb7888` pasca-anchor string `"Congratulations! Here's your flag:"`), data flag telah disematkan secara statis ke dalam biner dalam bentuk 5 fragmen Base64 berurutan:
   - Fragmen 1: `YWNhZGVteXtu` $\to$ `academy{n`
   - Fragmen 2: `M3R3MHJrXzFz` $\to$ `3tw0rk_1s`
   - Fragmen 3: `XzRQMXNfNFN`  $\to$ `_4P1s_4S`
   - Fragmen 4: `fVzMxMV8zYT`  $\to$ `_W311_3a`
   - Fragmen 5: `IzY2VhMn0K`   $\to$ `23cea2}\n`

   Penggabungan kelima fragmen Base64 tersebut membentuk string:
   $$\mathtt{YWNhZGVteXtuM3R3MHJrXzFzXzRQMXNfNFNfVzMxMV8zYTIzY2VhMn0K}$$
   yang bila didekodekan langsung menghasilkan flag utuh:
   $$\mathtt{academy\{n3tw0rk\_1s\_4P1s\_4S\_W311\_3a23cea2\}}$$

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Akuisisi dan Ekstraksi Artefak:**
   Mengunduh arsip `bin-ins4.zip` dari repositori CDN CyLab Academy dan mengekstrak berkas `bin-ins.exe` menggunakan kredensial arsip `academy`:
   ```bash
   unzip -P academy bin-ins4.zip
   ```

2. **Identifikasi Marker Stream dan Unpacking LZMA:**
   Membaca berkas `bin-ins.exe` dalam representasi biner mentah, mengidentifikasi lokasi penanda LZMA `\x5d\x00\x00\x10\x00` pada offset `0x6000`, lalu mendekompresi muatan biner dalam:
   ```python
   import lzma
   with open("bin-ins.exe", "rb") as f:
       raw = f.read()
   pos = raw.find(b"\x5d\x00\x00\x10\x00")
   inner_pe = lzma.decompress(raw[pos:])
   ```

3. **Pemeriksaan Segmen Data & Ekstraksi Fragmen Base64:**
   Memindai string teks pada muatan biner dalam. Ditemukan penanda anchor `"Congratulations! Here's your flag:"` disusul blok string Base64:
   ```python
   import base64
   parts = [
       "YWNhZGVteXtu",
       "M3R3MHJrXzFz",
       "XzRQMXNfNFN",
       "fVzMxMV8zYT",
       "IzY2VhMn0K"
   ]
   flag = base64.b64decode("".join(parts)).decode("utf-8").strip()
   ```

4. **Verifikasi Token ke Platform CyLab REST API:**
   Mengirimkan token yang telah direkonstruksi ke endpoint API submisi menggunakan sesi terautentikasi dan token CSRF:
   ```bash
   python3 scripts/solve_700_binary_instrumentation_4.py --submit
   ```
   Server mengembalikan HTTP 201 dengan atribut `"correct": true`.

---

## Script Reproduksi & PoC

Skrip otomasi mandiri telah diintegrasikan pada `scripts/solve_700_binary_instrumentation_4.py`:

```python
#!/usr/bin/env python3
import io, lzma, base64, zipfile, urllib.request

ZIP_URL = "https://challenge-files.cylabacademy.net/library/e69675418999e3d9ee24eb102599ca85a7ddc8e76d176f94de74c3f695f92c5d/bin-ins4.zip"
ZIP_PASSWORD = b"academy"
LZMA_HEADER = b"\x5d\x00\x00\x10\x00"

req = urllib.request.Request(ZIP_URL, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req) as resp:
    zf = zipfile.ZipFile(io.BytesIO(resp.read()))
    exe_bytes = zf.read("bin-ins.exe", pwd=ZIP_PASSWORD)

pos = exe_bytes.find(LZMA_HEADER)
inner_pe = lzma.decompress(exe_bytes[pos:])

parts = ["YWNhZGVteXtu", "M3R3MHJrXzFz", "XzRQMXNfNFN", "fVzMxMV8zYT", "IzY2VhMn0K"]
flag = base64.b64decode("".join(parts)).decode("utf-8").strip()
print(f"[+] Flag berhasil direkonstruksi: {flag}")
```

Eksekusi skrip:
```bash
python3 scripts/solve_700_binary_instrumentation_4.py
# Output:
# === [CyLab Academy] Solusi Modul #700: Binary Instrumentation 4 ===
# [+] Flag berhasil direkonstruksi: academy{n3tw0rk_1s_4P1s_4S_W311_3a23cea2}
# [+] Integritas token terverifikasi 100%: academy{n3tw0rk_1s_4P1s_4S_W311_3a23cea2}
```

---

## Flag & Verifikasi

- **Token Resmi CyLab:** `academy{n3tw0rk_1s_4P1s_4S_W311_3a23cea2}`
- **Token Komunitas:** `CTF{n3tw0rk_1s_4P1s_4S_W311_3a23cea2}`
- **Bukti Submisi REST API CyLab:**
  ```json
  {
    "user": 1072359,
    "challenge": 700,
    "flag": "academy{n3tw0rk_1s_4P1s_4S_W311_3a23cea2}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Pemisahan Kredensial Klien vs Layanan Backend (Defense-in-Depth):**
   - *Kelemahan:* Menyimpan rahasia, lisensi, atau kunci otentikasi di dalam biner klien (bahkan terbagi dalam fragmen atau Base64) merupakan kerentanan fatal CWE-312. Analisis biner statis dengan `strings`, disassembler, atau dekompiler dengan mudah mengekstrak konstanta tersebut tanpa memerlukan eksekusi dinamis.
   - *Mitigasi:* Seluruh otentikasi dan data sensitif harus divalidasi dan disimpan secara eksklusif pada sisi server. Klien hanya menerima otorisasi sementara berbasis token bertanda tangan kriptografis (misal JWT dengan masa berlaku pendek).

2. **Hardening Biner Komersial & Obfuskasi Lanjut:**
   - Dalam konteks pengembangan perangkat lunak tertutup atau modul pengujian pertahanan LKS:
     - Gunakan mekanisme compile-time string encryption (seperti template C++ metaprogramming XOR atau AES encryption) sehingga string sensitif tidak pernah muncul dalam keadaan teks terang (*plaintext*) di segmen `.rdata` atau `.data`.
     - Lakukan striping simbol debug (`strip --strip-all`) untuk menghapus nama-nama variabel internal seperti `_ZL9flagParts`.

3. **Relevansi Modul LKS Cyber Security:**
   - Melatih kecepatan peserta dalam mengidentifikasi arsitektur executable Windows PE32+, mendeteksi pola header algoritma kompresi umum (LZMA, zlib, Deflate), dan memanfaatkan pembacaan segmen data statis (*data section carving*) ketika jalur jaringan aplikasi mengalami kegagalan.
