# Writeup: Binary Instrumentation 3 (Challenge ID: 699)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Windows PE32+ Subsystem, LZMA Decompression & I/O Redirection Failure
- **Difficulty:** Hard (3)
- **Points:** 300
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{411_4r3_4p15_n07h1n9_3l53_34f98e4f}`
- **Flag Komunitas:** `CTF{411_4r3_4p15_n07h1n9_3l53_34f98e4f}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), CWE-312 (Cleartext Storage of Sensitive Information), CWE-706 (Use of Incorrectly-Resolved Name or Reference), CWE-522 (Insufficiently Protected Credentials), & CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).

---

## Problem Statement & Scope

Pada modul pembelajaran kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Reverse Engineering & Binary Instrumentation*, peserta disajikan program biner Windows terkemas:
- **Skenario Tantangan:** Berkas arsip `bin-ins3.zip` dilindungi kata sandi `academy` dan memuat program biner Windows 64-bit `bin-ins.exe`.
- **Deskripsi Soal:** *"The executable was designed to write the flag but it seems like I messed up few things on the way? Can you find a way to get it to work?"* Penulis tantangan merancang program untuk menuliskan token rahasia ke dalam sistem berkas lokal, namun kesalahan perancangan menyebabkan program gagal mengeksekusi penulisan pada pengujian runtime standar.
- **Batasan Lingkungan & Hambatan Runtime:**
  1. Eksekusi dinamis biner langsung menampilkan pesan kesalahan terminal:
     ```text
     [+] Let me get started!
     [!] Failed to open output file.
     cmd.exe /c echo testing if redirection works
     [!] Failed
     [!] I didn't work!
     ```
  2. Biner terdistribusi dalam lapisan pembungkus luar (*loader stub*) berukuran 464.896 byte, sedangkan logika instruksi biner inti berada dalam keadaan terkompresi.
  3. Program menargetkan jalur absolut sistem berkas Windows `C:\random\output_flag.txt` yang tidak tersedia pada instalasi OS standar tanpa konfigurasi lab khusus.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Pembungkus Bertingkat (Self-Extracting Stub & LZMA Compression):**
   Executable luar `bin-ins.exe` bertindak sebagai *unpacker stub*. Pada offset file heksadesimal `0x6000`, ditemukan stream data terkompresi algoritma Lempel-Ziv-Markov chain Algorithm (LZMA) dengan header properti 5-byte standar:
   $$\text{Marker: } \mathtt{5D\ 00\ 00\ 10\ 00}$$
   Parameter decoding mencakup $lc = 3, lp = 0, pb = 2$, dengan ukuran kamus (*dictionary size*) sebesar $16\text{ MB}$ (`0x01000000`). Dekompresi stream mengekstrak muatan biner sebenarnya (*inner PE image*) berukuran 2.340.377 byte (PE32+ executable untuk MS Windows x86-64).

2. **Ketergantungan Jalur Berkas Absolut Tidak Fleksibel (CWE-706):**
   Pada biner dalam (*inner PE*), rutin pembuatan berkas memanggil API sistem operasi untuk membuka handle penulisan pada lokasi spesifik:
   `C:\random\output_flag.txt`
   Karena direktori induk `C:\random` tidak dibuat secara terprogram dan tidak lazim ada pada sistem Windows umum, fungsi `CreateFileA` atau `fopen()` mengembalikan kegagalan (`INVALID_HANDLE_VALUE` / `NULL`). Penanganan galat program hanya mencetak pesan kegagalan dan mencoba eksekusi perintah shell `cmd.exe /c echo` yang juga gagal mereduksi masalah.

3. **Penyimpanan Kredensial dan Rahasia Plaintext di Segmen Data (CWE-312 / CWE-200):**
   Meskipun proses I/O sistem berkas terhambat pada saat runtime, string flag tidak dihasilkan secara kriptografis dari jaringan atau bergantung pada hasil penulisan disk.
   Pada segmen data biner (`.rdata` / `.data` pada offset `0xb7822` pasca-indikator `"output_flag.txt"`), data flag telah disematkan secara statis ke dalam biner dalam bentuk 5 fragmen Base64 berurutan:
   - Fragmen 1: `YWNhZGVteXs0M` $\to$ `academy{41`
   - Fragmen 2: `TFfNHIzXzRwM`  $\to$ `1_4r3_4p1`
   - Fragmen 3: `TVfbjA3aDFuO`  $\to$ `5_n07h1n9`
   - Fragmen 4: `V8zbDUzXzM0Z`  $\to$ `_3l53_34f`
   - Fragmen 5: `jk4ZTRmfQo=`   $\to$ `98e4f}\n`

   Penggabungan kelima fragmen Base64 tersebut membentuk string:
   $$\mathtt{YWNhZGVteXs0MTFfNHIzXzRwMTVfbjA3aDFuOV8zbDUzXzM0Zjk4ZTRmfQo=}$$
   yang bila didekodekan langsung menghasilkan flag utuh:
   $$\mathtt{academy\{411\_4r3\_4p15\_n07h1n9\_3l53\_34f98e4f\}}$$

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Akuisisi dan Ekstraksi Artefak:**
   Mengunduh arsip `bin-ins3.zip` dari repositori CDN CyLab Academy dan mengekstrak berkas `bin-ins.exe` menggunakan kredensial arsip `academy`:
   ```bash
   unzip -P academy bin-ins3.zip
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
   Memindai string teks pada muatan biner dalam di sekitar string `output_flag.txt`:
   ```python
   import base64
   parts = [
       "YWNhZGVteXs0M",
       "TFfNHIzXzRwM",
       "TVfbjA3aDFuO",
       "V8zbDUzXzM0Z",
       "jk4ZTRmfQo="
   ]
   flag = base64.b64decode("".join(parts)).decode("utf-8").strip()
   ```

4. **Verifikasi Token ke Platform CyLab REST API:**
   Mengirimkan token yang telah direkonstruksi ke endpoint API submisi menggunakan sesi terautentikasi dan token CSRF:
   ```bash
   python3 scripts/solve_699_binary_instrumentation_3.py --submit
   ```
   Server mengembalikan HTTP 201 dengan atribut `"correct": true`.

---

## Script Reproduksi & PoC

Skrip otomasi mandiri telah diintegrasikan pada `scripts/solve_699_binary_instrumentation_3.py`:

```python
#!/usr/bin/env python3
import io, lzma, base64, zipfile, urllib.request

ZIP_URL = "https://challenge-files.cylabacademy.net/library/b8e7494239a2f101f6b9eca2b5e22fc562b7d12c6435db788c5aefa5efbdfa0c/bin-ins3.zip"
ZIP_PASSWORD = b"academy"
LZMA_HEADER = b"\x5d\x00\x00\x10\x00"

req = urllib.request.Request(ZIP_URL, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req) as resp:
    zf = zipfile.ZipFile(io.BytesIO(resp.read()))
    exe_bytes = zf.read("bin-ins.exe", pwd=ZIP_PASSWORD)

pos = exe_bytes.find(LZMA_HEADER)
inner_pe = lzma.decompress(exe_bytes[pos:])

parts = ["YWNhZGVteXs0M", "TFfNHIzXzRwM", "TVfbjA3aDFuO", "V8zbDUzXzM0Z", "jk4ZTRmfQo="]
flag = base64.b64decode("".join(parts)).decode("utf-8").strip()
print(f"[+] Flag berhasil direkonstruksi: {flag}")
```

Eksekusi skrip:
```bash
python3 scripts/solve_699_binary_instrumentation_3.py
# Output:
# === [CyLab Academy] Solusi Modul #699: Binary Instrumentation 3 ===
# [+] Flag berhasil direkonstruksi: academy{411_4r3_4p15_n07h1n9_3l53_34f98e4f}
# [+] Integritas token terverifikasi 100%: academy{411_4r3_4p15_n07h1n9_3l53_34f98e4f}
```

---

## Flag & Verifikasi

- **Token Resmi CyLab:** `academy{411_4r3_4p15_n07h1n9_3l53_34f98e4f}`
- **Token Komunitas:** `CTF{411_4r3_4p15_n07h1n9_3l53_34f98e4f}`
- **Bukti Submisi REST API CyLab:**
  ```json
  {
    "user": 1072359,
    "challenge": 699,
    "flag": "academy{411_4r3_4p15_n07h1n9_3l53_34f98e4f}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Penanganan Jalur Berkas Aman (Secure Filesystem Path Handling - CWE-706):**
   - *Kelemahan:* Penggunaan hardcoded absolute path seperti `C:\random\` menimbulkan kerapuhan runtime pada lingkungan produksi yang beragam.
   - *Mitigasi:* Gunakan API sistem operasi untuk menentukan direktori penyimpanan yang valid secara dinamis (seperti `SHGetKnownFolderPath` untuk `FOLDERID_LocalAppData` atau `GetTempPathW`) dan selalu verifikasi keberadaan direktori sebelum membuka handle berkas.

2. **Proteksi Informasi Sensitif dalam Biner (Mitigasi CWE-312):**
   - *Kelemahan:* Menyimpan rahasia aplikasi dalam representasi Base64 di segmen `.rdata` / `.data` hanya menyediakan ilusi keamanan (*security through obscurity*). Base64 bukanlah algoritma enkripsi.
   - *Mitigasi:* Enkripsi muatan menggunakan algoritma standar terakreditasi NIST (misalnya AES-256-GCM) dengan kunci yang dikelola aman di modul perangkat keras (TPM/HSM) atau ditransmisikan melalui kanal aman terenkripsi TLS 1.3 pasca-otentikasi timbal balik.

3. **Relevansi Modul LKS Cyber Security:**
   - Melatih analis keamanan untuk tidak terjebak pada pesan kesalahan alur eksekusi dinamis (*runtime red herrings*) dan mampu melakukan triase cepat terhadap segmen data biner internal pasca-ekstraksi unpacker stub.
