# Writeup: bytemancy 3 (Challenge ID: 730)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / ELF Symbol Table Resolution & Raw Little-Endian Socket Serialization
- **Difficulty:** Hard (3)
- **Points:** 200
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{0bjdump_m4g1c_c79394e0}`
- **Flag Komunitas:** `CTF{0bjdump_m4g1c_c79394e0}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), CWE-20 (Improper Input Validation), CWE-1188 (Insecure Default Initialization of Resource), & OWASP ASVS V5 (Encoding and Memory Boundary Controls).

---

## Problem Statement & Scope
Pada modul pembelajaran tingkat lanjut `bytemancy 3`, peserta diuji dalam kemampuan analisis struktur biner tingkat rendah dan komunikasi soket berorientasi byte:
- Skenario lingkungan: Layanan jaringan Python (`app.py`) berjalan di balik socket TCP pada kontainer lab *on-demand*. Layanan ini terhubung dengan biner pembantu `spellbook` (ELF 32-bit x86). Server mengajukan kuis 3 ronde acak yang menuntut peserta mengirimkan representasi biner mentah (raw bytes) dari alamat memori virtual untuk prosedur-prosedur tertentu (`ember_sigil`, `glyph_conflux`, `astral_spark`, `binding_word`). Jika seluruh 3 jawaban dikirimkan secara presisi dalam format little-endian, server akan mencetak token bendera.
- Sasaran pengujian: Menganalisis tabel simbol ELF statis pada berkas biner `spellbook` menggunakan utilitas inspeksi biner (`nm`, `objdump`, `readelf`), mengekstrak alamat virtual fungsi yang tidak teracak (non-PIE), menyusun pustaka serialisasi byte mentah 32-bit little-endian, mengotomasi interaksi multi-ronde melalui socket TCP, dan memverifikasi token resmi pada REST API CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Invarian Alamat Memori Virtual pada Biner Non-PIE (CWE-1188)
Ketika sebuah program ELF x86 dikompilasi tanpa proteksi *Position Independent Executable* (`-no-pie` / tipe `ET_EXEC`), seluruh simbol fungsi dipetakan ke alamat memori virtual statis pada saat linking time:
```bash
readelf -h spellbook | grep Type
# Output: Type: EXEC (Executable file)
```
Karena bukan bertipe shared object (`ET_DYN`), kernel Linux memuat segmen teks biner ke basis alamat memori absolut (`0x08048000` pada arsitektur x86 32-bit). Hal ini menyebabkan Address Space Layout Randomization (ASLR) di tingkat sistem operasi tidak merandomisasi lokasi fungsi-fungsi internal:
- `ember_sigil`   $\rightarrow$ `0x08049156`
- `glyph_conflux` $\rightarrow$ `0x08049176`
- `astral_spark`  $\rightarrow$ `0x08049199`
- `binding_word`  $\rightarrow$ `0x080491b7`

### 2. Protokol I/O Presisi Byte & Little-Endian Packing
Server `app.py` mengimplementasikan fungsi pembacaan data `read_exact_bytes(4)` yang memblokir hingga tepat 4 byte diterima, kemudian melakukan konversi nilai via modul `struct`:
```python
val = struct.unpack("<I", raw_bytes)[0]
```
Karakteristik protokol:
- `<I` merepresentasikan bilangan bulat tanpa tanda 32-bit (*unsigned 32-bit integer*) berformat *Little-Endian* (byte bernilai rendah ditempatkan pada alamat memori lebih awal).
- Contoh serialisasi alamat `0x08049156`:
  - Byte 0: `0x56`
  - Byte 1: `0x91`
  - Byte 2: `0x04`
  - Byte 3: `0x08`
  - Representasi byte stream: `\x56\x91\x04\x08`.
- Kesalahan pengiriman newline tambahan (`\n`) atau kesalahan urutan byte (*endianness mismatch*) langsung menggagalkan validasi soket server.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Ekstraksi Tabel Simbol Biner
Unduh berkas `spellbook` dari repositori lab CyLab dan periksa tabel simbol menggunakan `nm` atau `objdump`:
```bash
nm spellbook | grep -E "sigil|conflux|spark|word"
```
Output:
```text
08049156 T ember_sigil
08049176 T glyph_conflux
08049199 T astral_spark
080491b7 T binding_word
```

### Langkah 2: Pemetaan Simbol ke Byte Little-Endian
Petakan keempat fungsi ke dalam representasi byte mentah 4-byte:
```python
import struct

symbols = {
    "ember_sigil": 0x08049156,
    "glyph_conflux": 0x08049176,
    "astral_spark": 0x08049199,
    "binding_word": 0x080491B7,
}
for name, addr in symbols.items():
    print(f"{name}: {hex(addr)} -> {struct.pack('<I', addr)}")
```
Output:
```text
ember_sigil: 0x8049156 -> b'V\x91\x04\x08'
glyph_conflux: 0x8049176 -> b'v\x91\x04\x08'
astral_spark: 0x8049199 -> b'\x99\x91\x04\x08'
binding_word: 0x80491b7 -> b'\xb7\x91\x04\x08'
```

### Langkah 3: Eksekusi Otomasi Soket Interaktif
Luncurkan lab kontainer on-demand via REST API CyLab:
```bash
PUT /api/challenges/730/instance/
```
Setelah kontainer `RUNNING` pada port target (misalnya `xebec.cylabacademy.net:23788`), jalankan skrip eksploitasi:
- Skrip menyaring nama prosedur dari prompt `Cast the procedure '<name>' ==> `.
- Mengambil alamat simbol yang sesuai dari kamus statis.
- Mengirimkan 4 byte mentah via `s.sendall(struct.pack("<I", addr))`.
- Mengulangi hingga 3 ronde selesai.

Output penerimaan respon server:
```text
Spell correctly cast!
Spell correctly cast!
Spell correctly cast!
You have mastered bytemancy! Here is your reward:
academy{0bjdump_m4g1c_c79394e0}
```

---

## Flag & Bukti Verifikasi
- **Token Resmi Platform CyLab:** `academy{0bjdump_m4g1c_c79394e0}`
- **Token Format Komunitas:** `CTF{0bjdump_m4g1c_c79394e0}`
- **Hasil Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 730,
    "flag": "academy{0bjdump_m4g1c_c79394e0}",
    "correct": true,
    "historical": false
  }
  ```

---

## Script Reproduksi & PoC Otomasi
Skrip audit reproduktif lengkap yang memodelkan parsing tabel simbol biner ELF non-PIE, konversi serialisasi endianness, serta verifikasi endpoint REST API CyLab tersedia pada `scripts/solve_730_bytemancy_3.py`:
```bash
python3 scripts/solve_730_bytemancy_3.py
```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Penerapan Mitigasi Kompiler Hardening (PIE & Full RELRO)
- **Kompilasi dengan Proteksi PIE:** Dalam sistem produksi, seluruh biner yang dieksekusi harus dikompilasi dengan bendera `-fPIE -pie`. PIE memastikan bahwa basis alamat memori fungsi diacak setiap kali proses dijalankan bersama ASLR kernel, menghilangkan ketergantungan pada alamat statis yang dapat dieksploitasi oleh penyerang.
- **Stripping Tabel Simbol:** Hapus informasi simbol debug dan nama fungsi pada biner produksi menggunakan `strip --strip-all <binary>` untuk meningkatkan kompleksitas analisis rekayasa balik.

### 2. Standar Protokol Jaringan Berorientasi Byte
- **Validasi Header & Panjang Data:** Protokol jaringan berbasis biner harus selalu menyertakan *magic bytes* dan verifikasi integritas (CRC32/HMAC) untuk memvalidasi bahwa muatan yang diterima berasal dari entitas terpercaya dan tidak mengalami korupsi transmisi.

---

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)
- **David (Leader):** Menetapkan metodologi pemecahan berbasis inspeksi struktur biner ELF statis dan memvalidasi alur verifikasi NIST SP 800-115.
- **Charlie (Trend-hunter):** Mengidentifikasi tipe soal interaksi soket presisi byte dan inspeksi biner `objdump`/`readelf` yang kerap muncul pada modul General Skills dan Binary LKS.
- **Alex (Fullstack-dev) & Omnirush (Coding Agent):** Merancang skrip serialisasi byte mentah `struct.pack("<I")` dan arsitektur simulasi 3-ronde lokal.
- **Julius (QA-engineer):** Menguji presisi I/O soket terhadap potensi *race condition* dan memvalidasi token flag resmi CyLab (HTTP 201).
- **Athena (Security-engineer):** Menganalisis kelemahan non-PIE pada arsitektur x86 berdasarkan taksonomi CWE-1188 dan prinsip mitigasi biner.
- **Judith (Guru LKS):** Mengintegrasikan materi serialisasi biner dan analisis tabel simbol ini ke dalam silabus persiapan kompetisi LKS Nasional.
