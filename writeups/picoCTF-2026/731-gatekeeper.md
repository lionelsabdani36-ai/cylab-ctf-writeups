# Writeup: Gatekeeper (Challenge ID: 731)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Base-16 vs Base-10 Representation Contradiction & String Obfuscation Inversion
- **Difficulty:** Medium (2)
- **Points:** 100
- **Author:** Yahya Meddy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{3_digit_hex_GT_999_fed7fa16}`
- **Flag Komunitas:** `CTF{3_digit_hex_GT_999_fed7fa16}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), CWE-20 (Improper Input Validation), CWE-1287 (Improper Validation of Specified Type of Input), & OWASP ASVS V5 (Validation, Sanitization, and Encoding Verification).

---

## Problem Statement & Scope
Pada tantangan `Gatekeeper`, peserta diberikan biner ELF 64-bit Linux yang beroperasi di balik socket TCP interaktif:
- Skenario lingkungan: Program menyajikan pesan sambutan `Enter a numeric code (must be > 999 ): ` dan menunggu input dari pengguna. Jika kode yang diberikan memenuhi seluruh batasan validasi biner, fungsi `reveal_flag()` akan membaca `/flag.txt` dan mengirimkan keluaran yang diobfuskasi ke terminal pengguna.
- Sasaran pengujian: Menganalisis alur logika verifikasi input pada fungsi `main()` menggunakan teknik dekompilasi/disassembly, mengungkap inkonsistensi batasan numerik (kontradiksi basis 10 vs basis 16), menyusun input valid untuk memicu eksekusi fungsi pengungkap bendera, serta merekayasa algoritma inversi untuk memulihkan string bendera asli dari keluaran yang diobfuskasi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Kontradiksi Batasan Input & Representasi Basis Bilangan (CWE-20 / CWE-1287)
Pemeriksaan disassembly pada fungsi `main` (alamat offset `0x158e`) memperlihatkan bahwa biner membaca string input pengguna via `__isoc99_scanf("%31s", buffer)` dan melakukan dua tahap parsing bersyarat:
1. Menguji apakah string memenuhi karakter desimal melalui fungsi `is_valid_decimal()`. Jika valid, string dikonversi menjadi integer via `atoi(buffer)`.
2. Jika bukan representasi desimal murni, biner menguji apakah string merupakan heksadesimal valid via `is_valid_hex()`. Jika valid, string dikonversi via `strtol(buffer, NULL, 16)`.

Setelah nilai numerik integer diperoleh, program memberlakukan tiga batasan logis simultan:
- $val > 999$ (`cmp eax, 0x3e7; jg`)
- $val \le 9999$ (`cmp eax, 0x270f; jle`)
- $\text{strlen}(buffer) == 3$ (`cmp rax, 0x3; jne`)

Pada representasi desimal (basis 10), bilangan integer yang lebih besar dari $999$ memiliki nilai minimum $1000$. Rentang $[1000, 9999]$ secara matematis membutuhkan tepat 4 digit karakter desimal (`"1000"` hingga `"9999"`). Tidak ada bilangan desimal $> 999$ yang dapat direpresentasikan dalam 3 karakter.
Namun, karena parser biner juga menerima representasi heksadesimal (basis 16), nilai integer $1000_{10}$ dapat dituliskan sebagai heksadesimal `0x3e8`. String `"3e8"` memiliki panjang tepat 3 karakter (`strlen == 3`) dan memiliki nilai numerik $1000$ yang memenuhi kondisi $999 < val \le 9999$.

### 2. Obfuskasi Reversible pada `reveal_flag()`
Setelah verifikasi lolos, fungsi `reveal_flag()` membaca berkas `/flag.txt` ke dalam buffer memori, lalu melakukan iterasi cetak karakter dengan pengaburan:
- Iterasi dimulai dari indeks karakter terakhir menuju awal ($i = N-1$ turun ke $0$).
- Setiap karakter dicetak satu per satu (`putchar(flag[i])`).
- Pada setiap indeks yang memenuhi $(i \pmod 4 == 0)$, biner menyisipkan string bising pengabur `ftc_oc_ip` (`printf("ftc_oc_ip")`).

Keluaran server menghasilkan string terbalik yang disisipi derau:
```text
}61aftc_oc_ipf7deftc_oc_ipf_99ftc_oc_ip9_TGftc_oc_ip_xehftc_oc_ip_tigftc_oc_ipid_3ftc_oc_ip{ymeftc_oc_ipdacaftc_oc_ip
```
Karena transformasi bersifat deterministik dan linear, inversi dapat dilakukan dengan:
1. Menghapus seluruh token pengabur `ftc_oc_ip` (`scrambled.replace("ftc_oc_ip", "")`).
2. Membalik urutan string yang telah dibersihkan (`cleaned[::-1]`).

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Analisis Statis Biner dengan Ghidra / Objdump
Unduh biner `gatekeeper` dari CDN CyLab Academy dan periksa tabel fungsi serta logika percabangan:
```bash
readelf -h gatekeeper
objdump -d -M intel gatekeeper | grep -A 30 "<main>:"
```
Disassembly menunjukkan instruksi perbandingan kunci:
```assembly
15df:   call   14e3 <is_valid_decimal>
15e4:   test   eax, eax
15e6:   je     1604 <check_hex>
15e8:   lea    rdi, [rbp-0x30]
15ec:   call   atoi
...
1604:   call   152b <is_valid_hex>
1609:   test   eax, eax
160b:   je     1694 <fail_exit>
...
1630:   cmp    eax, 0x3e7       ; cmp val, 999
1635:   jle    1694 <fail_exit>
1637:   cmp    eax, 0x270f      ; cmp val, 9999
163c:   jg     1694 <fail_exit>
163e:   cmp    QWORD PTR [rbp-0x18], 0x3 ; cmp strlen, 3
1643:   jne    1694 <fail_exit>
1645:   call   1449 <reveal_flag>
```

### Langkah 2: Evaluasi Nilai Kunci Bypass
Hitung representasi heksadesimal dari batas bawah:
- Nilai target minimum: $1000$ (desimal).
- Konversi ke basis 16: $1000 / 16 = 62 \text{ sisa } 8$, $62 / 16 = 3 \text{ sisa } 14 \text{ (e)}$, $3 / 16 = 0 \text{ sisa } 3 \rightarrow \text{0x3e8}$.
- Panjang karakter: `"3e8"` = 3 karakter.

### Langkah 3: Interaksi Live Socket & Pengambilan Keluaran
Hubungkan ke endpoint kontainer lab:
```bash
nc chatelaine.cylabacademy.net 17012
```
Kirimkan string input:
```text
3e8
```
Respon dari server:
```text
Access granted: }61aftc_oc_ipf7deftc_oc_ipf_99ftc_oc_ip9_TGftc_oc_ip_xehftc_oc_ip_tigftc_oc_ipid_3ftc_oc_ip{ymeftc_oc_ipdacaftc_oc_ip
```

### Langkah 4: De-obfuskasi String & Rekonstruksi Flag
Jalankan operasi pembersihan derau dan pembalikan string dalam Python:
```python
raw = "}61aftc_oc_ipf7deftc_oc_ipf_99ftc_oc_ip9_TGftc_oc_ip_xehftc_oc_ip_tigftc_oc_ipid_3ftc_oc_ip{ymeftc_oc_ipdacaftc_oc_ip"
cleaned = raw.replace("ftc_oc_ip", "")
flag = cleaned[::-1]
print(flag)
# Output: academy{3_digit_hex_GT_999_fed7fa16}
```

---

## Flag & Bukti Verifikasi
- **Token Resmi Platform CyLab:** `academy{3_digit_hex_GT_999_fed7fa16}`
- **Token Format Komunitas:** `CTF{3_digit_hex_GT_999_fed7fa16}`
- **Hasil Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 731,
    "flag": "academy{3_digit_hex_GT_999_fed7fa16}",
    "correct": true,
    "historical": false
  }
  ```

---

## Script Reproduksi & PoC Otomasi
Skrip audit reproduktif lengkap yang menyimulasikan parser biner, pengujian batas input multi-basis, serta inversi obfuscation tersedia pada `scripts/solve_731_gatekeeper.py`:
```bash
python3 scripts/solve_731_gatekeeper.py
```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Penanganan Tipe Input yang Konsisten (CWE-1287 Remediation)
- **Hindari Multi-Basis Parsing Implisit:** Bila suatu antarmuka mengharapkan masukan angka desimal dari pengguna manusia, batasi parsing secara eksplisit hanya pada basis 10 (`strtol(buf, &endptr, 10)`). Jangan mengizinkan fallback otomatis ke basis 16 tanpa validasi format yang jelas.
- **Validasi Konsistensi Semantik:** Pastikan aturan validasi panjang input (`strlen`) konsisten dengan batasan rentang nilai numerik untuk mencegah celah logika (*logic flaw* / *paradoxical condition*).

### 2. Evaluasi Keamanan Obfuskasi String
- **Obfuskasi Bukan Enkripsi:** Menyisipkan string bising atau membalikkan urutan karakter tidak memberikan perlindungan kerahasiaan (*confidentiality*). Pada pengujian defensif LKS, identifikasi logika transformasi linear dan gunakan otomasi skrip untuk membalikkan artefak data tersembunyi.

---

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)
- **David (Leader):** Mengarahkan strategi reverse engineering pada kontrol logika multi-basis dan menyusun metodologi verifikasi NIST SP 800-115.
- **Charlie (Trend-hunter):** Menyoroti pola soal logika multi-basis dan manipulasi string pada sub-kategori Reverse Engineering kompetisi CTF dan LKS.
- **Alex (Fullstack-dev) & Omnirush (Coding Agent):** Mengimplementasikan simulator parsing biner lokal dan modul otomatisasi de-obfuskasi Python.
- **Julius (QA-engineer):** Memvalidasi akurasi inversi string dan memastikan respon API CyLab mengembalikan status valid HTTP 201.
- **Athena (Security-engineer):** Menganalisis inkonsistensi input validation terhadap standar CWE-20 dan panduan verifikasi OWASP ASVS V5.
- **Judith (Guru LKS):** Menggunakan studi kasus ini sebagai bahan ajar modul *Reverse Engineering & Logic Flaws* dalam kurikulum LKS.
