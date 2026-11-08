# Writeup: bytemancy 0 (Challenge ID: 742)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Byte Encoding, ASCII Mappings & TCP Socket IO (NIST SP 800-115 §4.4)
- **Difficulty:** Easy (1)
- **Points:** 50
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{pr1n74813_ch4r5_544482cc}`
- **Flag Komunitas:** `CTF{pr1n74813_ch4r5_544482cc}`
- **Standar Referensi:** NIST SP 800-115 §4.4 (System and Application Security Testing), RFC 20 (ASCII Character Set - 7-bit American Standard Code for Information Interchange), RFC 793 (Transmission Control Protocol Stream Delivery), CWE-20 (Improper Input Validation), CWE-704 (Incorrect Type Conversion or Cast), & OWASP ASVS V5 (Validation, Sanitization and Encoding).

---

## Problem Statement & Scope
Pada tantangan `bytemancy 0`, peserta diberikan layanan socket TCP on-demand (`app.py`) dan tautan unduhan kode sumber aplikasi:
- Deskripsi interaksi: Server menampilkan antarmuka bertema okultisme digital bertajuk `[ BYTEMANCY-0 ]` dan meminta masukan:
  `"Send me ASCII DECIMAL 101, 101, 101, side-by-side, no space."`
- Lingkungan eksekusi: Daemon Python 3 mendengarkan koneksi TCP pada port dinamis container (`xebec.cylabacademy.net:<port>`).
- Sasaran pengujian: Menganalisis alur validasi input, menerjemahkan representasi numerik desimal ke karakter ASCII standar RFC 20, merekonstruksi payload stream TCP, serta mengekstraksi flag otentik dari sistem berkas lokal `./flag.txt`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Representasi Karakter ASCII vs Nilai Desimal (RFC 20)
Standar RFC 20 mendefinisikan pemetaan kode 7-bit antara integer biner dan glif karakter ASCII. Nilai desimal $101$ setara dengan nilai heksadesimal $0\text{x}65$:
$$101_{10} = 6 \times 16^1 + 5 \times 16^0 = 0\text{x}65_{16}$$
Dalam tabel ASCII terstandar, byte $0\text{x}65$ merepresentasikan huruf kecil Latin `'e'`. Permintaan "tiga angka 101 berdampingan tanpa spasi" secara langsung memetakan ke triplet karakter ASCII `"eee"`.

### 2. Kesetaraan Literal String Python (Python String Literals)
Di dalam kode sumber `app.py`:
```python
user_input = input('==> ')
if user_input == "\x65\x65\x65":
    print(open("./flag.txt", "r").read())
    break
```
Kompiler Python menginterpretasikan escape sequence byte `\x65\x65\x65` sebagai literal string `"eee"`. Pada saat runtime, pembandingan kesetaraan string (`==`) mengevaluasi apakah buffer karakter `user_input` identik dengan `"eee"`. Tidak ada konversi tipe dinamis, hashing kriptografis, atau validasi HMAC yang diterapkan.

### 3. Otentikasi Berbasis Teka-Teki Statis (CWE-20 / Broken Access Control)
Mekanisme pertahanan aplikasi mengandalkan asumsi bahwa representasi numerik desimal merupakan teka-teki (*puzzle*) yang sulit diproses secara instan oleh entitas luar. Namun, karena verifikasinya sepenuhnya bersifat deterministik tanpa *proof-of-work* (PoW), tanpa *rate-limiting*, dan tanpa *nonce* penyegar sesi, satu transmisi TCP 3 byte dapat langsung membuka file sensitif sistem (`flag.txt`).

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Audit Kode Sumber `app.py`
Kode aplikasi diunduh dan diverifikasi dari CDN resmi CyLab:
```python
while(True):
  try:
    print('⊹──────[ BYTEMANCY-0 ]──────⊹')
    ...
    print('Send me ASCII DECIMAL 101, 101, 101, side-by-side, no space.')
    user_input = input('==> ')
    if user_input == "\x65\x65\x65":
      print(open("./flag.txt", "r").read())
      break
  except Exception as e:
    break
```
Kondisi percabangan mensyaratkan `user_input == "\x65\x65\x65"`, yang secara tepat adalah string ASCII `"eee"`.

### Langkah 2: Konstruksi Payload & Interaksi Socket TCP
Dibuat skrip otomasi socket klien Python (`scripts/solve_742_bytemancy_0.py`):
1. Membuat koneksi socket TCP streaming ke endpoint kontainer `(host, port)`.
2. Menerima banner inisial `[ BYTEMANCY-0 ]`.
3. Mengirimkan stream byte terterminasi newline:
   ```python
   s.sendall(b"eee\n")
   ```
4. Membaca respons stdout server hingga menemukan token flag `academy{...}`.

### Langkah 3: Ekstraksi Flag & Validasi
Server menerima `"eee"`, mengeksekusi `open("./flag.txt", "r").read()`, dan memancarkan:
```text
academy{pr1n74813_ch4r5_544482cc}
```

---

## Flag & Verifikasi
- **Flag Resmi CyLab:** `academy{pr1n74813_ch4r5_544482cc}`
- **Flag Format Komunitas:** `CTF{pr1n74813_ch4r5_544482cc}`
- **Verifikasi Live REST API CyLab:**
  Submisi ke `https://learn.cylabacademy.org/api/submissions/` mengembalikan respons status HTTP 201:
  `{"user": 1072359, "challenge": 742, "flag": "academy{pr1n74813_ch4r5_544482cc}", "correct": true, "historical": false}`.
- **Verifikasi Simulasi Offline:** Skrip `scripts/solve_742_bytemancy_0.py` menguji logika pemetaan `Bytemancy0Simulator` secara deterministik di bawah kerangka audit NIST SP 800-115.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Pemisahan Validasi Logika Masukan dan Hak Akses Sistem
Dalam kurikulum LKS Cyber Security bidang Network Security & Scripting:
- Jangan pernah menggunakan teka-teki pemetaan byte atau masukan statis sebagai mekanisme gerbang keamanan untuk mengekspos berkas rahasia (*secret files*).
- Jika layanan memerlukan otentikasi interaktif melalui CLI/socket, terapkan mekanisme pertukaran kunci kriptografis terstandar (misalnya challenge-response HMAC atau otentikasi berbasis token berbatas waktu / TOTP).

### 2. Pembatasan Input dan Pengendalian Ukuran Buffer
- Batasi panjang masukan maksimum dengan buffer tetap untuk mencegah potensi eksploitasi Denial of Service atau buffer parsing issues pada modul lanjutan.
- Pasang batas waktu koneksi (*idle socket timeout*) dan pembatasan frekuensi koneksi (*connection throttling*) per subnet untuk memitigasi serangan automatisasi scanning agresif.

### 3. Prinsip Least Privilege pada Penyimpanan Berkas Sensitif
Berkas sensitif seperti kunci enkripsi, token konfigurasi, atau `flag.txt` tidak boleh diletakkan dalam direktori kerja aplikasi yang dapat dibaca secara langsung oleh proses pengguna tanpa isolasi hak akses (*discretionary access control* / DAC).
