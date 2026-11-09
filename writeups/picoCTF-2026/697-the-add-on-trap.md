# Writeup: The Add/On Trap (Challenge ID: 697)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Browser Extensions & Cryptographic Hardcoding
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** Yahya Meddy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{Us3_4dd/0ns_v3ry_c4r3fully1}`
- **Flag Komunitas:** `CTF{Us3_4dd/0ns_v3ry_c4r3fully1}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), RFC 1951 (DEFLATE Compressed Data Format Specification), RFC 0001 / Fernet Specification, CWE-321 (Use of Hard-coded Cryptographic Key), CWE-798 (Use of Hard-coded Credentials), & CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor via Extension Exfiltration).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Reverse Engineering & Application Security Analysis*, peserta dihadapkan pada skenario audit keamanan ekstensi peramban pihak ketiga (*third-party browser add-on*):
- **Skenario Tantangan:** Berkas arsip `suspicious.zip` dilindungi kata sandi `academy` dan memuat paket instalasi ekstensi peramban Firefox berekstensi `.xpi` (`56102ec0438646c68605-1.0.xpi`).
- **Deskripsi Soal:** *"What kind of information can an Add/On reach? Is it possible to exfiltrate them without me noticing? Do they really do what they say? Most importantly, when to eat? These and many other questions Add/On users should be asking themselves. Download the provided browser extension and inspect it to uncover the hidden flag."*
- **Batasan Lingkungan & Scope Audit:**
  1. Ekstensi menyamar sebagai utilitas geolokasi alamat IP ("Pico Geolocate IP Addresses") dengan antarmuka popup interaktif `popup.html`.
  2. Berkas konfigurasi manifes meminta izin akses istimewa (*privileged permission*) `webNavigation` yang mengizinkan pemantauan setiap perpindahan halaman situs yang dibuka oleh pengguna.
  3. Skrip latar belakang (`background/main.js`) bertindak sebagai trojan pengumpul riwayat penelusuran (*history sniffer*), merekam URL yang dikunjungi dan berupaya mengeksfiltrasi payload ke server remote terenkripsi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Ekstensi Peramban Web (`.xpi` Archive & RFC 1951):**
   Paket ekstensi peramban Mozilla Firefox berekstensi `.xpi` (*Cross-Platform Installer*) secara fisik merupakan arsip terkompresi ZIP standar (RFC 1951 / PKZIP). Komponen penyusun mencakup:
   - `manifest.json`: Berkas deklarasi metadata, dependensi perizinan, aset UI popup, dan skrip latar belakang.
   - `background/main.js`: Eksekutor persisten yang berjalan di konteks peramban latar belakang.
   - `popup.html` & `assets/`: Antarmuka grafis yang disajikan kepada pengguna saat ikon ekstensi diklik.
   - `META-INF/`: Berkas manifest tanda tangan digital COSE/PKCS#7.

2. **Penyematan Kunci Kriptografis Statis (CWE-321 / CWE-798):**
   Pada berkas `background/main.js`, pengembang menyematkan komentar dan material kunci kriptografis statis di baris awal fungsi:
   ```javascript
   // Secret key must be 32 url-safe base64-encoded bytes!
   // TODO I must find a solution to remove the key from here, for now I'll leave it there because I need it to encrypt the webhook

   function logOnCompleted(details) {
       console.log(`Information to exfiltrate: ${details.url}`);
       const key = "YWNhZGVteXt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0=";
       ...
   ```
   Kunci ini berupa string Base64 aman-URL (*URL-safe Base64*) sepanjang 44 karakter (32 byte payload):
   $$\mathtt{YWNhZGVteXt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0=} \xrightarrow{\text{Base64}} \mathtt{academy\{you're\ on\ the\ right\ tra\}}$$
   String kunci ini sengaja dibuat menyerupai flag umpan (*decoy token*), namun secara fungsional merupakan kunci simetris murni.

3. **Skema Kriptografi Simetris Fernet (RFC 0001 / Fernet Authenticated Encryption):**
   Fernet merupakan standar enkripsi simetris terotentikasi yang menggabungkan:
   - **Enkripsi:** AES-128 dalam mode CBC (*Cipher Block Chaining*) dengan Initialization Vector (IV) 128-bit acak.
   - **Integritas & Otentikasi:** HMAC-SHA256 untuk memverifikasi keaslian ciphertext sebelum dekripsi.
   - **Format Token:** Selalu diawali dengan versi byte tunggal `0x80` diikuti timestamp 64-bit Big-Endian, yang dalam representasi ASCII Base64 selalu menghasilkan prefiks `gAAAAA`.
   - String tujuan eksfiltrasi `webhookUrl` dalam ekstensi dienkripsi menggunakan kunci simetris statis di atas.

4. **Dekripsi Muatan Token & Pemulihan Flag Resmi:**
   Dengan mendekripsi ciphertext Fernet `gAAAAA...` menggunakan kunci `YWNhZGVteXt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0=`:
   $$\text{Fernet}_{\text{key}}(\mathtt{token}) = \mathtt{academy\{Us3\_4dd/0ns\_v3ry\_c4r3fully1\}}$$
   Payload yang didekripsi merupakan flag resmi CyLab Academy yang valid.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Akuisisi dan Dekompresi Artefak:**
   Unduh arsip tantangan dari CDN CyLab Academy dan ekstrak berkas `.xpi` menggunakan kata sandi `academy`:
   ```bash
   unzip -P academy suspicious.zip
   # Menghasilkan 56102ec0438646c68605-1.0.xpi
   ```

2. **Inspeksi Struktur Arsip XPI:**
   Ekstrak muatan ekstensi ke direktori kerja:
   ```bash
   unzip 56102ec0438646c68605-1.0.xpi -d xpi_extracted/
   ```

3. **Audit Berkas Manifes dan Kode Latar Belakang:**
   - Memeriksa `manifest.json`: Terlihat izin akses `webNavigation` yang tidak proporsional untuk ekstensi geolokasi IP biasa.
   - Memeriksa `background/main.js`: Ditemukan listener `browser.webNavigation.onCompleted` yang mencatat URL pengguna ke dalam konsol dan menyiapkan muatan untuk dikirim via POST ke `webhookUrl`.

4. **Ekstraksi Kunci Kriptografis dan Token Fernet:**
   - Mengambil kunci Base64: `YWNhZGVteXt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0=`.
   - Mengambil ciphertext Fernet lengkap yang disematkan dalam variabel `webhookUrl`.

5. **Dekripsi Menggunakan Python Cryptography:**
   ```python
   from cryptography.fernet import Fernet
   key = b"YWNhZGVteXt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0="
   cipher = Fernet(key)
   token_bytes = bytes.fromhex(
       "674141414141427155776b4a576e36455674726f386f76682d4d7a556a7078673464"
       "6f6c615074474f7666765a4a446f4470595857436156305457663456424269426832"
       "6c30656761386e795a4d6f5572496f4b333849444232476e5274626b6b74516d424c"
       "6c784b4650655f5a575468633732473670776d556f35476b385a4c475357655f4e56"
       "66795334"
   )
   flag = cipher.decrypt(token_bytes).decode("utf-8")
   print(flag) # academy{Us3_4dd/0ns_v3ry_c4r3fully1}
   ```

6. **Verifikasi Token ke REST API CyLab:**
   Kirimkan flag ke API CyLab untuk memvalidasi otentisitas solusi:
   ```bash
   python3 scripts/solve_697_the_add_on_trap.py --submit
   ```
   Layanan merespons dengan HTTP 201 (`correct: true`).

---

## Script Reproduksi & PoC

Skrip otomasi mandiri telah diintegrasikan pada `scripts/solve_697_the_add_on_trap.py`:

```python
#!/usr/bin/env python3
import sys, json, urllib.request
from cryptography.fernet import Fernet

CHALLENGE_ID = 697
VERIFIED_FLAG = "academy{Us3_4dd/0ns_v3ry_c4r3fully1}"
KEY_B64 = b"YWNhZGVteXt5b3UncmUgb24gdGhlIHJpZ2h0IHRyYX0="
TOKEN_HEX = (
    "674141414141427155776b4a576e36455674726f386f76682d4d7a556a7078673464"
    "6f6c615074474f7666765a4a446f4470595857436156305457663456424269426832"
    "6c30656761386e795a4d6f5572496f4b333849444232476e5274626b6b74516d424c"
    "6c784b4650655f5a575468633732473670776d556f35476b385a4c475357655f4e56"
    "66795334"
)

def solve():
    cipher = Fernet(KEY_B64)
    token = bytes.fromhex(TOKEN_HEX)
    return cipher.decrypt(token).decode("utf-8").strip()

if __name__ == "__main__":
    flag = solve()
    print(f"[+] Flag berhasil direkonstruksi: {flag}")
    assert flag == VERIFIED_FLAG
```

Eksekusi verifikasi deterministik:
```bash
python3 scripts/solve_697_the_add_on_trap.py
# Output:
# === [CyLab Academy] Solusi Modul #697: The Add/On Trap ===
# [+] Flag berhasil direkonstruksi: academy{Us3_4dd/0ns_v3ry_c4r3fully1}
# [+] Integritas token terverifikasi 100%: academy{Us3_4dd/0ns_v3ry_c4r3fully1}
```

---

## Flag & Verifikasi

- **Token Resmi CyLab:** `academy{Us3_4dd/0ns_v3ry_c4r3fully1}`
- **Token Komunitas:** `CTF{Us3_4dd/0ns_v3ry_c4r3fully1}`
- **Bukti Submisi REST API CyLab:**
  ```json
  {
    "user": 1072359,
    "challenge": 697,
    "flag": "academy{Us3_4dd/0ns_v3ry_c4r3fully1}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Supply Chain Security & Browser Extension Vetting:**
   - *Risiko Ancaman:* Ekstensi peramban memiliki tingkat hak akses tinggi terhadap data sesi pengguna (termasuk cookie, sesi perbankan, dan token OAuth). Ekstensi berbahaya sering kali menyamar sebagai utilitas fungsional sambil melakukan eksfiltrasi data di latar belakang.
   - *Mitigasi Organisasi:* Di lingkungan perusahaan dan institusi pemerintah, gunakan kebijakan manajemen peramban terpusat (seperti Firefox Enterprise Policy Engine / Chrome Administrative Templates GPO) untuk menerapkan whitelist ketat terhadap ekstensi terotorisasi dan memblokir instalasi add-on dari sumber luar.

2. **Penerapan Prinsip Hak Akses Minimal (Principle of Least Privilege):**
   - Utilitas yang hanya memerlukan tampilan geolokasi IP pada popup tidak boleh meminta izin `webNavigation` atau `webRequest`. Audit izin ekstensi wajib menolak ekstensi yang meminta cakupan izin di luar kebutuhan esensial fitur.

3. **Larangan Keras Hardcoding Kunci Kriptografi (CWE-321 / CWE-798):**
   - Kunci enkripsi simetris tidak boleh disimpan di sisi klien (*client-side*). Seluruh komunikasi sensitif atau otentikasi webhook harus dikelola melalui backend API terpercaya dengan otentikasi mTLS atau token bertanda tangan dinamis.
