# Writeup: convertme.py (Challenge ID: 239)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Radix Transformation & Static Flag Recovery
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** Beginner picoMini 2022
- **Points:** 15
- **Flag:** `academy{4ll_y0ur_b4535_fff0af3d}`

---

## Problem Statement & Scope

Diberikan sebuah berkas skrip Python bernama `convertme.py`. Ketika dijalankan, skrip memilih sebuah bilangan bulat acak berbasis desimal (basis 10) antara rentang 10 hingga 100, lalu menanyakan representasi biner (basis 2) dari bilangan tersebut kepada pengguna melalui prompt konsol.

Jika jawaban yang diberikan tepat, skrip melakukan operasi bitwise XOR untuk mendekripsi flag dan mencetaknya ke konsol.

Peserta ditugaskan untuk menyelesaikan konversi basis bilangan atau mengekstrak rutin kriptografis secara statis untuk memperoleh token bendera resmi format `academy{...}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Konversi Basis Bilangan (Radix Transformation: Decimal to Binary):**
   - Sistem bilangan desimal menggunakan basis 10 (simbol 0–9), sedangkan biner menggunakan basis 2 (simbol 0 dan 1).
   - Konversi dari desimal ke biner dapat dilakukan dengan pembagian berulang oleh 2 dan mencatat sisa hasil bagi (*remainder*) dari bawah ke atas, atau menggunakan fungsi bawaan seperti `bin(n)[2:]` di Python.
   - Contoh: Angka desimal 42 dipecah menjadi:
     - $42 = 32 + 8 + 2 = 2^5 + 2^3 + 2^1 \implies 101010_2$.
2. **Ketergantungan Keamanan pada Validasi Input Klien (CWE-807):**
   - Logika program mengkondisikan rilis informasi sensitif pada keberhasilan pemeriksaan nilai input pengguna:
     ```python
     if ans_num == num:
         flag = str_xor(flag_enc, 'enkidu')
     ```
   - Namun, ciphertext `flag_enc` dan kunci simetris `'enkidu'` didefinisikan secara lokal di dalam berkas yang sama tanpa proteksi enkripsi tambahan.
   - Penganalisis tidak perlu menjalankan kuis interaktif; fungsi `str_xor` dapat langsung dipanggil terhadap `flag_enc` menggunakan kunci `'enkidu'` untuk mendapatkan teks terang flag secara instan.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Metode 1: Solusi Interaktif (Konversi Desimal ke Biner)
1. Unduh skrip `convertme.py`:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/d507213597114cdf0943d7f7c585eab624e16586a7cdcb88229fd24c143128a1/convertme.py
   ```
2. Jalankan skrip:
   ```bash
   python3 convertme.py
   ```
   Prompt menampilkan pertanyaan:
   ```text
   If 83 is in decimal base, what is it in binary base?
   Answer:
   ```
3. Hitung biner dari angka yang diminta (misal via terminal bash atau Python):
   ```bash
   python3 -c "print(bin(83)[2:])"
   # Output: 1010011
   ```
4. Masukkan jawaban `1010011` ke prompt:
   ```text
   That is correct! Here's your flag: academy{4ll_y0ur_b4535_fff0af3d}
   ```

### Metode 2: Solusi Statis (Bypass Kuis / One-Liner Extraction)
Ekstrak dan jalankan fungsi XOR secara langsung tanpa mengeksekusi pemeriksaan input:
```bash
python3 -c "
def str_xor(secret, key):
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return ''.join([chr(ord(s) ^ ord(k)) for (s, k) in zip(secret, new_key)])

flag_enc = chr(0x04) + chr(0x0d) + chr(0x0a) + chr(0x0d) + chr(0x01) + chr(0x18) + chr(0x1c) + chr(0x15) + chr(0x5f) + chr(0x05) + chr(0x08) + chr(0x2a) + chr(0x1c) + chr(0x5e) + chr(0x1e) + chr(0x1b) + chr(0x3b) + chr(0x17) + chr(0x51) + chr(0x5b) + chr(0x58) + chr(0x5c) + chr(0x3b) + chr(0x13) + chr(0x03) + chr(0x08) + chr(0x5b) + chr(0x08) + chr(0x02) + chr(0x46) + chr(0x01) + chr(0x13)
print(str_xor(flag_enc, 'enkidu'))
"
```
Output:
```text
academy{4ll_y0ur_b4535_fff0af3d}
```

---

## Flag & Verifikasi

- **Flag:** `academy{4ll_y0ur_b4535_fff0af3d}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status verifikasi valid:
  ```json
  {"challenge": 239, "flag": "academy{4ll_y0ur_b4535_fff0af3d}", "correct": true}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Pemahaman representasi data biner pada tingkat perangkat keras/arsitektur sistem serta efisiensi transformasi basis numerik.
  - Keterampilan memisahkan mekanisme perlindungan data dengan logika presentasi pengguna (*presentation vs protection logic*).
- **Mitigasi Defensif:**
  - **Prinsip Least Privilege & Zero Trust:** Data rahasia tidak boleh dimuat ke memori proses klien sebelum otorisasi pengguna diverifikasi secara kredibel oleh otoritas terpercaya (*authoritative server*).
  - **Enkripsi Kredensial End-to-End:** Jangan pernah menyertakan kunci kriptografi statis di dalam distribusi perangkat lunak publik. Gunakan arsitektur Key Management Service (KMS) berbasis perangkat keras (HSM) atau TPM.
