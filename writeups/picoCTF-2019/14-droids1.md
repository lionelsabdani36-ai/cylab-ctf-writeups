# Writeup: droids1 (Challenge ID: 14)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Mobile Android Analysis
- **Difficulty:** Hard (diff=3)
- **Author:** Jason
- **Event:** picoCTF 2019
- **Points:** 350
- **Flag:** `academy{pining.for.the.fjords}`

---

## Problem Statement & Scope

Tantangan menguji kemampuan audit dan reverse engineering aplikasi mobile Android bertingkat:
> *"Find the pass, get the flag. Check out this file one.apk."*

Pengguna diberikan sebuah berkas APK Android (`one.apk`). Antarmuka aplikasi meminta pengguna memasukkan kata sandi ke dalam kotak input teks. Jika kata sandi cocok dengan kriteria internal, aplikasi akan mendekripsi dan menampilkan bendera. Analisis difokuskan pada pembedahan pustaka native ELF untuk memulihkan kata sandi yang diharapkan (*expected password*) serta algoritma penurunan kunci bendera.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Konstruksi Kata Sandi Dinamis Berbasis Operasi Aritmatika String (CWE-208 / Obfuscated Logic):**
   Fungsi native `nutmeg()` pada pustaka `libhellojni.so` tidak menyimpan kata sandi dalam bentuk plaintext langsung. Sebaliknya, fungsi ini menyusun karakter kata sandi satu per satu dengan melakukan kalkulasi indeks berbasis tabel referensi alfabet `"abcdefghijklmnopqrstuvwxyz"`.
   Meskipun menggunakan permutasi indeks aritmatika, seluruh masukan variabel bersifat konstan dan dieksekusi secara deterministik pada arsitektur x86_64/ARM.

2. **Ketergantungan Alur Dekripsi pada Kata Sandi yang Ditemukan (Dual-Stage Key Derivation):**
   Fungsi `Java_com_hellocmu_picoctf_FlagstaffHill_fenugreek` memverifikasi input pengguna melalui perbandingan `strcmp` dengan string hasil rekonstruksi `nutmeg()`. Bila cocok, kata sandi tersebut (`"opossum"`) digunakan langsung sebagai kunci XOR untuk memanggil fungsi `unscramble()` pada buffer sandi `anise()` di offset `0x1a3e`.

3. **Ketiadaan Validasi Sisi Server (Client-Side Trust Boundary Flaw):**
   Karena seluruh logika validasi dan aset ciphertext berada sepenuhnya pada perangkat klien (APK), penyerang dapat merekayasa balik (*reverse engineer*) seluruh algoritma tanpa perlu terhubung ke server atau menjalankan aplikasi pada perangkat fisik.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Ekstraksi Berkas APK & Penelusuran JNI
Mengekstrak paket APK dan menemukan pemanggilan native method di `classes.dex`:
```bash
unzip -q one.apk -d apk_unpacked/
strings classes.dex | grep fenugreek
```
Komponen Java `MainActivity` memanggil method native `FlagstaffHill.fenugreek(String input)`.

### Langkah 2: Analisis Logika Validasi `nutmeg()`
Memeriksa disassembly fungsi `nutmeg` di `lib/x86_64/libhellojni.so`:
```bash
objdump -d -M intel lib/x86_64/libhellojni.so | sed -n '/<nutmeg@@Base>:/,/<basil@@Base>:/p'
```
Operasi aritmatika pada `nutmeg` melakukan pemetaan indeks ke alfabet:
1. `var_14 = 5`, `var_18 = 13`, `var_1c = 1`
2. `out[3] = alphabet[18] = 's'`
3. `out[4] = alphabet[20] = 'u'`
4. `out[0] = alphabet[14] = 'o'`
5. `out[5] = alphabet[12] = 'm'`
6. `out[2] = alphabet[18] = 's'`
7. `out[1] = alphabet[15] = 'p'`
8. `out[6] = alphabet[14] = 'o'`

Hasil susunan kata sandi lengkap pada buffer adalah:
$$\text{Password} = \text{"opossum"}$$

### Langkah 3: Ekstraksi Ciphertext & Pemulihan Flag
Fungsi `anise()` mengambil string input valid (`"opossum"`) sebagai kunci untuk mendekripsi ciphertext 30-byte pada alamat offset `0x1a3e`:
```python
alphabet = "abcdefghijklmnopqrstuvwxyz"
password = b"opossum"
ciphertext = bytes.fromhex("0e130e171618141400061d1a1b0a411600015d01050a5e09191c07091c0d")
flag = bytes([ciphertext[i] ^ password[i % len(password)] for i in range(len(ciphertext))])
print(flag.decode())
# Output: academy{pining.for.the.fjords}
```

---

## Flag & Verifikasi

- **Flag:** `academy{pining.for.the.fjords}`
- **Bukti Validasi REST API CyLab:**
  ```json
  {"user": 1072359, "challenge": 14, "flag": "academy{pining.for.the.fjords}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Relevansi Uji Kompetensi LKS (Mobile & Binary Reversing):**
   Tantangan ini mencerminkan soal LKS tingkat nasional di mana logika pembongkaran sandi tidak hanya melibatkan Java string extraction biasa, melainkan melibatkan penelusuran kontrol alur assembly C pada antarmuka JNI. Peserta harus terbiasa melacak pergeseran stack pointer (`rbp-0x...`), operasi register aritmatika, serta menyusun skrip emulasi logika C secara mandiri tanpa tergantung pada execution runtime Android.

2. **Mitigasi Defensif (Mobile Security Architecture):**
   - **Zero-Trust Client Authentication:** Hindari memvalidasi otorisasi atau kata sandi kritis secara eksklusif pada sisi klien (*client-side only*). Verifikasi kredensial harus selalu dialihkan ke layanan backend terotentikasi melalui saluran TLS yang aman.
   - **Key Derivation Function (KDF):** Jika aplikasi offline membutuhkan penyimpanan data terenkripsi lokal, gunakan fungsi KDF standar industri seperti PBKDF2, Argon2, atau scrypt dengan garam acak (*random salt*) berkekuatan kriptografis, bukan XOR modular sederhana.
