# Writeup: droids0 (Challenge ID: 11)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Mobile Android Analysis
- **Difficulty:** Hard (diff=3)
- **Author:** Jason
- **Event:** picoCTF 2019
- **Points:** 300
- **Flag:** `academy{a.moose.once.bit.my.sister}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan reverse engineering aplikasi mobile Android:
> *"Where do droid logs go. Check out this file zero.apk."*

Berkas yang diberikan berupa paket aplikasi Android (`zero.apk`). Pengguna diminta untuk menganalisis aplikasi, menelusuri bagaimana flag diproses, dan mengekstrak flag rahasia yang tersembunyi di dalam mekanisme aplikasi tanpa memerlukan perangkat emulator Android fisik.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Android APK & Lapisan Java Native Interface (JNI):**
   Aplikasi Android dibangun dari kombinasi kode bytecode Dalvik/ART (`classes.dex`) dan modul pustaka biner native C/C++ (`.so`) yang dimuat melalui JNI (`System.loadLibrary`). Ketika komponen Java (`MainActivity`) membutuhkan operasi sensitif atau teroptimasi, eksekusi didelegasikan ke fungsi native terkompilasi yang dideklarasikan di antarmuka `FlagstaffHill`.

2. **Ketergantungan Kunci Kriptografi Hardcoded pada Biner Native (CWE-798 / CWE-321):**
   Pustaka native `libhellojni.so` mengimplementasikan fungsi `Java_com_hellocmu_picoctf_FlagstaffHill_paprika`. Fungsi ini memverifikasi input menggunakan fungsi stub `dill()` yang selalu mengembalikan nilai kebenaran `1`, lalu memanggil fungsi pembantu `marjoram()`.
   Di dalam `marjoram()`, program memuat string kunci `notexist` dan array byte sandi yang keduanya tersimpan secara statis di segmen data biner.

3. **Dekripsi XOR Sederhana (Weak Cryptographic Routine):**
   Fungsi `unscramble()` menerapkan algoritma dekripsi XOR byte-per-byte:
   $$\text{flag}[i] = \text{ciphertext}[i] \oplus \text{key}[i \pmod{\text{len}(\text{key})}]$$
   Karena kunci dan ciphertext tersedia secara langsung di dalam biner tanpa enkripsi berlapis atau perlindungan white-box cryptography, teks terang (*plaintext*) flag dapat dipulihkan secara instan melalui analisis statis.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Ekstraksi Paket APK
Paket APK pada hakikatnya merupakan arsip ZIP standar. Berkas dapat diekstrak menggunakan utilitas `unzip`:
```bash
unzip -q zero.apk -d apk_extracted/
```
Struktur berkas menunjukkan:
- `classes.dex`: Bytecode Dalvik Java aplikasi.
- `lib/x86_64/libhellojni.so`: Modul biner native ELF 64-bit.

### Langkah 2: Inspeksi Dekompilasi & Panggilan JNI
Pemeriksaan string pada `classes.dex` menunjukkan kelas `com/hellocmu/picoctf/FlagstaffHill` mendeklarasikan pemanggilan fungsi native bernama `paprika`:
```bash
strings classes.dex | grep paprika
```

### Langkah 3: Analisis Disassembly `libhellojni.so`
Menganalisis simbol dan fungsi native pada `lib/x86_64/libhellojni.so` menggunakan `objdump`:
```bash
objdump -d -M intel lib/x86_64/libhellojni.so | grep -A 30 "paprika"
```
Alur fungsi `paprika` memanggil `dill()` (selalu `true`), kemudian memanggil `marjoram()`. Pada fungsi `marjoram()`:
- Pointer `0x1a04` memuat string kunci `notexist`.
- Pointer `0x1a1a` memuat ciphertext sepanjang 35 byte (`0x23`).
- Memanggil `unscramble(0x1a1a, 0x23, "notexist", 8)`.

### Langkah 4: Rekonstruksi Algoritma dengan Python
Melakukan pembacaan langsung dan dekripsi XOR byte array:
```python
key = b"notexist"
ciphertext = bytes.fromhex("0f0c15011d040a0f0f41190a171a165a01011700560b1a0040020d4b0b0000000b1d09")
flag = bytes([ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))])
print(flag.decode())
# Output: academy{a.moose.once.bit.my.sister}
```

---

## Flag & Verifikasi

- **Flag:** `academy{a.moose.once.bit.my.sister}`
- **Bukti Validasi REST API CyLab:**
  ```json
  {"user": 1072359, "challenge": 11, "flag": "academy{a.moose.once.bit.my.sister}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Relevansi Uji Kompetensi LKS (Mobile Reverse Engineering):**
   Pada LKS Cyber Security bidang Reverse Engineering, peserta sering kali dihadapkan pada berkas APK yang menyembunyikan logika validasi di dalam Shared Object (`.so`) untuk mengelabui dekompiler Java (seperti Jadx atau JAD). Peserta harus mahir membaca struktur APK sebagai kontainer ZIP, mengekstrak pustaka arsitektur yang relevan, menelusuri simbol JNI C/C++, serta membedah assembly x86_64/ARM untuk merekonstruksi aliran data kriptografi.

2. **Mitigasi Defensif (Mobile Application Security Verification Standard - MASVS):**
   - **MASVS-CRYPTO:** Jangan pernah menyimpan kunci enkripsi atau data sensitif secara plaintext di dalam aset aplikasi maupun pustaka biner native terkompilasi.
   - Gunakan Android Keystore System yang didukung perangkat keras (*Hardware-backed KeyStore*) untuk menyimpan kunci privat.
   - Terapkan teknik proteksi biner (obfuscation, control flow flattening, string encryption via OLLVM) serta mekanisme anti-tamper untuk mempersulit analisis statis dan dinamis.
