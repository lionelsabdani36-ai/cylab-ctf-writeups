# Writeup: droids2 (Challenge ID: 63)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Mobile Android Analysis
- **Difficulty:** Hard (diff=3)
- **Author:** Jason
- **Event:** picoCTF 2019
- **Points:** 400
- **Flag:** `academy{what.is.your.favourite.colour}`

---

## Problem Statement & Scope

Tantangan menguji keterampilan reverse engineering aplikasi mobile Android dengan lapisan hybrid Java dan biner native terkompilasi:
> *"Find the pass, get the flag. Check out this file two.apk."*

Pengguna diberikan paket biner Android (`two.apk`). Aplikasi meminta pengguna untuk memasukkan kata sandi ke dalam antarmuka grafis. Ketika tombol verifikasi ditekan, aplikasi mencocokkan input dan menampilkan flag jika sandi valid. Tujuan analisis adalah membongkar logika komputasi sandi dan mengekstrak flag tanpa harus menjalankan emulator fisik secara dinamis.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Komputasi Kunci Dinamis di Lapisan Java Dalvik (Obfuscated Key Construction):**
   Pada berkas `classes.dex`, kelas `com.hellocmu.picoctf.FlagstaffHill` mendefinisikan array nama-nama karakter:
   ```java
   String[] witches = {"weatherwax", "ogg", "garlick", "nitt", "aching", "dismass"};
   ```
   Alih-alih menyimpan kata sandi dalam bentuk string plaintext, kode Java menyusun kata sandi menggunakan serangkaian operasi aritmetika bilangan bulat untuk menentukan indeks elemen array yang akan digabungkan:
   - Indeks yang dipilih adalah: `5, 1, 0, 4, 3, 2`
   - Hasil penggabungan dengan pemisah titik (`.`) menghasilkan string: `dismass.ogg.weatherwax.aching.nitt.garlick`.

2. **Arsitektur JNI & Penundaan Dekripsi Kriptografis (JNI Handshake):**
   Setelah input dicocokkan dengan kata sandi hasil kalkulasi, Java memanggil metode native `sesame(input)` yang didefinisikan dalam `libhellojni.so`.
   Di dalam modul native ELF (`libhellojni.so`):
   - Fungsi `Java_com_hellocmu_picoctf_FlagstaffHill_sesame` memeriksa kembali input via `basil()`.
   - Jika valid, fungsi memanggil `oregano(input)` yang memuat ciphertext sepanjang 39 byte dari segmen data pada offset `0x1a5d`.
   - Fungsi `unscramble()` mengeksekusi operasi XOR bergulir:
     $$\text{flag}[i] = \text{ciphertext}[i] \oplus \text{password}[i \pmod{\text{len}(\text{password})}]$$

3. **Kelemahan Kriptografi Simetris Statis (CWE-321 / CWE-798):**
   Meskipun kata sandi disusun secara modular di lapisan Java, seluruh ciphertext dan algoritma dekripsi berada di dalam biner client-side. Siapapun yang memiliki akses ke file APK dapat membaca struktur memori dan merekonstruksi teks terang secara instan.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Dekompresi dan Inspeksi Berkas APK
Mengekstrak paket APK sebagai arsip ZIP:
```bash
unzip -q two.apk -d unpacked/
```
Struktur komponen penting:
- `classes.dex`: Bytecode Dalvik Java aplikasi.
- `lib/x86_64/libhellojni.so`: Shared Object C/C++ native untuk arsitektur x86_64.

### Langkah 2: Rekonstruksi Kata Sandi dari Bytecode Dalvik
Pemeriksaan pada `FlagstaffHill` menunjukkan logika pembentukan sandi:
```text
witches = ["weatherwax", "ogg", "garlick", "nitt", "aching", "dismass"]
password = witches[5] + "." + witches[1] + "." + witches[0] + "." + witches[4] + "." + witches[3] + "." + witches[2]
password = "dismass.ogg.weatherwax.aching.nitt.garlick"
```

### Langkah 3: Disassembly Biner Native `libhellojni.so`
Menganalisis rutin `oregano` pada `lib/x86_64/libhellojni.so` menggunakan `objdump`:
```bash
objdump -d -M intel lib/x86_64/libhellojni.so | grep -A 20 "<oregano@@Base>:"
```
Rutin memuat pointer ciphertext pada `rip + 0x1ea` (offset `0x1a5d`), panjang `0x27` (39 byte), dan meneruskannya ke `unscramble(buf, 0x27, key, strlen(key))`.

### Langkah 4: Rekonstruksi Flag Melalui Python
Membaca 39 byte ciphertext dari biner dan melakukan operasi XOR dengan kunci yang ditemukan:
```python
key = b"dismass.ogg.weatherwax.aching.nitt.garlick"
ciphertext = bytes.fromhex("050a1209041e0a55180f065a590c125a110a07054f1e4f170c1d1b07134b400a1b184112130f6c")
flag = bytes([ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))])
print(flag.decode())
# Output: academy{what.is.your.favourite.colour}
```

---

## Flag & Verifikasi

- **Flag:** `academy{what.is.your.favourite.colour}`
- **Bukti Validasi REST API CyLab:**
  ```json
  {"user": 1072359, "challenge": 63, "flag": "academy{what.is.your.favourite.colour}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Relevansi Uji Kompetensi LKS (Mobile Application Security):**
   Tantangan ini mencerminkan skenario umum pada LKS Cyber Security di mana analis harus menghubungkan bukti antara dua lapisan arsitektur yang berbeda (DEX bytecode dan C/C++ native shared object). Kemampuan mengisolasi algoritma kunci dari dekompilasi Java dan memetakannya ke ciphertext pada biner native adalah keterampilan inti reverse engineering.

2. **Mitigasi Defensif (Hardening Rekomendasi):**
   - **Eliminasi Client-Side Secret:** Validasi kredensial dan pembukaan fitur sensitif harus selalu diverifikasi di sisi server yang terpercaya (*server-side authorization*).
   - **Obfuscation Lanjut (DexGuard & OLLVM):** Gunakan perkakas pengabur kontrol aliran bytecode dan string native enkripsi untuk menyulitkan pemulihan statis.
   - **Integrity Attestation:** Terapkan Play Integrity API / SafetyNet untuk memverifikasi keaslian biner aplikasi sebelum mengeksekusi rutin sensitif.
