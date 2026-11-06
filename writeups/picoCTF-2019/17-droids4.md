# Writeup: droids4 (Challenge ID: 17)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Mobile Android Analysis
- **Difficulty:** Hard (diff=3)
- **Author:** Jason
- **Event:** picoCTF 2019
- **Points:** 500
- **Flag:** `academy{not.particularly.silly}`

---

## Problem Statement & Scope

Tantangan level tertinggi pada serial Android Droids:
> *"Reverse the pass, patch the file, get the flag. Check out this file four.apk."*

Pengguna diberikan paket biner Android `four.apk`. Pada tantangan ini, deskripsi menyarankan untuk memodifikasi biner (*patch the file*) atau membalik logika pemeriksaan kata sandi untuk memperoleh flag. Tujuan analisis adalah mengurai logika internal fungsi verifikasi JNI C/C++ pada `libhellojni.so` tanpa perlu melakukan repackaging APK atau menjalankan emulator.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Konstruksi Kunci Berbasis Aritmetika Karakter Dinamis (Obfuscated Key Generator):**
   Pada berkas pustaka native `libhellojni.so`, fungsi `Java_com_hellocmu_picoctf_FlagstaffHill_cardamom` memanggil rutin pemeriksa `chervil()`.
   Di dalam fungsi `chervil()`:
   - Program membuat empat salinan string dasar `"aaa"` (`rbp-0x10`, `rbp-0x18`, `rbp-0x20`, `rbp-0x28`).
   - Setiap byte dimodifikasi menggunakan operasi aritmetika penjumlahan offset karakter ASCII:
     - $s_1$: `['a'+4, 'a'+19, 'a'+18] = ['e', 't', 's']` $\rightarrow$ `"ets"`
     - $s_2$: `['a'+7, 'a'+0, 'a'+1] = ['h', 'a', 'b']` $\rightarrow$ `"hab"`
     - $s_3$: `['a'+0, 'a'+11, 'a'+15] = ['a', 'l', 'p']` $\rightarrow$ `"alp"`
     - $s_4$: `['a'+14, 'a'+20, 'a'+15] = ['o', 'u', 'p']` $\rightarrow$ `"oup"`
   - Keempat potongan string tersebut kemudian disusun menggunakan format `sprintf(buf, "%s%s%s%s", s3, s2, s1, s4)` yang menghasilkan kata sandi: `"alphabetsoup"`.

2. **Pencocokan Kredensial & Pemicu Rutin Dekripsi (JNI Execution Gate):**
   Input pengguna dicocokkan dengan kata sandi hasil komputasi menggunakan `strcmp(buf, input)`.
   Jika masukan bernilai sama dengan `"alphabetsoup"`, fungsi `cardamom` memanggil `pepper(input)`.

3. **Dekripsi Buffer Native Terenkripsi (Weak Stream Cipher):**
   Fungsi `pepper()` memuat buffer teks sandi sepanjang 31 byte (`0x1f`) dari segmen data biner pada offset `0x1aa0`:
   `00 0f 11 0c 04 0f 1c 0f 1d 00 01 5e 11 0d 02 1c 08 01 10 18 12 1d 19 09 4f 1f 19 04 0d 1b 18`
   Dekripsi dilakukan dengan rutin XOR bergulir:
   $$\text{flag}[i] = \text{ciphertext}[i] \oplus \text{"alphabetsoup"}[i \pmod{12}]$$
   Karena seluruh parameter dapat direkayasa balik secara statis, flag dapat dipulihkan secara langsung tanpa modifikasi kode APK.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Ekstraksi Berkas APK
Mengekstrak berkas `four.apk` menggunakan utilitas arsip:
```bash
unzip -q four.apk -d unpacked/
```
Pustaka target berlokasi di `lib/x86_64/libhellojni.so`.

### Langkah 2: Disassembly Rutin Rekonstruksi Sandi `chervil`
Mengurai instruksi perakitan fungsi `chervil` dengan `objdump`:
```bash
objdump -d -M intel lib/x86_64/libhellojni.so | grep -A 45 "<chervil@@Base>:"
```
Menemukan mutasi string `"aaa"`:
- `s1 = "ets"`
- `s2 = "hab"`
- `s3 = "alp"`
- `s4 = "oup"`
Pemanggilan `sprintf` dengan urutan register argumen x86_64 (`rdx=s3, rcx=s2, r8=s1, r9=s4`) menghasilkan string `"alphabetsoup"`.

### Langkah 3: Disassembly Rutin Dekripsi `pepper`
Memeriksa fungsi `pepper`:
```bash
objdump -d -M intel lib/x86_64/libhellojni.so | grep -A 20 "<pepper@@Base>:"
```
Instruksi memuat pointer ciphertext dari offset `0x1aa0` sepanjang 31 byte dan memanggil `unscramble`.

### Langkah 4: Pemulihan Flag Menggunakan Python
Mengeksekusi dekripsi XOR menggunakan kunci `"alphabetsoup"`:
```python
key = b"alphabetsoup"
ciphertext = bytes.fromhex("000f110c040f1c0f1d00015e110d021c08011018121d19094f1f19040d1b18")
flag = bytes([ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))])
print(flag.decode())
# Output: academy{not.particularly.silly}
```

---

## Flag & Verifikasi

- **Flag:** `academy{not.particularly.silly}`
- **Bukti Validasi REST API CyLab:**
  ```json
  {"user": 1072359, "challenge": 17, "flag": "academy{not.particularly.silly}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Relevansi Uji Kompetensi LKS (Mobile Reverse Engineering & Binary Patching):**
   Tantangan ini menguji kepekaan peserta dalam menelusuri pemanggilan register x86_64 ABI (`rdi, rsi, rdx, rcx, r8, r9`) pada rutin pembuatan string terobfuskasi. Peserta dapat menyelesaikan tantangan baik melalui analisis statis algoritma matematika karakter maupun melalui patching biner instruksi cabang `je` menjadi `nop` / `jmp` pada binary editor (seperti Hex Editor atau Ghidra).

2. **Mitigasi Defensif (Defense-in-Depth):**
   - **Anti-Tampering & Signature Verification:** Terapkan pemeriksaan digest sertifikat penandatanganan APK (*APK signature scheme v2/v3 verification*) saat inisialisasi aplikasi untuk mendeteksi upaya modifikasi biner.
   - **Environment Integrity Verification:** Pastikan aplikasi mendeteksi keberadaan debugger (ptrace, gdb, Frida) dan emulator guna mencegah inspeksi memori secara dinamis.
   - **Hardware Key Attestation:** Hindari implementasi kriptografi mandiri yang rentan, dan alihkan pengamanan aset berharga ke Secure Enclave / TEE (*Trusted Execution Environment*).
