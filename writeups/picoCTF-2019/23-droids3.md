# Writeup: droids3 (Challenge ID: 23)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Mobile Android Analysis
- **Difficulty:** Hard (diff=3)
- **Author:** Jason
- **Event:** picoCTF 2019
- **Points:** 450
- **Flag:** `academy{tis.but.a.scratch}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman mendalam tentang reverse engineering aplikasi Android dan rekayasa alur kontrol biner terkompilasi:
> *"Find the pass, get the flag. Check out this file three.apk."*

Pengguna diberikan berkas paket aplikasi Android `three.apk`. Pada antarmuka pengguna, tombol validasi mengevaluasi masukan pengguna. Jika ditinjau dari bytecode Java, aplikasi memanggil metode native yang tampak terhambat atau memerlukan modifikasi instruksi jika dijalankan pada emulator. Tujuan analisis adalah menelusuri rutin validasi JNI C/C++ pada pustaka biner `libhellojni.so` dan memulihkan flag secara mandiri.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Struktur Alur Kendali Pustaka Native C/C++ (JNI Export Analysis):**
   Modul biner `libhellojni.so` mengimplementasikan serangkaian fungsi JNI untuk kelas `FlagstaffHill`. Untuk `droids3`, fungsi yang diekspor adalah `Java_com_hellocmu_picoctf_FlagstaffHill_cilantro`.
   
2. **Evaluasi Fungsi Validasi Kondisional (Stub Evaluation):**
   Pada disassembly x86_64 rutin `cilantro`:
   - Fungsi memanggil stub validasi `dill()`.
   - Fungsi `dill()` mengembalikan nilai `1` secara deterministik (`mov eax, 0x1; ret`).
   - Hasil operasi `test al, 0x1` terpenuhi, mengarahkan eksekusi ke pemanggilan fungsi `sumac()`.

3. **Dekripsi Kriptografis Berbasis Kunci Statis (CWE-798 / Hardcoded Cryptographic Key):**
   Fungsi `sumac()` mengalokasikan parameter untuk rutin dekripsi:
   - String kunci dimuat dari offset `0x1a0d`: `"againmissing"`.
   - Buffer teks tersandi (*ciphertext*) sepanjang 26 byte (`0x1a`) dimuat dari offset `0x1a85`:
     `00 04 00 0d 0b 00 10 08 07 00 1d 49 03 12 15 47 0f 43 1a 10 01 08 1a 04 09 1a`
   - Rutin `unscramble()` mengeksekusi operasi XOR bergulir:
     $$\text{flag}[i] = \text{ciphertext}[i] \oplus \text{key}[i \pmod{\text{len}(\text{key})}]$$
   Karena kunci dan data tersandi bersifat statis di memori biner, flag dapat dipulihkan tanpa memerlukan patching biner atau eksekusi runtime emulator Android.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Ekstraksi Berkas APK
Mengekstrak berkas `three.apk` menggunakan utilitas ekstraksi arsip:
```bash
unzip -q three.apk -d unpacked/
```
Menemukan modul pustaka native:
- `lib/x86_64/libhellojni.so`

### Langkah 2: Inspeksi Simbol Ekspor Biner Native
Mengidentifikasi simbol dinamis yang relevan menggunakan `readelf`:
```bash
readelf -W -s lib/x86_64/libhellojni.so | grep -E "cilantro|sumac|unscramble"
```
Simbol menunjukkan fungsi `Java_com_hellocmu_picoctf_FlagstaffHill_cilantro` dan fungsi internal `sumac`.

### Langkah 3: Disassembly Rutin `sumac`
Menganalisis disassembly x86_64 rutin `sumac`:
```bash
objdump -d -M intel lib/x86_64/libhellojni.so | grep -A 25 "<sumac@@Base>:"
```
Instruksi menunjukkan:
- `lea rax, [rip + 0x13e]` menunjuk ke offset `0x1a0d` yang berisi string ASCII `"againmissing"`.
- `lea rax, [rip + 0x1ab]` menunjuk ke offset `0x1a85` yang berisi buffer sandi sepanjang `0x1a` (26 byte).
- Memanggil `unscramble(buf, 0x1a, key, 12)`.

### Langkah 4: Rekonstruksi Plaintext Flag
Menerapkan operasi XOR antara array byte sandi dan kunci `"againmissing"` melalui skrip Python:
```python
key = b"againmissing"
ciphertext = bytes.fromhex("0004000d0b00100807001d49031215470f431a1001081a04091a")
flag = bytes([ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))])
print(flag.decode())
# Output: academy{tis.but.a.scratch}
```

---

## Flag & Verifikasi

- **Flag:** `academy{tis.but.a.scratch}`
- **Bukti Validasi REST API CyLab:**
  ```json
  {"user": 1072359, "challenge": 23, "flag": "academy{tis.but.a.scratch}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Relevansi Uji Kompetensi LKS (Mobile Reverse Engineering):**
   Pada modul Reverse Engineering LKS Cyber Security, peserta sering diminta untuk membedah binary shared object Android yang memodifikasi aliran eksekusi fungsi Java. Peserta harus memiliki kapabilitas analisis statis menggunakan disassembler (`objdump`, Ghidra, IDA Pro), mengenali konvensi pemanggilan JNI (`JNIEnv*`, `jobject`, `jstring`), dan memetakan pointer offset data ke algoritma kriptografi.

2. **Mitigasi Defensif (Mobile Security Best Practices):**
   - **Enkripsi Kunci & White-Box Cryptography:** Jangan menyimpan kunci simetris secara mentah di segmen data biner ELF (`.rodata` atau `.data`).
   - **Symbol Stripping & Function Renaming:** Hapus seluruh simbol debugging dan ekspor fungsi internal (gunakan `strip --strip-all` atau `-fvisibility=hidden`).
   - **Control Flow Obfuscation:** Terapkan pengaburan kontrol aliran pada pustaka native guna mencegah analisis pola pemanggilan fungsi kritis.
