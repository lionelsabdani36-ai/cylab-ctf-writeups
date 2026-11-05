# Writeup: vault-door-7 (Challenge ID: 65)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Bit Manipulation & Packing
- **Difficulty:** Medium
- **Author:** Mark E. Haase
- **Event:** picoCTF 2019
- **Points:** 400
- **Flag:** `academy{A_b1t_0f_b1t_sh1fTiNg_575f3602ad}`

---

## Problem Statement & Scope
Diberikan berkas sumber Java `VaultDoor7.java`. Aplikasi memvalidasi input kata sandi sepanjang 32 karakter dengan cara memadatkan (packing) setiap 4 byte karakter ASCII menjadi satu bilangan bulat 32-bit (integer) bertipe big-endian. Sebanyak 8 bilangan bulat hasil konversi dibandingkan dengan array bilangan statis yang tertanam pada metode `checkPassword()`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Mekanisme Integer Packing & Endianness:**
   - Dalam arsitektur komputasi dan protokol jaringan (RFC 791 / RFC 9293 network byte order), data biner multi-byte sering diorganisasikan dalam urutan big-endian.
   - Metode `passwordToIntArray` memproses setiap 4 byte berturut-turut:
     ```java
     x[i] = hexBytes[i*4]   << 24
          | hexBytes[i*4+1] << 16
          | hexBytes[i*4+2] << 8
          | hexBytes[i*4+3];
     ```
   - Operasi ini memetakan byte paling signifikan (MSB) ke byte pertama dan byte paling tidak signifikan (LSB) ke byte keempat.
2. **Kelemahan Pembalikan Deterministik:**
   - Operasi pergeseran bit (bit shift) dan penggabungan bitwise OR merupakan pemetaan bijektif 1-ke-1 (one-to-one mapping).
   - Tidak ada fungsi hash kriptografis satu arah (one-way hash) atau salt yang diterapkan. Akibatnya, setiap integer 32-bit dapat dibalikkan kembali menjadi 4 karakter ASCII melalui ekstraksi byte standar.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Ekstrak 8 integer konstan dari `checkPassword()`:
   - `x[0] = 1096770097` -> hex `0x415f6231` -> ASCII `A_b1`
   - `x[1] = 1952395366` -> hex `0x745f3066` -> ASCII `t_0f`
   - `x[2] = 1600270708` -> hex `0x5f623174` -> ASCII `_b1t`
   - `x[3] = 1601398833` -> hex `0x5f736831` -> ASCII `_sh1`
   - `x[4] = 1716808014` -> hex `0x6654694e` -> ASCII `fTiN`
   - `x[5] = 1734292791` -> hex `0x675f3537` -> ASCII `g_57`
   - `x[6] = 895890230`  -> hex `0x35663336` -> ASCII `5f36`
   - `x[7] = 808608100`  -> hex `0x30326164` -> ASCII `02ad`
2. Rekonstruksi string utuh:
   `A_b1` + `t_0f` + `_b1t` + `_sh1` + `fTiN` + `g_57` + `5f36` + `02ad` = `A_b1t_0f_b1t_sh1fTiNg_575f3602ad`
3. Susun flag resmi format CyLab: `academy{A_b1t_0f_b1t_sh1fTiNg_575f3602ad}`.
4. Jalankan script reproduktif:
   ```bash
   python3 scripts/solve_65_vault_door_7.py
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{A_b1t_0f_b1t_sh1fTiNg_575f3602ad}`
- **Verifikasi:** POST `/api/submissions/` merespons `{"correct": true}` (HTTP Status 201 Created).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Takeaway LKS:** Peserta kompetisi LKS Cyber Security bidang Reverse Engineering harus memahami representasi memori integer (big-endian vs little-endian) serta mampu mengonversi array integer menjadi byte stream tanpa memerlukan eksekusi dinamis Java Virtual Machine (JVM).
- **Mitigasi Defensif:** Dalam perancangan autentikasi kredensial (NIST SP 800-63B), kredensial tidak boleh diverifikasi melalui perbandingan plaintext atau bitwise inverting sederhana. Gunakan Key Derivation Function (KDF) yang diperkuat seperti Argon2id atau PBKDF2 dengan salt acak unik per pengguna.
