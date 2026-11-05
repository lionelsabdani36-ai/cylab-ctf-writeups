# Writeup: vault-door-training (Challenge ID: 7)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Java Source Code Static Analysis
- **Difficulty:** Easy (diff=1)
- **Author:** Mark E. Haase
- **Event:** picoCTF 2019
- **Points:** 50
- **Flag:** `academy{w4rm1ng_Up_w1tH_jAv4_8352733cecd}`

---

## Problem Statement & Scope

Tantangan memperkenalkan seri *Vault Door* yang mengevaluasi logika verifikasi kata sandi (*password authentication logic*) pada program Java:
> *"Your mission is to enter Dr. Evil's laboratory and retrieve the blueprints for his Doomsday Project. The laboratory is protected by a series of locked vault doors. Each door is controlled by a computer and requires a password to open. Unfortunately, our undercover agents have not been able to obtain the secret passwords for the vault doors, but one of our junior agents obtained the source code for each vault's computer! You will need to read the source code for each level to figure out what the password is for that vault door. As a warmup, we have created a replica vault in our training facility."*

Artefak yang disediakan berupa berkas kode sumber Java tunggal: `VaultDoorTraining.java`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Penggunaan Kredensial Hardcoded (CWE-798 & CWE-259):**
   - Masalah utama dalam arsitektur aplikasi ini adalah penanaman kredensial autentikasi langsung di dalam basis kode (*hardcoded credentials*).
   - Fungsi verifikasi `checkPassword(String password)` melakukan perbandingan kesetaraan nilai string secara langsung:
     ```java
     public boolean checkPassword(String password) {
         return password.equals("w4rm1ng_Up_w1tH_jAv4_8352733cecd");
     }
     ```
   - Siapa pun yang memiliki akses baca ke kode sumber (atau artefak bytecode `.class` melalui dekompiler seperti CFR, Jadx, atau Fernflower) dapat membaca kata sandi secara instan tanpa perlu melakukan serangan brute force.

2. **Tinjauan Kode Sumber Statis Sesuai Standar NIST SP 800-115:**
   - Berdasarkan NIST SP 800-115 (*Technical Guide to Information Security Testing and Assessment*, Section 5.3: *Source Code Review*), audit kode manual dan analisis statis merupakan metode verifikasi tingkat pertama untuk mengidentifikasi kesalahan arsitektural fatal seperti penyimpanan rahasia plaintext dan logika autentikasi rapuh.
   - Pengecekan substring pada input pengguna:
     ```java
     String input = userInput.substring("academy{".length(), userInput.length() - 1);
     ```
     mengindikasikan bahwa token akhir yang diinputkan pengguna harus diapit oleh pembungkus `academy{...}`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan Berkas Kode Sumber:**
   Unduh artefak kode sumber `VaultDoorTraining.java`:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/78ec91618d4c4219c55fbe2c9fc67ec6e248664564e6b2f13a54534aaf1d1000/VaultDoorTraining.java
   ```

2. **Pemeriksaan Isi Berkas:**
   Tampilkan baris logika validasi menggunakan `cat` atau `grep`:
   ```bash
   grep -C 3 "checkPassword" VaultDoorTraining.java
   ```
   Keluaran:
   ```java
   public boolean checkPassword(String password) {
       return password.equals("w4rm1ng_Up_w1tH_jAv4_8352733cecd");
   }
   ```

3. **Rekonstruksi Format Flag:**
   Sesuai logika fungsi `main`, masukan pengguna dipotong dari indeks panjang `"academy{"` hingga karakter sebelum kurung kurawal penutup:
   - Nilai token rahasia: `w4rm1ng_Up_w1tH_jAv4_8352733cecd`
   - Format flag lengkap: `academy{w4rm1ng_Up_w1tH_jAv4_8352733cecd}`

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{w4rm1ng_Up_w1tH_jAv4_8352733cecd}`
- **Verifikasi API Platform:** Validasi token melalui endpoint `POST /api/submissions/` menghasilkan respons sukses:
  ```json
  {"user": 1072359, "challenge": 7, "flag": "academy{w4rm1ng_Up_w1tH_jAv4_8352733cecd}", "correct": true, "historical": false}
  ```
  Status kode HTTP 201 Created mengonfirmasi keabsahan token.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi Inti LKS Cyber Security:** Pada modul *Reverse Engineering*, seri tantangan Java sering melibatkan abstraksi yang semakin kompleks dari tingkatan serial vault: perbandingan array karakter per indeks, operasi permutasi bit, hashing parsial, hingga XOR bersarang. Meninjau kode Java secara metodis dan memahami alur kontrol input/output adalah fondasi esensial untuk membedah tantangan reverse engineering berbasis JVM/Android APK.
- **Mitigasi Defensif (Secure Authentication Architecture):**
  1. *No Hardcoded Secrets:* Jangan pernah menyimpan rahasia autentikasi langsung dalam kode program.
  2. *Salted Cryptographic Hashing:* Kata sandi wajib di-*hash* menggunakan fungsi derivasi kunci yang tahan serangan GPU/ASIC (*memory-hard functions*) seperti Argon2id, bcrypt, atau PBKDF2 dengan garam (*salt*) unik yang dihasilkan secara kriptografis acak (CSPRNG).
  3. *Constant-Time Comparison:* Saat membandingkan hash atau token autentikasi, gunakan pembanding waktu konstan seperti `MessageDigest.isEqual()` di Java untuk mencegah serangan sampingan waktu (*timing attacks*).

---

## Solver

Skrip otomatis mandiri tersedia pada `scripts/solve_7_vault_door_training.py`.
