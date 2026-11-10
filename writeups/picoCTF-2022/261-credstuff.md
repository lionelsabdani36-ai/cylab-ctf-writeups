# Writeup: credstuff (Challenge ID: 261)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Credential Leak & Classical Substitution Cipher (CWE-256 / CWE-327 / OAT-008)
- **Difficulty:** Easy (diff=1)
- **Event:** picoCTF 2022
- **Points:** 100
- **Author:** Will
- **Flag:** `academy{C7r1F_54V35_71M3}`

---

## Problem Statement & Scope
Tantangan `credstuff` mensimulasikan skenario investigasi insiden kebocoran data otentikasi dari platform pasar gelap (blackmarket). Peserta diberikan arsip terkompresi `leak.tar` yang berisi dua berkas teks berukuran ratusan baris: `usernames.txt` dan `passwords.txt`. Baris ke-$n$ pada `usernames.txt` berkorelasi secara langsung 1:1 dengan baris ke-$n$ pada `passwords.txt`. Sasaran investigasi adalah melacak kredensial milik pengguna bernama `cultiris`, mengidentifikasi skema perlindungan kriptografis yang digunakan pada string sandinya, dan mendekripsi kata sandi tersebut untuk memperoleh bendera kompetisi.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penyimpanan Kredensial Reversibel dan Tidak Ter-hash (CWE-256 / CWE-312 / CWE-327):**
   Sistem menyimpan kata sandi pengguna dalam bentuk sandi klasik reversibel (substitution cipher) alih-alih menerapkan fungsi *cryptographic one-way password hash* ber-salt adaptif (seperti Argon2id, scrypt, atau PBKDF2). Penyimpanan kredensial secara reversibel melanggar prinsip dasar *confidentiality* dan kepatuhan standar NIST SP 800-63B.
2. **Kelemahan Inheren Rotasi Alfabet Monoalfabetik (ROT13 / Caesar Cipher):**
   String tersandi milik pengguna `cultiris` adalah `npnqrzl{P7e1S_54I35_71Z3}`. Karakter prefiks `npnqrzl` secara langsung mencerminkan kata pembungkus token `academy`:
   - `n` (posisi 13) bergeser 13 langkah modulo 26 menjadi `a` (posisi 0).
   - `p` (posisi 15) bergeser 13 langkah modulo 26 menjadi `c` (posisi 2).
   - `q` (posisi 16) bergeser 13 langkah modulo 26 menjadi `d` (posisi 3).
   Algoritma ROT13 adalah involusi ($E(E(x)) = x$), di mana proses enkripsi dan dekripsi menggunakan operasi yang identik tanpa memerlukan kunci rahasia (*zero key entropy*). Ruang pencarian kunci berukuran paling banyak 26 pergeseran, menjadikannya rentan terhadap *brute-force* instan dalam kompleksitas waktu $O(1)$.
3. **Ancaman Credential Stuffing & Password Reuse (OWASP OAT-008):**
   Insiden kebocoran berkas basis data kredensial mentah memberikan amunisi bagi aktor ancaman untuk melakukan serangan *credential stuffing*. Serangan ini menguji pasangan username/password yang bocor ke ribuan layanan publik lain secara otomatis guna mengeksploitasi kebiasaan buruk pengguna yang menggunakan kata sandi identik di berbagai platform (*password reuse*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Inspeksi dan Ekstraksi Arsip Data:**
   Arsip `leak.tar` diunduh dan diekstraksi ke direktori kerja:
   ```bash
   tar -xvf leak.tar
   ```
   Dua berkas dihasilkan: `leak/usernames.txt` dan `leak/passwords.txt`.
2. **Korelasi Indeks Akun Target `cultiris`:**
   Mencari nomor baris untuk entri `cultiris` pada berkas nama pengguna:
   ```bash
   grep -n "^cultiris$" leak/usernames.txt
   ```
   Hasil menunjukkan target berada tepat pada baris ke-378.
3. **Ekstraksi String Sandi Tersandi:**
   Mengekstrak baris ke-378 dari berkas kata sandi:
   ```bash
   sed -n '378p' leak/passwords.txt
   # Output: npnqrzl{P7e1S_54I35_71Z3}
   ```
4. **Kriptoanalisis dan Dekripsi ROT13:**
   Melakukan pergeseran rotasi 13 langkah pada alfabet ASCII huruf besar dan kecil:
   - `npnqrzl` -> `academy`
   - `P7e1S_54I35_71Z3` -> `C7r1F_54V35_71M3`
   Teks terang lengkap hasil dekripsi adalah `academy{C7r1F_54V35_71M3}`.
5. **Verifikasi Live Submisi:**
   Submisi token ke REST API CyLab (`POST /api/submissions/`) menghasilkan kode status HTTP 201 Created dengan atribut `{"correct": true}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{C7r1F_54V35_71M3}`
- **Native PicoCTF Format:** `picoCTF{C7r1F_54V35_71M3}`
- **Status Solver:** Terverifikasi 100% via REST API CyLab (`POST /api/submissions/` -> HTTP 201 `correct: true`) dan skrip solver mandiri `scripts/solve_261_credstuff.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Penerapan Standar Hashing Password Modern (NIST SP 800-63B § 5.1.1 & OWASP Password Storage CS):**
   Jangan pernah menyimpan kata sandi menggunakan enkripsi simetris reversibel, apalagi cipher substitusi klasik. Wajib gunakan fungsi derivasi kunci memori-keras (*memory-hard key derivation functions*) seperti:
   - **Argon2id:** Algoritma rekomendasi standar internasional (RFC 9106) dengan parameter memori minimal 64 MB, iterasi $t=3$, dan parallelism $p=4$.
   - **Bcrypt:** Alternatif teruji dengan cost factor minimal 12 ($2^{12} = 4096$ putaran).
   - Selalu sertakan *cryptographically secure random salt* unik minimal 128 bita untuk setiap pengguna guna mematahkan serangan *precomputed rainbow tables*.
2. **Mitigasi Serangan Credential Stuffing (Defensif LKS):**
   - **Multi-Factor Authentication (MFA):** Terapkan MFA berbasis WebAuthn / FIDO2 atau TOTP (RFC 6238) agar kredensial statis yang bocor tidak cukup untuk mengotentikasi sesi.
   - **Breached Credential Detection:** Integrasikan pemeriksaan API kebocoran kredensial (seperti *Have I Been Pwned Pwned Passwords* dengan k-anonymity SHA-1) pada saat pendaftaran atau penggantian sandi.
   - **Rate Limiting & Behavioral Biometrics:** Terapkan pembatasan frekuensi login per IP/subnet dan captcha adaptif saat terdeteksi pola lonjakan kegagalan otentikasi.
