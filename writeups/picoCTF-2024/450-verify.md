# Writeup: Verify (Challenge ID: 450)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Cryptographic Hash Verification & File Integrity
- **Difficulty:** Easy
- **Author:** Jeffery John
- **Event:** picoCTF 2024
- **Points:** 50
- **Flag:** `academy{trust_but_verify_a1859a21}`

---

## Problem Statement & Scope
Disediakan sebuah instance container yang di dalamnya terdapat direktori `files/` berisi puluhan berkas acak yang meniru token flag (*decoy flags*). Pengguna diberikan nilai hash SHA-256 autentik (`f6f0ad659940b7235f39f88d3168a6586645fb8f59a95b7f497c5c55a68f59af`) serta skrip dekripsi `decrypt.sh`. Peserta diminta mencari berkas yang sah berdasarkan kecocokan checksum dan mendekripsinya untuk memperoleh flag asli.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Integritas Data Menggunakan SHA-256 (Secure Hash Algorithm):**
   Fungsi hash kriptografis SHA-256 memetakan input data sembarang menjadi nilai digest 256-bit (64 karakter heksadesimal). Sifat krusial fungsi hash meliputi:
   - **Pre-image Resistance:** Sangat sulit menemukan input $M$ jika hanya diketahui nilai hash $H(M)$.
   - **Collision Resistance:** Sangat sulit menemukan dua input berbeda $M_1 \neq M_2$ yang menghasilkan $H(M_1) = H(M_2)$.
   - **Avalanche Effect:** Perubahan satu bit pada file input akan menghasilkan nilai digest yang berubah total secara acak.
2. **Identifikasi Berkas Sah (Whitelisting via Hash):** Dalam investigasi forensik digital dan deteksi malware, pencocokan hash adalah standar emas untuk memverifikasi keaslian bukti dan membedakan berkas bersih (*known good*) dari berkas berbahaya (*known bad*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Sambungkan ke instance SSH:
   ```bash
   ssh -p 39150 ctf-player@xebec.cylabacademy.net
   # Password: <PASSWORD>
   ```
2. Pindah ke direktori `drop-in/`:
   ```bash
   cd drop-in
   ls -la
   # Berkas: checksum.txt, decrypt.sh, files/
   ```
3. Hitung hash SHA-256 dari seluruh berkas di folder `files/` dan saring menggunakan hash target:
   ```bash
   sha256sum files/* | grep "f6f0ad659940b7235f39f88d3168a6586645fb8f59a95b7f497c5c55a68f59af"
   # Output:
   # f6f0ad659940b7235f39f88d3168a6586645fb8f59a95b7f497c5c55a68f59af  files/a1859a21
   ```
4. Dekripsi berkas sah yang telah diverifikasi:
   ```bash
   ./decrypt.sh files/a1859a21
   # Output: academy{trust_but_verify_a1859a21}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{trust_but_verify_a1859a21}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pentingnya Verifikasi Checksum pada Distribusi Perangkat Lunak:** Selalu sediakan dan verifikasi checksum SHA-256 atau tanda tangan PGP/GPG sebelum mengeksekusi biner atau paket instalasi dari internet untuk mencegah serangan *Man-in-the-Middle* (MitM) atau *supply chain compromise*.
- **Otomasi File Integrity Monitoring (FIM):** Dalam pertahanan infrastruktur (LKS Sysadmin / SOC Module), terapkan alat pemantau integritas berkas (seperti Wazuh, Tripwire, atau AIDE) untuk mendeteksi secara instan setiap modifikasi tidak sah pada berkas sistem kritis.
