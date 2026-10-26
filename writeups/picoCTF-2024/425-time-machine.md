# Writeup: Time Machine (Challenge ID: 425)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Git Log Analysis
- **Difficulty:** Easy
- **Author:** Jeffery John
- **Event:** picoCTF 2024
- **Points:** 50
- **Flag:** `academy{t1m3m@ch1n3_aaac4598}`

---

## Problem Statement & Scope
Diberikan arsip `challenge.zip` yang berisi repositori lokal Git (`drop-in/`). Pengguna lupa apa yang terakhir kali dikerjakan dan meninggalkan pesan pengingat di dalam histori version control.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Immutability Objek Git:** Git menyimpan setiap perubahan dalam bentuk graf asiklik terarah (DAG) dari objek commit kriptografis terkompresi zlib (SHA-1/SHA-256).
2. **Kelemahan Operasional Pesan Commit (Commit Message Leakage):** Developer sering kali secara tidak sadar memasukkan informasi rahasia, token akses sementara, atau flag ke dalam pesan commit (`git commit -m "<secret>"`). Meskipun isi berkas diubah di kemudian hari, seluruh histori metadata commit tetap tersimpan di dalam direktori `.git/` selama repositori tidak dipangkas (*pruned/rebased*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Ekstraksi arsip dan masuk ke direktori repositori:
   ```bash
   unzip challenge.zip && cd drop-in
   ```
2. Periksa histori commit menggunakan perintah `git log`:
   ```bash
   git log -n 1
   ```
3. Commit teratas langsung memperlihatkan token flag pada subjek pesan commit:
   ```text
   commit f3c285602815d5ef4a3109eb055ef5efa41bc6be
   Author: academy <ops@cylabacademy.org>
   Date:   Wed Sep 23 05:12:25 2026 +0000

       academy{t1m3m@ch1n3_aaac4598}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{t1m3m@ch1n3_aaac4598}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Audit Secret Scanning pada Pipeline CI/CD:** Implementasikan pre-commit hooks (seperti `trufflehog`, `gitleaks`) untuk memblokir commit yang memuat string sensitif atau token sebelum mendarat di repositori git bersama.
- **Pembersihan Histori Sensitif:** Jika secret terlanjur ter-commit, gunakan utilitas `git-filter-repo` atau BFG Repo-Cleaner untuk menghapus objek dari histori, kemudian cabut dan rotasi kredensial yang terpapar seketika.
