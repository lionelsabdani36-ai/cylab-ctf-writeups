# Writeup: runme.py (Challenge ID: 250)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Python Execution
- **Difficulty:** Easy
- **Author:** Sujeet Kumar
- **Event:** Beginner picoMini 2022
- **Points:** 5
- **Flag:** `academy{run_s4n1ty_run}`

---

## Problem Statement & Scope
Diberikan sebuah skrip Python sederhana `runme.py`. Peserta diminta mengeksekusi skrip di lingkungan terminal untuk mencetak flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Hardcoded Secrets dalam Kode Sumber:** Menaruh nilai rahasia secara eksplisit dalam kode program (hardcoded constants) membuat rahasia tersebut dapat langsung dibaca oleh siapa pun yang memiliki akses ke berkas skrip tanpa perlu menjalankan otentikasi.
2. **Eksekusi Interpreter Python:** Python adalah bahasa interpreted; baris perintah dieksekusi langsung oleh runtime tanpa langkah kompilasi biner yang rumit.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh berkas `runme.py`:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/e4f0c4525ade26a755d6b5c3ce5b220a10c295879c2c3b75385e3a6c9e1ae697/runme.py
   ```
2. Jalankan skrip atau periksa isinya:
   ```bash
   python3 runme.py
   # Output: academy{run_s4n1ty_run}
   ```
3. Alternatif inspeksi statis:
   ```bash
   grep -o "academy{[^}]*}" runme.py
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{run_s4n1ty_run}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Larangan Hardcoded Credentials:** Data sensitif tidak boleh ditulis langsung di kode program. Gunakan Environment Variables (`os.environ`) atau Secrets Manager (HashiCorp Vault, AWS Secrets Manager) yang diakses saat runtime melalui identitas terotentikasi.
