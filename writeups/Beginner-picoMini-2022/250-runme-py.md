# Writeup: runme.py (Challenge ID: 250)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Python Execution & Static Source Analysis
- **Difficulty:** Easy (diff=1)
- **Author:** Sujeet Kumar
- **Event:** Beginner picoMini 2022
- **Points:** 5
- **Flag:** `academy{run_s4n1ty_run}`

---

## Problem Statement & Scope

Diberikan sebuah skrip Python bernama `runme.py` yang dapat diunduh melalui tautan CDN CyLab Academy atau diunduh langsung di webshell menggunakan utilitas `wget`. Skenario tantangan menginstruksikan peserta untuk mengeksekusi skrip Python tersebut di lingkungan CLI terminal guna memperoleh bendera resmi pembelajaran.

Tantangan ini bertujuan menguji pemahaman dasar peserta mengenai pengoperasian lingkungan baris perintah Linux (CLI), eksekusi interpreter skrip Python, serta inspeksi kode sumber statis untuk mendeteksi data sensitif yang tidak terlindungi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Penyematan Kredensial Langsung dalam Kode Sumber (CWE-798 / Hardcoded Credentials):**
   - Skrip `runme.py` mendefinisikan variabel bendera secara gamblang pada lingkup modul:
     ```python
     flag = 'academy{run_s4n1ty_run}'
     print(flag)
     ```
   - Ketiadaan kontrol akses, enkripsi, obfuskasi, atau mekanisme penyimpanan kredensial eksternal menyebabkan rahasia ini dapat diakses secara instan oleh siapa pun yang membaca berkas kode sumber.

2. **Karakteristik Interpreter Python & Kemudahan Inspeksi Statis (NIST SP 800-115 § 4.2):**
   - Sesuai panduan NIST SP 800-115 Bagian 4.2 mengenai *Review Techniques and Source Code Analysis*, berkas berbasis skrip (*interpreted languages*) tidak mengalami transformasi biner kompleks yang menyamarkan konstanta teks.
   - Konstanta literal string disimpan sebagai objek bytecode langsung (`LOAD_CONST`) dan teks terang (*plaintext*) dalam berkas teks, memungkinkan ekstraksi menggunakan *regular expression*, analisis *Abstract Syntax Tree* (AST), maupun eksekusi langsung melalui runtime interpreter `python3`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Unduh berkas skrip `runme.py` dari repositori pustaka CyLab:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/e4f0c4525ade26a755d6b5c3ce5b220a10c295879c2c3b75385e3a6c9e1ae697/runme.py
   ```
2. Metode 1: Eksekusi langsung melalui runtime Python:
   ```bash
   python3 runme.py
   ```
   Output konsol:
   ```text
   academy{run_s4n1ty_run}
   ```
3. Metode 2: Ekstraksi statis menggunakan pencarian pola teks regex di terminal:
   ```bash
   grep -o "academy{[^}]*}" runme.py
   ```
4. Metode 3: Analisis sintaks terstruktur menggunakan Abstract Syntax Tree (AST) Python:
   ```python
   import ast

   with open("runme.py", "r") as f:
       tree = ast.parse(f.read())

   for node in ast.walk(tree):
       if isinstance(node, ast.Assign):
           for target in node.targets:
               if isinstance(target, ast.Name) and target.id == "flag":
                   print("[+] Flag diekstrak via AST:", node.value.value)
   ```
5. Eksekusi skrip reproduksi mandiri `scripts/solve_250_runme.py` untuk validasi otomatis menyeluruh.

---

## Flag & Verifikasi

- **Flag:** `academy{run_s4n1ty_run}`
- **Bukti Validasi REST API:**
  Endpoint `POST /api/submissions/` merespons dengan status verifikasi valid:
  ```json
  {"challenge": 250, "flag": "academy{run_s4n1ty_run}", "correct": true}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Kompetensi LKS Cyber Security:**
  - Kemampuan dasar penanganan lingkungan CLI Linux dan automasi eksekusi skrip (*Scripting and Environment Management*).
  - Menerapkan teknik audit kode statis (*Static Application Security Testing / SAST*) untuk mengidentifikasi keberadaan token atau kredensial yang disematkan secara tidak aman (*hardcoded secrets*) pada artefak aplikasi.
- **Mitigasi Defensif:**
  - **Pemisahan Kredensial dari Basis Kode (CWE-798 Remediation):** Jangan pernah menyimpan kunci API, token otentikasi, atau informasi rahasia di dalam repositori kode sumber (*version control*).
  - **Penggunaan Secrets Management:** Terapkan pemuatan konfigurasi sensitif dari variabel lingkungan (*Environment Variables*) atau sistem manajemen rahasia terpusat (seperti HashiCorp Vault, AWS Secrets Manager, atau Azure Key Vault) saat runtime.
  - **Pre-commit Secret Scanning:** Integrasikan perkakas pemindai rahasia otomatis (seperti Trufflehog atau Gitleaks) ke dalam *pipeline* CI/CD untuk mencegah kebocoran kredensial ke repositori publik.
