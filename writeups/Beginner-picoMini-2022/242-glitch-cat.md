# Writeup: Glitch Cat (Challenge ID: 242)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Python ASCII Expression Evaluation
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** Beginner picoMini 2022
- **Points:** 30
- **Flag:** `academy{gl17ch_m3_n07_3881dce3}`

---

## Problem Statement & Scope
Layanan pencetak flag pada endpoint TCP socket mengalami malfungsi ("glitching") dan mencetak token flag yang terpecah menjadi ekspresi penggabungan string Python dengan pemanggilan fungsi konversi karakter ASCII `chr(hex)`. Peserta diminta mengekstrak dan merekonstruksi string flag lengkap.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Representasi Karakter ASCII & Heksadesimal:** Setiap karakter alfanumerik memiliki representasi nilai numerik berbasis tabel ASCII. Nilai heksadesimal `0x33`, `0x38`, `0x64`, `0x63`, `0x65` berkorespondensi langsung dengan karakter `'3'`, `'8'`, `'d'`, `'c'`, `'e'`.
2. **Evaluasi Ekspresi Bahasa Pemrograman:** Ketika sistem menghasilkan output yang merupakan sintaks sintesis ekspresi bahasa (seperti Python string literal concatenation), penyerang/penguji dapat mengevaluasi ekspresi tersebut baik melalui interpreter interaktif maupun melalui parser regex tanpa menjalankan kode arbitrer (*safe evaluation*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Hubungkan ke layanan TCP menggunakan `nc`:
   ```bash
   nc chatelaine.cylabacademy.net 21308
   ```
2. Layanan mengembalikan respons berikut:
   ```text
   'academy{gl17ch_m3_n07_' + chr(0x33) + chr(0x38) + chr(0x38) + chr(0x31) + chr(0x64) + chr(0x63) + chr(0x65) + chr(0x33) + '}'
   ```
3. Evaluasi kode ASCII secara manual atau dengan Python:
   - `chr(0x33)` = `'3'`
   - `chr(0x38)` = `'8'`
   - `chr(0x38)` = `'8'`
   - `chr(0x31)` = `'1'`
   - `chr(0x64)` = `'d'`
   - `chr(0x63)` = `'c'`
   - `chr(0x65)` = `'e'`
   - `chr(0x33)` = `'3'`
4. Hasil penggabungan:
   $$\text{academy\{gl17ch\_m3\_n07\_3881dce3\}}$$

---

## Flag & Verifikasi
- **Flag:** `academy{gl17ch_m3_n07_3881dce3}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pemahaman Fundamental Encoding:** Keterampilan mengonversi secara cepat antara heksadesimal, desimal, biner, dan karakter ASCII adalah kompetensi dasar wajib dalam kompetisi LKS Cyber Security (kategori Forensics dan General Skills).
- **Hindari Penggunaan `eval()` Sembarangan:** Saat mengurai output yang berformat ekspresi kode, utamakan teknik *parsing deterministik* (seperti `ast.literal_eval` atau regex) daripada `eval()` langsung untuk mencegah eksekusi kode berbahaya (*Remote Code Execution*).
