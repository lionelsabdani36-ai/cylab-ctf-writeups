# Writeup: Unminify (Challenge ID: 426)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Code De-obfuscation
- **Difficulty:** Easy
- **Author:** Jeffery John
- **Event:** picoCTF 2024
- **Points:** 100
- **Flag:** `academy{pr3tty_c0d3_c7ba568b}`

---

## Problem Statement & Scope
Pengembang web menerapkan kompresi / minifikasi terhadap kode HTML, CSS, dan JavaScript halaman web untuk mempercepat waktu pemuatan halaman (*page load performance*). Peserta ditugaskan untuk menganalisis dokumen yang telah diminifikasi dan menemukan token rahasia yang tersembunyi.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Minifikasi Bukan Enkripsi:** Minifikasi (*code minification*) adalah proses penghapusan spasi, indentasi, baris baru, dan pemendekan identifier variabel tanpa mengubah struktur atau semantik logika program. Minifikasi hanya bertujuan untuk optimalisasi bandwidth jaringan, bukan untuk melindungi kerahasiaan data.
2. **Penyimpanan Nilai Rahasia dalam Atribut DOM:** Token sensitif disematkan sebagai nama kelas CSS (`class="academy{...}"`) pada elemen paragraf `<p>` kosong di dalam berkas HTML.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Ambil kode HTML dari instance web:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:18252/
   ```
2. Analisis output satu baris yang terkompresi. Meskipun tidak memiliki indentasi, pencarian pola regex sederhana mengungkap token flag secara instan:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:18252/ | grep -o "academy{[^}]*}"
   ```
3. Alternatif menggunakan utilitas formatting / beautifier (misal `tidy`, `prettier`, atau parser DOM di Python) menunjukkan elemen HTML berikut:
   ```html
   <p class="academy{pr3tty_c0d3_c7ba568b}"></p>
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{pr3tty_c0d3_c7ba568b}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pembersihan Artefak Produksi (Build Pipeline Hygiene):** Pastikan pipeline CI/CD menerapkan audit dan pembersihan ketat terhadap komentar pengembang, data uji, token staging, dan kelas tersembunyi sebelum berkas dipublikasikan ke server produksi.
- **Audit Kode Statis (SAST):** Terapkan scanner otomatis seperti Semgrep, GitLeaks, atau SonarQube untuk mendeteksi keberadaan pola token rahasia di dalam template HTML dan bundle frontend sebelum rilis.
