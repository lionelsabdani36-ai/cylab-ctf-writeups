# Writeup: Trust But Verify (Challenge ID: 783)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / AI Safety & Governance (NIST SP 800-115 §4.2 / NIST AI RMF 1.0)
- **Difficulty:** Easy (1)
- **Points:** 1
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Flag (Resmi CyLab):** `academy{7ru57_15_34rn3d_65d5434b}`
- **Flag Komunitas:** `CTF{7ru57_15_34rn3d_65d5434b}`

---

## Problem Statement & Scope

Tantangan menguji kebiasaan kritis dan tata kelola keamanan dalam alur kerja berbasis *Generative AI / Large Language Models* (LLM):
> *"Play through an AI ethics interactive fiction where confident AI outputs can be wrong, subtly wrong, or almost-right. Verify claims, code, and citations to learn practical habits for safe AI-assisted work."*

Lingkungan tantangan menyajikan antarmuka fiksi interaktif berbasis terminal (socket TCP netcat) yang mensimulasikan interaksi antara seorang analis (*Ren*) dan asisten AI (*ARIA*) dalam penyusunan proposal penelitian ilmiah. Selama interaksi, peserta dihadapkan pada 3 titik keputusan kritis:
1. **Verifikasi Klaim Statistik:** Membedakan antara data empiris valid dan angka dramatis hasil halusinasi model.
2. **Audit Kode Otomatis (*Silent Code Defect*):** Mengidentifikasi penyisipan logika komputasi cacat tersembunyi yang tetap valid secara sintaksis.
3. **Validasi Sitasi Ilmiah:** Memverifikasi integritas bibliografi primer untuk mencegah fabrikasi akademis dan distorsi metadata.

Peserta dituntut mengambil jalur verifikasi independen yang sesuai dengan panduan NIST AI Risk Management Framework (AI RMF 1.0) untuk menyelesaikan skenario dan memperoleh token verifikasi resmi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Mekanisme Halusinasi & Sycophancy pada Model Bahasa (LLM):**
   Model bahasa probabilistik (*autoregressive transformers*) mengoptimalkan fungsi probabilitas kata berikutnya $P(w_t \mid w_{<t})$ berdasarkan distribusi token korpus pelatihan. Model tidak memiliki *grounded world knowledge* atau basis data kebenaran ontologis inheren. Akibatnya:
   - Model sering menghasilkan klaim faktual fiktif dengan tingkat kepercayaan retoris yang sangat tinggi (*fluent hallucination*).
   - Fenomena *sycophancy* mendorong model untuk mengonfirmasi bias pengguna daripada menyajikan kebenaran faktual.

2. **Ancaman Injeksi Cacat Tersembunyi (*Silent Logic Errors* & CWE-684):**
   Kode yang dihasilkan AI sering kali lolos kompilasi dan linting sintaks standar, namun memuat anomali kalkulasi halus (seperti penambahan offset arbitrer `+ 1` pada fungsi rata-rata). Dalam pipa CI/CD dan sistem kritis, menerima kode buatan AI tanpa inspeksi manusia (*human-in-the-loop audit*) menciptakan celah integritas data yang sulit dideteksi oleh pemindai statis biasa.

3. **Integritas Rantai Pasok Pengetahuan (*Knowledge Supply Chain Integrity*):**
   Mengutip publikasi ilmiah fiktif atau mengubah metadata dokumen primer (seperti tahun terbit atau ruang lingkup metodologi) merusak akurasi pengambilan keputusan strategis dalam tim investigasi keamanan siber dan analisis intelijen ancaman (*Threat Intelligence*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Skenario 1 — The Statistic (Audit Halusinasi Statistik):**
   - Asisten AI menyajikan klaim statistik dramatis: *"Over 500 million metric tons of plastic enter the world's oceans annually (2022 UNEP report)"*.
   - Evaluasi Keputusan: Penyerang/pengguna cerdas tidak menerima angka tersebut begitu saja. Memilih opsi `b` (*Demand specific source link/document*).
   - Respons Sistem: AI mengakui ketidakmampuannya menyediakan tautan resmi dan mengakui terjadinya halusinasi angka.

2. **Skenario 2 — The Code (Audit Logika Kode Python):**
   - AI menghasilkan skrip kalkulasi rata-rata volume:
     ```python
     average = sum(data) / len(years) + 1
     ```
   - Evaluasi Keputusan: Menolak langsung menjalankan kode. Memilih opsi `b` (*Inspect code logic prior to execution*).
   - Deteksi Defek: Teridentifikasi penambahan bias arbitrer `+ 1` yang mendistorsi hasil analisis numerik tanpa memicu *runtime error*.

3. **Skenario 3 — The Citation (Verifikasi Sumber Primer):**
   - AI mengutip penelitian nyata Dr. Heather Leslie terkait mikroplastik dalam darah manusia.
   - Evaluasi Keputusan: Memilih opsi `b` (*Cross-reference primary publication independently*).
   - Temuan: Peneliti dan topik benar, namun tahun publikasi keliru (2022, bukan 2021) dan status temuan merupakan studi rintisan awal (*preliminary investigation*).

4. **Eksekusi Otomasi & Penerimaan Token:**
   Seluruh gerbang tata kelola berhasil dipenuhi melalui skrip otomasi `scripts/solve_783_trust_but_verify.py`, menghasilkan token flag resmi.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{7ru57_15_34rn3d_65d5434b}`
- **Format Flag Komunitas:** `CTF{7ru57_15_34rn3d_65d5434b}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 783, "flag": "academy{7ru57_15_34rn3d_65d5434b}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Penerapan Prinsip "Human-in-the-Loop" (HITL):**
   Dalam kurikulum LKS Cyber Security, siswa wajib menguasai prinsip bahwa output AI tidak boleh diperlakukan sebagai otoritas final. Setiap kode sumber, konfigurasi aturan keamanan (seperti snort/suricata rules atau yara rules), dan klaim intelijen wajib melewati inspeksi teknis manusia sebelum diterapkan ke lingkungan produksi.
2. **Pengujian Berbasis Kasus Uji Ekstrem (*Adversarial & Boundary Testing*):**
   Untuk mendeteksi *silent logic errors* pada skrip yang dihasilkan AI, organisasi wajib menerapkan *automated unit testing* dengan cakupan nilai batas (*boundary value analysis*) dan *differential testing* terhadap implementasi referensi yang telah terverifikasi.
3. **Kepatuhan Terhadap Kerangka Kerja NIST AI RMF 1.0 (GOVERN & MAP):**
   Organisasi harus menegakkan kebijakan pelarangan penggunaan output AI tanpa audit sumber primer, mengimplementasikan mekanisme *provenance tracking* untuk memastikan setiap artefak memiliki rantai audit (*audit trail*) yang dapat diverifikasi.
