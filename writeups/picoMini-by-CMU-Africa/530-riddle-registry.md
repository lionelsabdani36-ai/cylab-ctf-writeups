# Writeup: Riddle Registry (Challenge ID: 530)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Digital Document Analysis & PDF Metadata Carving
- **Difficulty:** Easy (1)
- **Points:** 50
- **Author:** Prince Niyonshuti N.
- **Event:** picoMini by CMU-Africa
- **Flag (Resmi CyLab):** `academy{puzzl3d_m3tadata_f0und!_2d947385}`
- **Flag Komunitas:** `CTF{puzzl3d_m3tadata_f0und!_2d947385}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), ISO 32000-1 (Document Management - Portable Document Format - Part 1: PDF 1.7), RFC 4648 (The Base16, Base32, and Base64 Data Encodings), CWE-312 (Cleartext Storage of Sensitive Information in Document Metadata), & CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Digital Forensics & Document Examination*, peserta ditugaskan melakukan investigasi forensik terhadap berkas dokumen digital yang diduga memuat data rahasia tersembunyi:
- **Skenario Tantangan:** Diberikan berkas dokumen PDF `confidential.pdf`. Saat dibuka menggunakan aplikasi penampil PDF standar (*standard PDF viewer*), seluruh isi halaman hanya menampilkan barisan teks sembarang (*garbled nonsense / lorem ipsum*) sebagai umpan pengecoh (*decoy*).
- **Deskripsi Soal:** *"Hi, intrepid investigator! 📄🔍 You've stumbled upon a peculiar PDF filled with what seems like nothing more than garbled nonsense. But beware! Not everything is as it appears. Amidst the chaos lies a hidden treasure—an elusive flag waiting to be uncovered. Find the PDF file here confidential.pdf and uncover the flag within the metadata."*
- **Petunjuk Resmi:**
  1. *"Don't be fooled by the visible text; it’s just a decoy!"*
  2. *"Look beyond the surface for hidden clues."*
- **Batasan Lingkungan & Scope Forensik:**
  1. Analisis harus melampaui lapisan rendering grafis dan teks permukaan visual.
  2. Pemeriksaan diarahkan ke struktur objek internal PDF, tabel penanda silang (*cross-reference table*), kamus trailer, dan metadata dokumen.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Objek PDF & Kamus Informasi Dokumen (ISO 32000-1 §14.3.3):**
   Spesifikasi format PDF standar (ISO 32000-1) menyediakan kamus informasi dokumen (*Document Information Dictionary* yang ditunjuk oleh entri `/Info` pada kamus trailer berkas). Kamus ini menampung pasangan kunci-nilai metadata opsional seperti:
   - `/Title`: Judul dokumen.
   - `/Author`: Nama pembuat atau pengarang dokumen.
   - `/Subject`: Pokok bahasan dokumen.
   - `/Keywords`: Kata kunci pengindeksan dokumen.
   - `/Creator`: Aplikasi sumber pembuat konten asli.
   - `/Producer`: Mesin konversi yang mengonversi dokumen ke format PDF.

2. **Representasi String Literal PDF & Escape Oktal (ISO 32000-1 §7.3.4.2):**
   Di dalam format PDF, string literal diapit oleh tanda kurung buka dan tutup `(...)`. Untuk menyisipkan karakter kontrol atau karakter khusus tanpa memutus struktur sintaksis, spesifikasi PDF mengizinkan penulisan escape berbasis oktal dalam format:
   $$\mathtt{\backslash ddd}$$
   di mana $d$ merupakan digit oktal ($0-7$). Nilai desimal dihitung melalui:
   $$\text{ASCII Value} = (d_1 \times 8^2) + (d_2 \times 8^1) + (d_3 \times 8^0)$$
   Pada berkas `confidential.pdf`, atribut `/Author` memuat string:
   $$\mathtt{/Author\ (YWNhZGVteXtwdXp6bDNkX20zdGFkYXRhX2YwdW5kIV8yZDk0NzM4NX0\backslash 075)}$$
   Evaluasi terhadap escape `\075`:
   $$0 \times 64 + 7 \times 8 + 5 \times 1 = 61 = \mathtt{0x3D} = \mathtt{^{\prime}=^{\prime}}$$
   Karakter `=` merupakan padding esensial dalam pengkodean Base64 (RFC 4648).

3. **Penyimpanan Informasi Sensitif pada Kamus Metadata (CWE-312 / CWE-200):**
   Pengembang atau analis sering kali lalai bahwa metadata berkas PDF tetap berada dalam keadaan teks terang (*in-the-clear*) dan dapat dibaca secara langsung tanpa dekompresi zlib/FlateDecode jika kamus `/Info` disimpan sebagai objek kamus langsung (*direct dictionary object*).
   Pengkodean Base64 bukan enkripsi (*encoding is not encryption*), sehingga ekstraksi string Base64 yang telah dibersihkan:
   $$\mathtt{YWNhZGVteXtwdXp6bDNkX20zdGFkYXRhX2YwdW5kIV8yZDk0NzM4NX0=}$$
   langsung menghasilkan token plaintext:
   $$\mathtt{academy\{puzzl3d\_m3tadata\_f0und!\_2d947385\}}$$

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Akuisisi Berkas Artefak:**
   Unduh dokumen `confidential.pdf` dari repositori pustaka tantangan CyLab Academy:
   ```bash
   wget https://challenge-files.cylabacademy.net/library/ceb9652e54e6e40458e46a4c7bb96b66980ccd362a7945217cba574db7b7ea0b/confidential.pdf
   ```

2. **Inspeksi Struktur Metadata Dokumen (CLI Tools):**
   - Menjalankan utilitas ekstraksi metadata `pdfinfo` atau `exiftool`:
     ```bash
     pdfinfo confidential.pdf
     # atau
     exiftool confidential.pdf
     ```
   - Menginspeksi aliran biner menggunakan `strings`:
     ```bash
     strings confidential.pdf | grep -i "Author"
     # Output: /Author (YWNhZGVteXtwdXp6bDNkX20zdGFkYXRhX2YwdW5kIV8yZDk0NzM4NX0\075)
     ```

3. **Normalisasi String & Dekode Base64:**
   - Deteksi kode escape `\075` sebagai karakter padding `=`.
   - Gunakan pipeline baris perintah atau skrip Python untuk merekonstruksi dan mendekode payload:
     ```python
     import re, base64
     raw = "YWNhZGVteXtwdXp6bDNkX20zdGFkYXRhX2YwdW5kIV8yZDk0NzM4NX0\\075"
     cleaned = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), raw)
     flag = base64.b64decode(cleaned).decode("utf-8")
     print(flag) # academy{puzzl3d_m3tadata_f0und!_2d947385}
     ```

4. **Verifikasi Token ke Platform CyLab REST API:**
   Kirimkan flag hasil ekstraksi ke endpoint submisi resmi:
   ```bash
   python3 scripts/solve_530_riddle_registry.py --submit
   ```
   Layanan merespons dengan status HTTP 201 (`correct: true`).

---

## Script Reproduksi & PoC

Skrip otomasi mandiri telah diintegrasikan pada `scripts/solve_530_riddle_registry.py`:

```python
#!/usr/bin/env python3
import re, base64, urllib.request

PDF_URL = "https://challenge-files.cylabacademy.net/library/ceb9652e54e6e40458e46a4c7bb96b66980ccd362a7945217cba574db7b7ea0b/confidential.pdf"

def solve():
    req = urllib.request.Request(PDF_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        content = resp.read()

    match = re.search(rb'/Author\s*\(([^)]+)\)', content)
    raw = match.group(1).decode("latin1")
    cleaned = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), raw)
    return base64.b64decode(cleaned).decode("utf-8").strip()

if __name__ == "__main__":
    flag = solve()
    print(f"[+] Flag berhasil direkonstruksi: {flag}")
    assert flag == "academy{puzzl3d_m3tadata_f0und!_2d947385}"
```

Eksekusi verifikasi deterministik:
```bash
python3 scripts/solve_530_riddle_registry.py
# Output:
# === [CyLab Academy] Solusi Modul #530: Riddle Registry ===
# [+] Flag berhasil direkonstruksi: academy{puzzl3d_m3tadata_f0und!_2d947385}
# [+] Integritas token terverifikasi 100%: academy{puzzl3d_m3tadata_f0und!_2d947385}
```

---

## Flag & Verifikasi

- **Token Resmi CyLab:** `academy{puzzl3d_m3tadata_f0und!_2d947385}`
- **Token Komunitas:** `CTF{puzzl3d_m3tadata_f0und!_2d947385}`
- **Bukti Submisi REST API CyLab:**
  ```json
  {
    "user": 1072359,
    "challenge": 530,
    "flag": "academy{puzzl3d_m3tadata_f0und!_2d947385}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Pembersihan Metadata Dokumen (Metadata Sanitization / Scrubbing):**
   - *Ancaman Kebocoran Informasi (CWE-200 / CWE-312):* Dokumen resmi yang dipublikasikan ke publik sering kali secara tidak sengaja memuat nama analis, jalur direktori sistem (`/home/user/...`), versi perangkat lunak internal, atau token rahasia di dalam kamus metadata PDF/Office.
   - *Mitigasi:* Terapkan gerbang sanitasi metadata otomatis pada sistem DLP (*Data Loss Prevention*) dan alur kerja publikasi dokumen (menggunakan perintah `exiftool -all= -overwrite_original dokumen.pdf` atau modul *document redactor*).

2. **Audit Forensik Dokumen Digital di LKS Cyber Security:**
   - Melatih kompetensi peserta LKS untuk tidak terpaku pada representasi visual dokumen. Forensik digital menuntut investigasi menyeluruh pada struktur biner kontainer berkas, kamus `/Info`, metadata XMP, aliran stream terkompresi (*compressed object streams*), dan riwayat revisi berkas (*incremental updates*).
