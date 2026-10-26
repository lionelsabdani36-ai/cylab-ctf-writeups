# Writeup: Riddle Registry (Challenge ID: 530)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / PDF Metadata
- **Difficulty:** Easy
- **Author:** Prince Niyonshuti N.
- **Event:** picoMini by CMU-Africa
- **Points:** 50
- **Flag:** `academy{puzzl3d_m3tadata_f0und!_2d947385}`

---

## Deskripsi Tantangan
> Hi, intrepid investigator! 📄🔍 You've stumbled upon a peculiar PDF filled with what seems like nothing more than garbled nonsense. But beware! Not everything is as it appears. Amidst the chaos lies a hidden treasure—an elusive flag waiting to be uncovered.
> Find the PDF file here `confidential.pdf` and uncover the flag within the metadata.
> Hints:
> 1. Don't be fooled by the visible text; it’s just a decoy!
> 2. Look beyond the surface for hidden clues

---

## Analisis Kerentanan & Konsep Teknis
Struktur dokumen PDF menyimpan metadata dokumen dalam kamus `/Info` atau metadata XML XMP. Kamus ini mencakup atribut seperti `/Title`, `/Author`, `/Subject`, `/Keywords`, `/Creator`, dan `/Producer`.

Dalam investigasi forensik dokumen digital, metadata sering kali tidak terlihat saat dokumen dibuka melalui penampil PDF standar (PDF viewer), namun dapat diekstrak menggunakan alat inspeksi biner atau parser PDF.

Pada tantangan ini:
1. Bidang `/Author` pada kamus informasi PDF berisi string terenkode Base64:
   ```text
   /Author (YWNhZGVteXtwdXp6bDNkX20zdGFkYXRhX2YwdW5kIV8yZDk0NzM4NX0\075)
   ```
2. Karakter escape `\075` adalah representasi oktal dari karakter ASCII `=` (`0x3D`).
3. String Base64 lengkap adalah:
   `YWNhZGVteXtwdXp6bDNkX20zdGFkYXRhX2YwdW5kIV8yZDk0NzM4NX0=`

---

## Tahapan Eksploitasi & Solusi
1. Ekstraksi metadata PDF menggunakan regex biner atau perintah `strings`:
   ```bash
   python3 -c '
   import re, base64
   with open("confidential.pdf", "rb") as f:
       data = f.read()
   m = re.search(rb"/Author\s*\(([^)]+)\)", data)
   raw = m.group(1).decode("latin1").replace("\\075", "=")
   print(base64.b64decode(raw).decode("utf-8"))
   '
   ```
2. Output yang dihasilkan langsung mengembalikan token flag resmi:
   ```text
   academy{puzzl3d_m3tadata_f0und!_2d947385}
   ```

---

## Pembelajaran Defensif & Mitigasi LKS
- **Pembersihan Metadata (Metadata Scrubbing):** Sebelum mempublikasikan dokumen resmi atau rahasia ke publik atau jaringan tidak terpercaya, organisasi wajib menjalankan prosedur sanitasi metadata (menggunakan alat seperti `exiftool -all= file.pdf` atau PDF Redaction Tools).
- **Audit Informasi Tersembunyi:** Sistem DLP (Data Loss Prevention) di perimeter jaringan harus memeriksa kamus internal berkas dokumen untuk mencegah kebocoran data terenkode (data exfiltration via PDF metadata).
