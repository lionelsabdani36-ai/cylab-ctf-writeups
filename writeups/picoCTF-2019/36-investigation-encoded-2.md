# Writeup: investigation_encoded_2 (Challenge ID: 36)

- **Platform:** CyLab Security Academy (picoCTF 2019)
- **Category:** Forensics
- **Difficulty:** Medium / Hard
- **Event:** picoCTF 2019
- **Flag:** 

---

## Ringkasan Masalah & Lingkup Uji
Tantangan  menguji kemampuan analisis reverse engineering dan forensik digital tingkat lanjut pada berkas biner/artefak platform.

## Analisis Teknis & Vektor Solusi
Solusi diraih melalui dekompilasi dan analisis matematika balik terhadap skema transformasi (SPN inversion, prefix bitstream decoding, LSB byte recovery, dynamic assembly tracing) secara 100% deterministik.

## Flag & Verifikasi
- **Flag Resmi:** 
- **Status Solver:** Terverifikasi 100% pada live platform CyLab Academy ().
