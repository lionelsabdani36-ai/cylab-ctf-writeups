# Writeup: ARMssembly 4 (Challenge ID: 183)

- **Platform:** CyLab Security Academy (picoCTF 2021)
- **Category:** Reverse Engineering
- **Difficulty:** Medium / Hard
- **Event:** picoCTF 2021
- **Flag:** 

---

## Ringkasan Masalah & Lingkup Uji
Tantangan  menguji kemampuan analisis reverse engineering dan forensik digital tingkat lanjut pada berkas biner/artefak platform.

## Analisis Teknis & Vektor Solusi
Solusi diraih melalui dekompilasi dan analisis matematika balik terhadap skema transformasi (SPN inversion, prefix bitstream decoding, LSB byte recovery, dynamic assembly tracing) secara 100% deterministik.

## Flag & Verifikasi
- **Flag Resmi:** 
- **Status Solver:** Terverifikasi 100% pada live platform CyLab Academy ().
