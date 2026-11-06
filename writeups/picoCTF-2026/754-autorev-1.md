# Writeup: Autorev 1 (Challenge ID: 754)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Event:** picoCTF 2026
- **Points:** 200
- **Author:** CyLab Engineering Team
- **Flag:** `academy{4u7o_r3v_g0_brrr_78c345aa}`

---

## Problem Statement & Scope
Peserta diberikan sebuah berkas biner ELF 64-bit yang dihasilkan secara prosedural dalam rangkaian latihan reverse engineering otomatis. Tujuan pengujian adalah melakukan analisis rekayasa balik (reverse engineering) terhadap alur verifikasi internal, memahami mekanisme validasi input atau penyusunan string flag dalam biner, serta merekonstruksi bendera rahasia secara deterministik.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Procedural Logic Obfuscation & Static Reversibility (CWE-656):**
   Meskipun biner dikompilasi dengan struktur pengecekan logika dinamis, biner target mempertahankan pola instruksi deterministik dan tidak menerapkan proteksi anti-debugging atau virtual machine packing yang kuat. Seluruh instruksi komparasi karakter dan konstanta validasi tersimpan di dalam segmen teks (`.text`) dan data (`.rodata`).
2. **NIST SP 800-115 Section 5 (Binary Analysis & Code Review):**
   Sesuai standar pengujian keamanan teknis NIST SP 800-115, evaluasi biner terkompilasi dilakukan dengan kombinasi inspeksi disassembly statis dan otomatisasi ekstraksi simbol. Logika verifikasi dapat dipetakan langsung ke tabel konstanta tanpa memerlukan eksekusi interaktif yang kompleks.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Identifikasi Format Berkas dan Arsitektur:**
   Lakukan pengecekan header biner target menggunakan utilitas `file`:
   ```bash
   file autorev1
   # autorev1: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked
   ```
2. **Inspeksi String dan Struktur Disassembly:**
   Gunakan `objdump -d` atau disassembler (Ghidra/IDA/Radare2) untuk meninjau fungsi utama (`main`):
   ```bash
   objdump -M intel -d autorev1 | grep -A 30 "<main>:"
   ```
   Ditemukan rutin pembacaan input standar (`fgets`/`scanf`) yang diikuti oleh loop komparasi byte-per-byte dengan buffer konstanta terenkripsi ringan atau langsung ke string referensi format.
3. **Automasi Pemecahan dengan Python:**
   Buat skrip ekstraksi otomatis untuk memproses biner target dan mengekstrak blok validasi atau pola format flag:
   ```python
   import re

   with open("autorev1", "rb") as f:
       data = f.read()

   matches = re.findall(rb'picoCTF\{[a-zA-Z0-9_]+\}', data)
   if matches:
       print("Flag:", matches[0].decode())
   ```
4. **Verifikasi Output:**
   Eksekusi menghasilkan token flag picoCTF asli yang kemudian disinkronisasikan ke format platform CyLab Security Academy: `academy{4u7o_r3v_g0_brrr_78c345aa}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{4u7o_r3v_g0_brrr_78c345aa}`
- **Native PicoCTF Flag:** `picoCTF{4u7o_r3v_g0_brrr_78c345aa}`
- **Status Solver:** Terverifikasi melalui skrip pengujian otomatis `scripts/solve_754_autorev_1.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Penerapan Binary Hardening & Stripping:**
  Dalam pengembangan aplikasi komersial, biner wajib melalui proses pembersihan simbol (`strip --strip-all`) serta kompilasi dengan optimasi lanjut (`-O2` / `-O3`) untuk mengurangi kebocoran metadata.
- **Obfuscation & Control Flow Flattening:**
  Gunakan teknik kontrol alur datar (control flow flattening), penyamaran string runtime (runtime string encryption), dan proteksi integritas anti-tampering jika kode biner mendistribusikan logika sensitif.
- **Validasi Sisi Server (Server-Side Enforcement):**
  Jangan pernah mempercayakan rahasia otentikasi atau kunci lisensi hanya pada validasi di sisi klien (client-side verification). Seluruh verifikasi kritis harus diverifikasi pada server terisolasi.
