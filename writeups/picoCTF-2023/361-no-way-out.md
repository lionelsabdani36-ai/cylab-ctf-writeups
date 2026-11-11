# Writeup: No way out (Challenge ID: 361)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Unity Asset Serialisation & Binary Inspection (CWE-312 / CWE-693)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2023
- **Points:** 200
- **Author:** Kris
- **Flag:** `academy{WELCOME_TO_UNITY!!}`

---

## Problem Statement & Scope

Tantangan mendistribusikan berkas terkompresi terlindungi kata sandi (`win.zip` / `mac.app.zip`, kata sandi `picoctf`) yang berisi aplikasi permainan berbasis Unity Engine 3D. Di dalam skenario permainan, karakter pemain terkurung di dalam area sempit berpembatas dinding tinggi (*invisible colliders*) yang menghalangi jalan menuju lokasi bendera rahasia di luar arena.

Instruksi meminta flag diserahkan dalam format baku CyLab: `academy{<token>}`.

---

## Teori & Akar Kerentanan (Root Cause Theory - NIST SP 800-115 § 4.2)

1. **Serialisasi Scene Aset Statis Tanpa Proteksi (CWE-312 / Cleartext Asset Storage):**
   - Unity Engine mengemas seluruh hierarki game object, material, dan teks statis 3D ke dalam berkas biner serialisasi scene (seperti `pico_Data/level0` atau `sharedassets0.assets`).
   - Objek teks yang ditempatkan secara langsung pada hierarki scene tanpa enkripsi tingkat aplikasi (*at-rest plaintext storage*) dapat diinspeksi secara statis tanpa perlu mengompilasi ulang atau menjalankan runtime Unity.
2. **Ketiadaan Validasi Integritas Perakitan Klien (CWE-693 / Protection Mechanism Failure):**
   - Logika lompatan dan gerak diimplementasikan di sisi klien dalam rakitan C# .NET (`pico_Data/Managed/Assembly-CSharp.dll`).
   - Logika `PlayerController.Update` melakukan validasi `characterController.isGrounded` sebelum mengizinkan lompatan. Tanpa integritas assembly (misal via code signing, anti-tamper, atau IL2CPP compilation), pengecekan tersebut rentan di-patch menggunakan decompiler .NET (seperti dnSpy) untuk memberikan kemampuan terbang tak terbatas (*infinite jumping*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Metode Cepat (Static Asset Carving):**
   - Mengekstrak `win.zip` menggunakan kata sandi `picoctf`.
   - Menginspeksi file serialisasi scene `pico_Data/level0` menggunakan utilitas ekstraksi string atau skrip Python:
     ```bash
     strings win/pico_Data/level0 | grep -C 2 "WELCOME"
     ```
   - Aliran biner secara eksplisit memuat string teks 3D:
     ```text
     WELCOME_TO_UNITY!!
     ```
2. **Metode Alternatif (Dynamic Patching / dnSpy):**
   - Membuka `win/pico_Data/Managed/Assembly-CSharp.dll` di dnSpy.
   - Mengedit kelas `PlayerController`, menghapus kondisi `this.characterController.isGrounded && !this.isClimbing` dari blok `Input.GetButton("Jump")`.
   - Menyimpan rakitan, menjalankan game, dan melompati dinding pembatas menuju area bendera untuk memicu display teks.
3. **Format & Validasi:**
   - Membungkus token ke format resmi: `academy{WELCOME_TO_UNITY!!}`.
   - Mengirim token melalui REST API CyLab `POST /api/submissions/`.

---

## Flag & Verifikasi

- **Flag:** `academy{WELCOME_TO_UNITY!!}`
- **Bukti Validasi:** REST API CyLab merespons dengan HTTP Status 201 Created:
  ```json
  {"user": 1072359, "challenge": 361, "flag": "academy{WELCOME_TO_UNITY!!}", "correct": true, "historical": false}
  ```
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi mandiri `scripts/solve_361_no_way_out.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115 § 4.4)

1. **Proteksi Aset Permainan (Asset Encryption & Remote Delivery):**
   Teks atau data rahasia dalam game tidak boleh disimpan dalam plaintext di scene assets. Data sensitif harus dienkripsi secara asimetris atau diambil secara dinamis dari API server terotentikasi setelah menyelesaikan milestone.
2. **Integritas Biner Klien (Binary Hardening & IL2CPP):**
   Pada aplikasi klien .NET/Unity yang membutuhkan proteksi integritas logika (misal verifikasi anti-cheat atau DRM), wajib menerapkan enkripsi assembly (*Unity IL2CPP compilation* ke biner mesin ELF/PE asli), penandatanganan kode digital, dan pemeriksaan hash modul saat startup.
