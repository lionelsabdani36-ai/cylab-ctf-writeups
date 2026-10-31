# 751 - Hidden Cipher 2 (Reverse Engineering, picoCTF 2026, Medium)

## Challenge Metadata
- ID: 751 | Event: picoCTF 2026 | Author: Yahya Meddy
- Category: Reverse Engineering | Difficulty: Medium (2)
- Flag: `academy{m4th_b3h1nd_c1ph3r_3c573aef}`

## Problem Statement & Scope
Lab on-demand menyajikan biner ELF 64-bit `hiddencipher2` via layanan netcat port interaktif. Pengguna diminta menjawab soal aritmatika sederhana (`+`, `-`, `*`). Jika jawaban benar, biner mencetak serangkaian bilangan bulat yang merupakan hasil transformasi karakter flag. Tugas peserta adalah merekayasa balik algoritma transformasi untuk memulihkan plaintext flag asli.

## Teori & Akar Kerentanan (Root Cause)
1. **Analisis Disassembly Fungsi `encode_flag` (0x14eb):**
   Fungsi menerima dua argumen: pointer ke buffer flag (`rdi`) dan integer hasil hitungan matematika pengguna (`esi`). Loop mengiterasi setiap byte flag (`movzx eax, BYTE PTR [rax]`) dan mengalikannya secara langsung dengan jawaban matematika (`imul eax, DWORD PTR [rbp-0x1c]`), lalu mencetaknya via `printf("%d, ")`.
2. **Kelemahan Aritmatika & Reversibilitas:**
   Operasi perkalian skalar terhadap representasi karakter ASCII $C_i = P_i \times K$ memiliki invers langsung berupa pembagian modular/integer jika $K \neq 0$:
   $$P_i = \lfloor C_i / K \rfloor$$
   Karena nilai skalar $K$ (jawaban matematika) diketahui oleh penyerang, enkripsi ini tidak memiliki sifat kerahasiaan (*zero semantic security*).
3. **Miskonfigurasi Secret Separation (CWE-200 / CWE-311):**
   Server melakukan komputasi enkripsi secara live terhadap `flag.txt` di server menggunakan parameter input yang dikontrol penuh oleh pengguna tanpa *one-way cryptographic primitives* (seperti SHA-256 atau AES-GCM).

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis biner ELF lokal dari arsip `hiddencipher2.zip` menggunakan `objdump -d -M intel`:
   - `generate_math_question` (0x1369): memilih operator secara pseudorandom (`+`, `-`, `*`) dan dua operan integer 1-10.
   - `encode_flag` (0x14eb): mengalikan setiap byte flag dengan nilai return dari `generate_math_question`.
2. Luncurkan instans lab via API CyLab:
   `PUT /api/challenges/751/instance/` -> status `RUNNING` pada `xebec.cylabacademy.net:18581`.
3. Hubungkan soket TCP interaktif:
   - Server mengirimkan prompt: `What is 9 * 9? `
   - Skrip menghitung jawaban: `81`, lalu mengirimkannya ke stdin.
   - Server merespons dengan nilai integer:
     `7857, 8019, 7857, 8100, 8181, 8829, ...`
4. Dekripsi flag dengan membagi setiap bilangan dengan `81`:
   - $7857 / 81 = 97 \rightarrow \text{'a'}$
   - $8019 / 81 = 99 \rightarrow \text{'c'}$
   - $7857 / 81 = 97 \rightarrow \text{'a'}$
   - Hasil lengkap menghasilkan flag utuh: `academy{m4th_b3h1nd_c1ph3r_3c573aef}`.
5. Verifikasi flag via `POST /api/submissions/` -> respons `{"correct": true}`.
6. Hentikan container melalui `DELETE /api/challenges/751/instance/`.

## Flag & Verifikasi
- `academy{m4th_b3h1nd_c1ph3r_3c573aef}` (Status: Verified `correct: true`, `historical: false`).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Defensive Engineering:** Jangan pernah menggunakan operasi matematika linier sederhana (perkalian skalar) untuk mengaburkan data sensitif. Gunakan cipher standar industri (misalnya AES-256-GCM atau ChaCha20-Poly1305) dengan generator kunci CSPRNG.
- **Access Control & Input Validation:** Validasi parameter kontrol dan pisahkan logika autentikasi/kuis dari akses langsung ke objek rahasia di sistem operasi.
