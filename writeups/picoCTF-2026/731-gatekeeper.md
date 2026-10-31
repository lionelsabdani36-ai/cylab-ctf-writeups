# 731 - Gatekeeper (Reverse Engineering, picoCTF 2026, Medium)

## Challenge Metadata
- ID: 731 | Event: picoCTF 2026 | Author: Yahya Meddy
- Category: Reverse Engineering | Difficulty: Medium (2)
- Flag: `academy{3_digit_hex_GT_999_fed7fa16}`

## Problem Statement & Scope
Tantangan menyediakan program ELF 64-bit `gatekeeper` yang menerima input kode numerik. Program memberikan instruksi `Enter a numeric code (must be > 999 ): `. Pengguna harus menemukan representasi numerik yang memenuhi batas logika verifikasi biner untuk memicu pemanggilan fungsi `reveal_flag` pada container lab on-demand.

## Teori & Akar Kerentanan (Root Cause)
1. **Analisis Logika Verifikasi Input (`main` 0x158e):**
   - Program membaca input string via `__isoc99_scanf("%31s", buffer)`.
   - Menguji apakah string adalah desimal via `is_valid_decimal()` (menguji mask `0x800` / `isdigit`). Jika desimal, nilai dikonversi via `atoi()`.
   - Jika bukan desimal murni, program menguji via `is_valid_hex()` (menguji mask `0x1000` / `isxdigit`). Jika heksadesimal valid, nilai dikonversi via `strtol(buffer, NULL, 16)`.
   - Program memberlakukan tiga batasan ketat:
     - $val > 999$ (`cmp val, 0x3e7; jg`)
     - $val \le 9999$ (`cmp val, 0x270f; jle`)
     - $\text{strlen}(buffer) == 3$ (`cmp strlen, 0x3; jne 16a5`)
2. **Kontradiksi Representasi Basis Bilangan (Base Representation Mismatch):**
   Pada basis 10 (desimal), rentang integer $[1000, 9999]$ selalu memiliki panjang karakter minimum 4 digit (`"1000"` hingga `"9999"`). Tidak ada bilangan desimal $> 999$ dengan panjang 3 karakter. Namun pada basis 16 (heksadesimal), nilai desimal $1000$ dituliskan sebagai `0x3e8`, yang memiliki panjang string tepat 3 karakter (`"3e8"`).
3. **Obfuscation Reversal pada `reveal_flag` (0x1449):**
   Fungsi `reveal_flag` membaca `/flag.txt`, kemudian mengiterasi indeks dari akhir ke awal ($i = N-1$ turun ke $0$). Karakter dicetak satu per satu (`putchar(flag[i])`), dan setiap kali $i \pmod 4 == 0$, biner menyisipkan string pengabur `ftc_oc_ip` (`printf("ftc_oc_ip")`).

## Rekonstruksi Eksploitasi Step-by-Step
1. Ekstraksi dan disassembly biner `gatekeeper` dengan `objdump -d -M intel`.
2. Identifikasi syarat bypass gerbang:
   - Input string heksadesimal 3 karakter dengan nilai $\ge 1000$: `3e8` ($3 \times 16^2 + 14 \times 16 + 8 = 768 + 224 + 8 = 1000$).
3. Luncurkan instans lab via CyLab API:
   `PUT /api/challenges/731/instance/` -> dialokasikan pada `chatelaine.cylabacademy.net:17012`.
4. Kirim input `3e8\n` melalui koneksi soket TCP:
   - Server mengembalikan string tersamarkan:
     `}61aftc_oc_ipf7deftc_oc_ipf_99ftc_oc_ip9_TGftc_oc_ip_xehftc_oc_ip_tigftc_oc_ipid_3ftc_oc_ip{ymeftc_oc_ipdacaftc_oc_ip`
5. Rekonstruksi plaintext:
   - Hapus seluruh token `ftc_oc_ip`.
   - Balikkan urutan string (reversal):
     `academy{3_digit_hex_GT_999_fed7fa16}`.
6. Verifikasi via `POST /api/submissions/` -> `{"correct": true}`.
7. Bersihkan resource instans dengan `DELETE /api/challenges/731/instance/`.

## Flag & Verifikasi
- `academy{3_digit_hex_GT_999_fed7fa16}` (Status: Verified `correct: true`, `historical: false`).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Input Sanitization & Type Coercion:** Hindari multi-base parsing otomatis jika format yang diinginkan adalah desimal murni. Tetapkan spesifikasi basis bilangan secara eksplisit (`strtol` dengan basis tetap 10).
- **Format Invariant Validation:** Jangan mengandalkan panjang string (`strlen`) sebagai proksi ukuran magnitude bilangan biner jika tipe representasi teks tidak diisolasi.
