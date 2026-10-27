# Writeup: vault-door-4 (Challenge ID: 71)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Multi-Radix Encoding
- **Difficulty:** Medium
- **Author:** Mark E. Haase
- **Event:** picoCTF 2019
- **Points:** 250
- **Flag:** `academy{jU5t_4_bUnCh_0f_bYt3s_88a31dad6c}`

---

## Problem Statement & Scope
Diberikan berkas Java `VaultDoor4.java`. Logika verifikasi membandingkan representasi byte input pengguna dengan sebuah array statis berukuran 32 elemen yang didefinisikan menggunakan berbagai format basis bilangan: desimal (basis 10), heksadesimal (basis 16), oktal (basis 8), dan karakter literal ASCII. Analis diminta menyatukan seluruh representasi tersebut menjadi string kata sandi.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Representasi Nilai Literal Numerik dalam Java:**
   - Desimal: `106`, `85`, `53`, dst. (nilai langsung).
   - Heksadesimal: prefiks `0x` (contoh: `0x55` = 85 desimal = karakter `'U'`).
   - Oktal: prefiks `0` (contoh: `0142` = $1 \times 64 + 4 \times 8 + 2 = 98$ desimal = karakter `'b'`).
   - Karakter literal: tanda petik tunggal `'a'` (nilai ASCII 97).
2. **Kelemahan Hardcoded Radix Inlining:** Meskipun menggunakan empat representasi notasi yang berbeda untuk mengelabui pembacaan kasual (*code obfuscation*), seluruh nilai tetap merupakan representasi statis dari byte 8-bit yang dapat dikonversikan secara instan ke karakter ASCII.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Ekstrak 32 elemen array `myBytes`:
   - Baris 1 (Desimal): `106, 85, 53, 116, 95, 52, 95, 98` $\rightarrow$ `jU5t_4_b`
   - Baris 2 (Heksadesimal): `0x55, 0x6e, 0x43, 0x68, 0x5f, 0x30, 0x66, 0x5f` $\rightarrow$ `UnCh_0f_`
   - Baris 3 (Oktal): `0142, 0131, 0164, 063, 0163, 0137, 070, 070` $\rightarrow$ `bYt3s_88`
   - Baris 4 (Karakter): `'a', '3', '1', 'd', 'a', 'd', '6', 'c'` $\rightarrow$ `a31dad6c`
2. Gabungkan seluruh segmen:
   `jU5t_4_bUnCh_0f_bYt3s_88a31dad6c`
3. Susun flag resmi: `academy{jU5t_4_bUnCh_0f_bYt3s_88a31dad6c}`.
4. Eksekusi solver Python:
   ```bash
   python3 scripts/solve_71_vault_door_4.py
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{jU5t_4_bUnCh_0f_bYt3s_88a31dad6c}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Larangan Hardcoding Secrets:** Penyematan data rahasia (*hardcoded secrets*) dalam kode sumber terkompilasi (termasuk berkas `.class` Java) sangat mudah diekstraksi menggunakan decompiler seperti CFR, Jadx, atau `javap -c`.
- **Standar Sanitasi Kode:** Modul LKS Secure Software Development mewajibkan penggunaan secret scanner (misal Trivy, Gitleaks) dalam pipeline CI/CD untuk mencegah masuknya token kredensial ke repositori.
