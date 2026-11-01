# Writeup: Fresh Java (Challenge ID: 271)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Java Bytecode Static Analysis
- **Difficulty:** Medium
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 200
- **Flag:** `academy{700l1ng_r3qu1r3d_5e462060}`

---

## Problem Statement & Scope
Diberikan sebuah berkas biner Java class terkompilasi (`KeygenMe.class`). Peserta diminta menganalisis alur eksekusi biner untuk menemukan lisensi atau flag valid yang diharapkan oleh program tanpa memiliki akses ke kode sumber Java mentah.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Ketiadaan Obfuskasi Bytecode (Unobfuscated JVM Bytecode):** Berkas `.class` Java mempertahankan struktur instruksi tingkat menengah (bytecode) yang deterministik. Tanpa proteksi bytecode obfuscator (seperti ProGuard, R8, atau Zelix KlassMaster), nama metode, pemanggilan fungsi, dan instruksi primitif dapat dibaca langsung.
2. **Hardcoded Character-by-Character Verification:** Rutin validasi masukan memverifikasi setiap karakter string secara sekuensial menggunakan metode `String.charAt(int)`. Pada level bytecode:
   - Indeks karakter dimuat ke stack operan melalui `iconst_N` (rentang $0 \le N \le 5$, opcode `0x03` hingga `0x08`) atau `bipush` (opcode `0x10 <index>`).
   - Pemanggilan metode `invokevirtual java/lang/String.charAt:(I)C` (opcode `0xb6`).
   - Karakter ekspektasi didorong ke stack menggunakan opcode `bipush <immediate_ascii>`.
   - Perbandingan karakter dilakukan oleh instruksi cabang bersyarat `if_icmpne` (opcode `0x9f` atau `0xa0`), yang langsung melompat ke blok kegagalan lisensi jika terjadi ketidaksesuaian.
3. **Ekstraksi Statis Tanpa Eksekusi JVM:** Karena logika perbandingan bersifat statis dan linear, analisis heksadesimal terhadap aliran instruksi `bipush` memungkinkan pemulihan plaintext secara instan tanpa membutuhkan Java Virtual Machine (JVM) maupun kakas dekompilasi pihak ketiga.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis biner `.class` menggunakan pemindaian pola opcode:
   ```bash
   # Opcode bipush = 0x10, invokevirtual = 0xb6
   python3 -c "
   data = open('KeygenMe.class', 'rb').read()
   # Memindai urutan 0x10 <printable_ascii>
   "
   ```
2. Telusuri pasangan indeks argumen dan nilai karakter ekspektasi pada bytecode:
   - Index 0: `a` (`0x61`)
   - Index 1: `c` (`0x63`)
   - Index 2: `a` (`0x61`)
   - Index 3: `d` (`0x64`)
   - Index 4: `e` (`0x65`)
   - Index 5: `m` (`0x6d`)
   - Index 6: `y` (`0x79`)
   - Index 7: `{` (`0x7b`)
   - Index 8: `7` (`0x37`) ... hingga Index 33: `}` (`0x7d`)
3. Rangkai kembali seluruh karakter berdasarkan urutan indeks dari 0 hingga 33:
   $$\text{Flag} = \text{academy\{700l1ng\_r3qu1r3d\_5e462060\}}$$

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{700l1ng_r3qu1r3d_5e462060}`
- **Verifikasi:** Endpoint REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 271, "flag": "academy{700l1ng_r3qu1r3d_5e462060}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Bytecode Obfuscation & Control Flow Flattening:** Pada modul pengamanan aplikasi berbasis Java/Android di LKS Cyber Security, selalu gunakan kakas obfuskasi untuk mengaburkan alur kontrol, mengganti nama identifier menjadi acak, dan memecah string sensitif.
- **Cryptographic Hash Comparison:** Hindari verifikasi string sensitif karakter per karakter secara komparatif langsung. Terapkan verifikasi satu arah berbasis cryptographic hash (seperti SHA-256 bergaram) dengan *constant-time comparison* (`MessageDigest.isEqual()`) untuk mencegah ekstraksi statis dan serangan side-channel timing.
