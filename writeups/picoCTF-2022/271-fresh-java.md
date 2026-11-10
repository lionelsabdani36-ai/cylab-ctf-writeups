# Writeup: Fresh Java (Challenge ID: 271)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / JVM Bytecode Static Analysis & Logic Recovery (CWE-312 / CWE-798)
- **Difficulty:** Medium (diff=2)
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 200
- **Flag:** `academy{700l1ng_r3qu1r3d_5e462060}`

---

## Problem Statement & Scope

Tantangan menyajikan program Java terkompilasi dalam format berkas *bytecode* (`KeygenMe.class`):
> *"Can you get the flag? Reverse engineer this Java program."*

Peserta diminta menganalisis alur eksekusi internal dan struktur instruksi pada berkas `.class` Java guna memulihkan kunci lisensi atau *flag* rahasia yang diharapkan oleh program tanpa memiliki akses langsung ke kode sumber Java mentah.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Ketiadaan Obfuskasi Bytecode JVM (Unobfuscated JVM Bytecode):**
   - Berkas biner Java `.class` menyimpan instruksi perantara (*intermediate representation*) yang dieksekusi oleh Java Virtual Machine (JVM).
   - Tanpa proteksi *bytecode obfuscator* (seperti ProGuard, R8, atau Zelix KlassMaster), struktur kelas, tanda tangan metode, pemanggilan fungsi primitif, dan konstanta literal tetap terjaga dalam struktur biner yang deterministik.

2. **Verifikasi Karakter per Karakter Terbuka (Hardcoded Sequential Verification, CWE-312 / CWE-798):**
   - Rutin validasi program membaca masukan pengguna dan memverifikasi kesesuaian setiap karakter secara linear dari indeks 0 hingga 33 menggunakan metode `String.charAt(int)`.
   - Pada tingkat instruksi bytecode JVM:
     - Indeks karakter dimuat ke *operand stack* melalui instruksi `iconst_N` (untuk rentang $0 \le N \le 5$, opcode `0x03` hingga `0x08`) atau `bipush <index>` (opcode `0x10 <index>`).
     - Instruksi `invokevirtual java/lang/String.charAt:(I)C` (opcode `0xb6`) dieksekusi untuk mengambil karakter pada indeks tersebut.
     - Karakter ekspektasi didorong ke *operand stack* menggunakan opcode `bipush <immediate_ascii>` (opcode `0x10 <ascii_val>`).
     - Perbandingan kesetaraan karakter dievaluasi oleh instruksi cabang bersyarat `if_icmpne` (opcode `0x9f` atau `0xa0`), yang melompat ke blok kegagalan lisensi jika nilai karakter tidak cocok.

3. **Rekonstruksi Deterministik Tanpa Lingkungan Runtime JVM:**
   - Karena aliran instruksi `invokevirtual` (`0xb6`) selalu diikuti oleh `bipush` (`0x10`) yang memuat nilai ASCII target, seluruh rangkaian token rahasia dapat direkonstruksi secara deterministik melalui pemindaian pola heksadesimal langsung tanpa memerlukan instalasi kakas dekompilasi Java pihak ketiga (seperti CFR atau Jadx) maupun runtime JVM.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Pengunduhan & Identifikasi Berkas Bytecode:**
   - Mengunduh artefak berkas kelas dari repositori CyLab:
     ```bash
     wget https://challenge-files.cylabacademy.net/library/8a49236ebd176634e844de1f01d33adf9d0185836ef578fd72b168e513a4eabc/KeygenMe.class
     ```
   - Memeriksa tanda tangan biner berkas (*magic bytes* Java `0xCAFEBABE`):
     ```bash
     file KeygenMe.class
     ```
     Keluaran:
     ```text
     KeygenMe.class: compiled Java class data, version 55.0 (Java 11)
     ```

2. **Analisis Pola Bytecode & Pemetaan Indeks Karakter:**
   - Mengamati struktur heksadesimal urutan instruksi perbandingan:
     ```text
     [0x10, idx, 0xb6, ...] -> [0x10, char_val, 0x9f/0xa0, ...]
     ```
   - Setiap pasangan instruksi menetapkan relasi satu-ke-satu antara posisi indeks dan karakter yang diharapkan:
     - Indeks 0: `0x61` -> `'a'`
     - Indeks 1: `0x63` -> `'c'`
     - Indeks 2: `0x61` -> `'a'`
     - Indeks 3: `0x64` -> `'d'`
     - Indeks 4: `0x65` -> `'e'`
     - Indeks 5: `0x6d` -> `'m'`
     - Indeks 6: `0x79` -> `'y'`
     - Indeks 7: `0x7b` -> `'{'`
     - Indeks 8: `0x37` -> `'7'`
     - ... hingga Indeks 33: `0x7d` -> `'}'`

3. **Eksekusi Skrip Solver Otomatis (`scripts/solve_271_fresh_java.py`):**
   - Skrip Python mem-parsing berkas `.class` secara langsung, mengekstrak operan `bipush` setelah pemanggilan `charAt`, dan menyatukan string:
     ```bash
     python3 scripts/solve_271_fresh_java.py
     ```
     Keluaran:
     ```text
     [*] Solving Challenge 271: Fresh Java
     [*] Stage 1: Loading compiled Java bytecode (.class file)
         [+] Successfully loaded 1883 bytes of JVM bytecode
     [*] Stage 2: Scanning bytecode for String.charAt & bipush comparison patterns
         [+] Reconstructed 34 characters across 34 operand slots
     [+] Reconstructed Flag: academy{700l1ng_r3qu1r3d_5e462060}

     [SUCCESS] Module 271 (Fresh Java) fully audited and solved: academy{700l1ng_r3qu1r3d_5e462060}
     ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{700l1ng_r3qu1r3d_5e462060}`
- **Verifikasi API Platform:** Penyerahan token melalui endpoint REST API `POST /api/submissions/` menghasilkan status **HTTP 201 Created**:
  ```json
  {
    "user": 1072359,
    "challenge": 271,
    "flag": "academy{700l1ng_r3qu1r3d_5e462060}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

- **Relevansi Modul LKS Cyber Security (Reverse Engineering & Mobile/Java Security):**
  - Pada cabang lomba LKS Cyber Security, analisis biner Java/Kotlin (aplikasi desktop JAR maupun APK Android) menuntut pemahaman terhadap arsitektur berbasis stack JVM (*operand stack, local variables, constant pool*).
  - Peserta yang memahami pola opcode primitif dapat menyelesaikan tantangan *keygen* atau *license check* sederhana secara instan tanpa tergantung pada kakas dekompiler GUI.
- **Remediasi & Mitigasi Defensif Komprehensif:**
  1. **Penerapan Obfuskasi Bytecode & Perataan Alur Kontrol (Control Flow Flattening):**
     Gunakan kakas obfuskasi untuk mengubah identifier menjadi simbol acak, memecah blok logika menjadi *switch-dispatcher* berlapis, dan menyamarkan konstanta string ke dalam fungsi dekripsi runtime dinamis.
  2. **Verifikasi Hash Kriptografis Waktu Konstan (Constant-Time Hash Comparison):**
     Hindari perbandingan karakter secara komparatif langsung. Terapkan validasi berbasis fungsi hash satu arah yang diberi *salt* (seperti SHA-256 bergaram) dengan perbandingan waktu konstan:
     ```java
     byte[] expectedHash = HexFormat.of().parseHex("...");
     byte[] inputHash = MessageDigest.getInstance("SHA-256").digest((salt + userInput).getBytes(StandardCharsets.UTF_8));
     if (!MessageDigest.isEqual(expectedHash, inputHash)) {
         throw new SecurityException("Kunci lisensi tidak valid.");
     }
     ```
  3. **Penyimpanan Kunci pada Enklave Aman (Hardware Security Module / Keystore):**
     Pada aplikasi produksi berskala enterprise, rahasia otentikasi tidak boleh di-*hardcode* di dalam biner klien, melainkan diverifikasi melalui peladen otentikasi terpisah atau disimpan dalam penyimpanan perangkat keras terlindungi (*Android KeyStore / TPM*).
