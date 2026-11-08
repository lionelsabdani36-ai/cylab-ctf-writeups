# Writeup: Bypass Me (Challenge ID: 761)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Binary Obfuscation & SUID Privilege Analysis (NIST SP 800-115 §4.2)
- **Difficulty:** Medium (2)
- **Points:** 200
- **Author:** Prince Niyonshuti N.
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{d3bugg3r_p0w3r_is_4w3s0m3_e85bfcda}`
- **Flag Komunitas:** `CTF{d3bugg3r_p0w3r_is_4w3s0m3_e85bfcda}`

---

## Problem Statement & Scope

Tantangan menguji kompetensi rekayasa balik (*reverse engineering*) kode biner terkompilasi x86-64 dan analisis eskalasi privilese sistem operasi:
> *"Your task is to analyze and exploit a password-protected binary called **bypassme.bin** and binary performs input sanitization. However, instead of guessing the password, you are expected to reverse-engineer the verification logic and bypass the authentication check."*
> *Petunjuk: "Check the assembly instructions carefully. Does the binary decode something in memory before checking?"*

Layanan tantangan mengekspos lingkungan Linux SSH on-demand (`chatelaine.cylabacademy.net:10351`). Pengguna berinteraksi sebagai pengguna tidak berprivilese `ctf-player` dan menemukan biner SUID-root `bypassme.bin` di direktori beranda. Biner meminta input kata sandi, menjalankan fungsi sanitasi karakter non-alfabet, membandingkan masukan dengan string rahasia terdekode di memori, dan jika valid, mengeksekusi pembacaan berkas terlindungi `./../root/flag.txt` dengan izin UID 0 (root).

---

## Teori & Akar Kerentanan (Root Cause Theory)

Analisis statis dan dinamis terhadap biner ELF x86-64 mengungkap kelemahan fundamental dalam arsitektur validasi kredensial:

1. **CWE-798 / Hard-Coded Credentials & CWE-311 / Missing Encryption of Sensitive Data:**
   - Kredensial rahasia disimpan langsung di dalam berkas biner dalam bentuk terobfuskasi XOR sederhana dengan satu kunci konstan (`0xAA`).
   - Karena biner tidak di-strip (`not stripped`, tabel simbol dan informasi debug ELF dipertahankan), fungsi-fungsi utama seperti `decode_password`, `sanitize`, dan `auth_sequence` langsung dapat dipetakan melalui utilitas `nm`, `readelf`, atau `objdump`.

2. **Rekonstruksi Tata Letak Memori Stack & Overlap QWORD/DWORD:**
   - Dalam fungsi `decode_password`, compiler mengalokasikan variabel lokal pada stack frame `[rbp]`:
     - QWORD pada `[rbp-0x13]` diisi dengan nilai heksadesimal `0xc9cff9d8cfdadff9`. Dalam representasi Little-Endian x86-64, byte memori tersusun:
       $$\text{Offset } 0..7: [\text{0xf9}, \text{0xdf}, \text{0xda}, \text{0xcf}, \text{0xd8}, \text{0xf9}, \text{0xcf}, \text{0xc9}]$$
     - DWORD pada `[rbp-0x0c]` diisi dengan nilai heksadesimal `0xcfd8dfc9`. Dalam representasi Little-Endian, byte memori tersusun:
       $$\text{Offset } 0..3: [\text{0xc9}, \text{0xdf}, \text{0xd8}, \text{0xcf}]$$
   - Karena jarak offset stack $(0x13 - 0x0c) = 7$, byte pertama dari DWORD (`0xc9`) menimpa byte ke-8 dari QWORD (`0xc9`) dengan nilai identik yang sama, lalu menambahkan 3 byte berikutnya (`0xdf`, `0xd8`, `0xcf`).
   - Total panjang buffer tersusun tepat 11 byte:
     $$[\text{0xf9}, \text{0xdf}, \text{0xda}, \text{0xcf}, \text{0xd8}, \text{0xf9}, \text{0xcf}, \text{0xc9}, \text{0xdf}, \text{0xd8}, \text{0xcf}]$$
   - Batas loop ditentukan oleh instruksi `cmp rax, 0xa; jbe`, yang mengevaluasi secara tegas indeks $0 \le i \le 10$ (11 putaran). Karakter null terminator (`0x00`) disematkan pada indeks ke-11.

3. **Jebakan Analisis (Reversing Trap) & Anti-Pattern:**
   - Analisis statis linier tanpa memperhitungkan tumpang-tindih (overlap) offset stack menghasilkan 12 byte (`0xc9` dihitung dua kali), yang menghasilkan string keliru `"SuperSeccure"` (dua huruf 'c'). Upaya autentikasi dengan kata sandi tersebut ditolak sistem.
   - Perhitungan inversi XOR 0xAA yang akurat pada 11 byte menghasilkan kata sandi otentik:
     $$\text{0xf9} \oplus \text{0xAA} = \text{'S'} \ (0x53), \quad \text{0xdf} \oplus \text{0xAA} = \text{'u'} \ (0x75), \quad \text{0xda} \oplus \text{0xAA} = \text{'p'} \ (0x70)$$
     $$\text{0xcf} \oplus \text{0xAA} = \text{'e'} \ (0x65), \quad \text{0xd8} \oplus \text{0xAA} = \text{'r'} \ (0x72), \quad \text{0xf9} \oplus \text{0xAA} = \text{'S'} \ (0x53)$$
     $$\text{0xcf} \oplus \text{0xAA} = \text{'e'} \ (0x65), \quad \text{0xc9} \oplus \text{0xAA} = \text{'c'} \ (0x63), \quad \text{0xdf} \oplus \text{0xAA} = \text{'u'} \ (0x75)$$
     $$\text{0xd8} \oplus \text{0xAA} = \text{'r'} \ (0x72), \quad \text{0xcf} \oplus \text{0xAA} = \text{'e'} \ (0x65)$$
     $$\Longrightarrow \text{Password} = \text{"SuperSecure"}$$

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Reconnaissance Biner & Identifikasi Simbol:**
   - Mengekstrak informasi simbol ELF pada instans:
     ```bash
     file ./bypassme.bin
     nm ./bypassme.bin | grep -E "(decode|auth|sanitize)"
     ```
   - Hasil menunjukkan simbol fungsi C++ `decode_password()`, `sanitize()`, dan `auth_sequence()`.

2. **Disassembly Fungsi `decode_password`:**
   - Menginspeksi instruksi perakitan via `objdump -d -M intel ./bypassme.bin`:
     ```assembly
     mov QWORD PTR [rbp-0x13], 0xc9cff9d8cfdadff9
     mov DWORD PTR [rbp-0x0c], 0xcfd8dfc9
     mov rax, 0
     .loop:
     cmp rax, 0xa
     ja .exit_loop
     movzx edx, BYTE PTR [rbp-0x13+rax]
     xor edx, 0xaa
     mov BYTE PTR [rbp-0x20+rax], dl
     inc rax
     jmp .loop
     .exit_loop:
     mov BYTE PTR [rbp-0x15], 0x0
     ```

3. **Inversi XOR & Ekstraksi Kata Sandi:**
   - Menjalankan skrip dekode biner Python:
     ```python
     raw = bytes.fromhex("f9dfdacfd8f9cfc9dfd8cf")
     password = bytes(b ^ 0xAA for b in raw).decode()
     # Output: "SuperSecure"
     ```

4. **Eksekusi Eksploitasi Tanpa Alokasi PTY:**
   - Mengirimkan kata sandi langsung ke biner via SSH stdin pipe (`ssh -T`) untuk menghindari translasi karakter terminal (`\r\n` / EOF handling):
     ```bash
     printf "SuperSecure\n" | ssh -T -p 10351 ctf-player@chatelaine.cylabacademy.net ./bypassme.bin
     ```
   - Biner memvalidasi masukan, memanggil `setuid(0)`, membaca `./../root/flag.txt`, dan mencetak token bendera.
   - Skrip reproduktif terverifikasi: `scripts/solve_761_bypass_me.py`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{d3bugg3r_p0w3r_is_4w3s0m3_e85bfcda}`
- **Format Flag Komunitas:** `CTF{d3bugg3r_p0w3r_is_4w3s0m3_e85bfcda}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 761, "flag": "academy{d3bugg3r_p0w3r_is_4w3s0m3_e85bfcda}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Pemahaman Level Rendah Representasi Memori (Little-Endian Stack Offsets):**
   - Dalam kompetensi LKS Cyber Security bidang *Reverse Engineering*, ketelitian membedakan batas alamat memori stack (`[rbp-0x13]` dan `[rbp-0x0c]`) sangat krusial. Kegagalan memetakan overlap satu byte akan menghasilkan kegagalan fatal pada fase verifikasi string.

2. **Mitigasi Rekayasa Perangkat Lunak Aman (CWE-798 & CWE-311 Hardening):**
   - Jangan pernah menyematkan kata sandi atau rahasia autentikasi langsung dalam biner klien/aplikasi lokal.
   - Validasi kredensial harus selalu didelegasikan ke peladen terpusat dengan fungsi hash kriptografis bergaram (*salted password hashing*) seperti Argon2id atau PBKDF2.
   - Gunakan perbandingan waktu-konstan (`CRYPTO_memcmp` atau `timingsafe_bcmp`) untuk meniadakan potensi *side-channel timing attack*.
   - Terapkan mekanisme stripping simbol (`strip -s`) dan proteksi kompilasi tingkat lanjut (Full RELRO, Stack Canary, PIE) pada distribusi biner produksi.
