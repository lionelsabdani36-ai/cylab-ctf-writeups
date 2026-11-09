# Writeup: offset-cycle (Challenge ID: 733)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Dynamic Stack-Based Buffer Overflow & Ret2Win Hijack
- **Difficulty:** Medium (2)
- **Points:** 300
- **Author:** Aditya Sudhansu
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{u_Us3d_pwNt00L5_135aaff7}`
- **Flag Komunitas:** `CTF{u_Us3d_pwNt00L5_135aaff7}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Flaw Analysis), CWE-121 (Stack-based Buffer Overflow), CWE-242 (Use of Inherently Dangerous Function), CWE-676 (Use of Potentially Dangerous Function), System V AMD64 ABI (Stack Frame Alignment), NIST SP 800-53 SA-11 (Developer Testing and Evaluation), & OWASP ASVS V5 (Memory Safety).

---

## Problem Statement & Scope
Pada tantangan `offset-cycle`, peserta disajikan layanan jaringan berbasis biner Linux ELF x86_64 non-PIE yang mendengarkan koneksi TCP pada port kontainer:
- Deskripsi skenario: *"It's a race against time. Solve the binary exploit ASAP. A small program that generates a randomized buffer offset per instance. Can you find the dynamic offset, overwrite the saved return pointer, and redirect control flow to print the flag?"*
- Karakteristik biner: Target dikompilasi dengan proteksi stack canary dan PIE dinonaktifkan (`-fno-stack-protector -no-pie`). Namun, pengembang mengimplementasikan pengacakan alokasi buffer dinamis pada setiap instansiasi sesi, menyebabkan offset jarak masukan menuju *Saved Return Instruction Pointer* ($RIP$) bervariasi pada rentang terikat (64 hingga 128 byte).
- Sasaran pengujian: Menganalisis mekanisme alokasi buffer dinamis, memanfaatkan deret siklik De Bruijn untuk deteksi offset $\mathcal{O}(1)$, mengonstruksi payload *ret2win* yang memenuhi persyaratan *16-byte stack alignment* x86_64 ABI, membajak alur kendali ke fungsi `win()` pada alamat statis `0x00401196`, dan memverifikasi token resmi melalui REST API CyLab.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Fungsi Masukan Berbahaya Tanpa Batas Panjang (CWE-121 / CWE-242)
Program membaca input pengguna langsung ke dalam buffer lokal pada stack menggunakan fungsi tanpa batas panjang (seperti `gets()` atau `read()` dengan parameter ukuran yang melebihi kapasitas buffer lokal). Call frame stack x86_64 tersusun sebagai berikut:
```text
[ Alamat Rendah ] <-----------------------------------------> [ Alamat Tinggi ]
[ Buffer Lokal (K byte) ] | [ Saved RBP (8 byte) ] | [ Saved RIP / Return Address (8 byte) ]
```
Ketika masukan pengguna melebihi $K$ byte, kelebihan data secara deterministik merusak Saved RBP dan menimpa Saved RIP.

### 2. Resolusi Offset Dinamis Menggunakan Deret Siklik De Bruijn
Dalam skenario CTF dan eksploitasi dunia nyata di mana offset $K$ diacak atau bervariasi per build:
- Algoritma De Bruijn berorde $n=4$ menghasilkan barisan karakter di mana setiap sub-barisan berukuran 4 byte bersifat unik di seluruh panjang deret.
- Ketika program menerima deret De Bruijn dan mengalami crash pada instruksi `ret`, nilai 4/8 byte yang berada di puncak stack ($RSP$) atau mencemari register instruksi ($RIP$) dapat dicocokkan secara instan pada string pola generator untuk memperoleh nilai $K$ eksak dalam kompleksitas waktu $\mathcal{O}(1)$.

### 3. Jebakan Keselarasan Stack 16-Byte glibc ABI (x86_64 System V SSE Alignment)
Standar ABI arsitektur AMD64 System V menetapkan bahwa sebelum instruksi `call` dieksekusi, register stack pointer ($RSP$) harus selaras pada kelipatan 16 byte (`rsp % 16 == 0`).
- Saat `call` dijalankan, CPU mendorong alamat kembali 8-byte ke stack, sehingga pada awal fungsi tujuan, `rsp % 16 == 8`.
- Fungsi tujuan biasanya mengeksekusi `push rbp`, yang kembali menyelaraskan stack (`rsp % 16 == 0`).
- Namun, jika penyerang membajak alur eksekusi langsung ke alamat awal `win()` melalui instruksi `ret` (bukan melalui `call`), stack saat memasuki fungsi target tidak memiliki penyesuaian 8-byte tambahan tersebut.
- Ketika fungsi `win()` memanggil fungsi I/O glibc seperti `printf()`, `puts()`, atau `fopen()`, compiler memanfaatkan instruksi vektor SSE 128-bit (seperti `movaps %xmm0, ...`) yang membutuhkan operand memori selaras 16-byte. Kegagalan keselarasan memicu pengecualian perangkat keras *General Protection Fault* (`SIGSEGV`).
- **Solusi ROP Alignment:** Menyelipkan gadget `ret` tunggal (`0x0040101a`) tepat sebelum alamat `win()` (`0x00401196`). Gadget `ret` mengambil 8 byte dari stack dan melompat ke alamat berikutnya, menambahkan selisih 8 byte yang mengembalikan keselarasan `rsp % 16 == 0`.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Analisis Statis Biner & Tabel Simbol
Pemeriksaan biner menggunakan `objdump` dan `checksec`:
```bash
objdump -d -M intel vuln | grep -A 10 "<win>:"
```
Fungsi `win()` berada pada alamat absolut `0x00401196`. Gadget `ret` terisolasi diidentifikasi pada `0x0040101a`.

### Langkah 2: Evaluasi Dynamic Offset
Saat koneksi TCP dibuat, banner interaktif atau pembacaan probe De Bruijn mengidentifikasi offset instance aktif:
```python
banner = s.recv(1024).decode()
# Parsing offset terkonfirmasi, misalnya offset: 72
```

### Langkah 3: Konstruksi Payload Ret2Win Berimbang
Payload dirakit dengan urutan:
1. Padding pengisi buffer sebesar $K$ byte (`b"A" * offset`).
2. Alamat gadget `ret` (`0x0040101a` dalam 8-byte little-endian) untuk keselarasan 16-byte stack ABI.
3. Alamat fungsi target `win()` (`0x00401196` dalam 8-byte little-endian).
4. Karakter penutup baris (`b"\n"`).

```python
payload = b"A" * 72 + struct.pack("<Q", 0x0040101a) + struct.pack("<Q", 0x00401196) + b"\n"
```

### Langkah 4: Transmisi Socket & Pengambilan Flag
Payload dikirimkan ke layanan target:
```bash
python3 scripts/solve_733_offset_cycle.py
```
Layanan menerima payload, menyelesaikan fungsi input, mengeksekusi gadget `ret` penyelaras stack, melompat ke `win()`, dan mencetak token resmi ke koneksi socket.

---

## Flag & Bukti Verifikasi
- **Token Resmi Platform CyLab:** `academy{u_Us3d_pwNt00L5_135aaff7}`
- **Token Format Komunitas:** `CTF{u_Us3d_pwNt00L5_135aaff7}`
- **Hasil Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 733,
    "flag": "academy{u_Us3d_pwNt00L5_135aaff7}",
    "correct": true,
    "historical": false
  }
  ```

---

## Script Reproduksi & PoC Otomasi
Implementasi solver reproduktif lengkap yang mengintegrasikan algoritma generator deret De Bruijn murni, simulator verifikasi keselarasan stack x86_64 lokal standar NIST SP 800-115, serta klien socket remote terpadu pada `scripts/solve_733_offset_cycle.py`:
```bash
python3 scripts/solve_733_offset_cycle.py
```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Eliminasi Fungsi Masukan Berbahaya
Gantikan seluruh panggilan fungsi pembacaan data tanpa batas (`gets()`, `scanf("%s")`) dengan fungsi berorientasi panjang terikat yang memvalidasi ukuran buffer tujuan secara eksplisit:
```c
if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
    // Tangani error / EOF
}
```

### 2. Penerapan Proteksi Kompiler Modern (NIST SP 800-53 SA-11)
- **Stack Canaries (`-fstack-protector-strong`):** Menyisipkan nilai acak (*guard canary*) antara buffer lokal dan saved frame pointer. Jika buffer meluap, nilai canary rusak dan fungsi `__stack_chk_fail()` akan menghentikan proses sebelum instruksi `ret` sempat mengeksekusi alamat yang dipalsukan.
- **Position Independent Executables (`-fPIE -pie`):** Mengacak seluruh ruang memori biner saat dimuat, menghilangkan ketergantungan penyerang pada alamat statis `win()` atau gadget ROP.
- **Full RELRO (`-Wl,-z,relro,-z,now`):** Menjadikan tabel relokasi Global Offset Table (GOT) bersifat *read-only* setelah proses startup selesai, mencegah teknik pembajakan tabel pointer fungsi dinamis.

---

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)
- **David (Leader):** Mengorkestrasi analisis eksploitasi ret2win x86_64 dan mengarahkan standardisasi solusi berbasis De Bruijn cyclic sequence.
- **Charlie (Trend-hunter):** Menganalisis relevansi modul buffer overflow dinamis dengan tren soal kategori Pwn / Binary Exploitation pada LKS Nasional.
- **Alex (Fullstack-dev) & Omnirush (Coding Agent):** Mengimplementasikan generator deret De Bruijn mandiri (stdlib Python murni tanpa dependensi eksternal) dan penyelarasan ROP 16-byte.
- **Julius (QA-engineer):** Mengoreksi ketidaksesuaian flag lama dan memvalidasi respon live API CyLab HTTP 201 (`correct: true`).
- **Athena (Security-engineer):** Menjabarkan aspek arsitektur System V AMD64 ABI stack alignment dan memetakan kerentanan ke CWE-121 / CWE-242.
- **Judith (Guru LKS):** Mengabadikan studi kasus offset dinamis ini sebagai panduan praktis persiapan peserta lomba LKS Cyber Security.
