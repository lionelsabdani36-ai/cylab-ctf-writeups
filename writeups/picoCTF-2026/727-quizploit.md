# Writeup: Quizploit (Challenge ID: 727)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Stack Buffer Overflow & Mitigation Triage
- **Difficulty:** Easy (1)
- **Points:** 50
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{my_bIn@4y_3xpl0it_fL@g_95fef02a}`
- **Flag Komunitas:** `CTF{my_bIn@4y_3xpl0it_fL@g_95fef02a}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), CWE-121 (Stack-based Buffer Overflow), CWE-676 (Use of Potentially Dangerous Function), & OWASP ASVS V5 (Memory and Stack Protection Architecture).

---

## Problem Statement & Scope
Pada modul pembelajaran `Quizploit`, peserta diuji dalam pemahaman komprehensif terkait arsitektur biner ELF x86-64, mekanisme mitigasi memori pada sistem Linux modern, dan identifikasi kerentanan buffer overflow tingkat stack:
- Skenario lingkungan: Layanan jaringan kuis interaktif 13-tahap berjalan di balik socket TCP pada kontainer lab on-demand. Peserta diberikan berkas kode sumber C (`vuln.c`) dan biner hasil kompilasi (`vuln`).
- Pernyataan tantangan:
  > *"Solve the quiz. Download the source code and binary to answer 13 questions."*
- Sasaran pengujian: Menganalisis berkas biner `vuln` (arsitektur, linking type, stripping status), membedah fungsi rentan `vuln()` dan fungsi target `win()`, menghitung kapasitas memori dan batas pembacaan input, mengidentifikasi mitigasi aktif (NX), menentukan teknik eksploitasi yang relevan (ROP / ret2win), serta mengirimkan jawaban presisi ke layanan kuis interaktif untuk mendapatkan token resmi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Stack-based Buffer Overflow (CWE-121)
Analisis kode sumber `vuln.c`:
```c
void win() {
    system("cat flag.txt");
}

void vuln() {
    char buffer[0x15] = {0};
    fprintf(stdout, "\nEnter payload: ");
    fgets(buffer, 0x90, stdin);
}

void main() {
    vuln();
}
```
Karakteristik kerentanan:
- Buffer `buffer` dialokasikan di stack frame fungsi `vuln()` dengan ukuran `0x15` byte (21 byte desimal).
- Fungsi `fgets(buffer, 0x90, stdin)` membaca hingga `0x90` byte (144 byte desimal) dari stream standar input.
- Terjadi disparitas ukuran memori sebesar $0x90 - 0x15 = 0x7b$ byte (123 byte desimal), yang memungkinkan penulisan melampaui batas buffer (*out-of-bounds write*) ke stack frame.
- Data input yang berlebih akan menimpa variabel lokal lain, frame pointer tersimpan (`$rbp`), dan saved return address (`$rip`).

### 2. Mitigasi Memori dan Teknik Bypass (NX & ROP)
- **Arsitektur & Simbol:** Biner bertipe 64-bit ELF (`x86-64`), dynamic linking dengan `libc.so.6`, dan memiliki tabel simbol lengkap (`not stripped`), sehingga entry point fungsi `win()` dapat diidentifikasi secara langsung pada alamat `0x401176`.
- **Proteksi NX (No-eXecute):** Segmen GNU_STACK ditandai sebagai `RW-` (Read-Write, Non-Executable). Hal ini mencegah eksekusi shellcode langsung di stack.
- **Bypass Technique:** Karena stack tidak dapat dieksekusi, teknik eksploitasi standar memanfaatkan kode yang sudah ada di segmen teks yang dapat dieksekusi (*executable code reuse*), seperti pengalihan aliran eksekusi langsung ke fungsi `win()` (*ret2win*) atau menyusun rantai *Return-Oriented Programming* (ROP).

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Inspeksi Biner & Mitigasi (checksec & readelf)
Jalankan analisis awal terhadap biner `vuln`:
```bash
file vuln
# Output: vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, not stripped

readelf -l vuln | grep GNU_STACK
# Output: GNU_STACK 0x0000000000000000 ... RW  0x10 (NX enabled, no X flag)
```

### Langkah 2: Resolusi Simbol Fungsi Target `win()`
Gunakan utilitas `objdump` atau `nm` untuk menentukan lokasi fungsi pembacaan flag:
```bash
nm vuln | grep win
# Output: 0000000000401176 T win
```
Fungsi `win()` berada pada alamat absolut `0x401176` dan memanggil `system("cat flag.txt")`.

### Langkah 3: Penyusunan Jawaban Kuis Interaktif
Berdasarkan analisis statis, formulasikan 13 parameter teknis:
1. `0x1` (Architecture): `64-bit`
2. `0x2` (Linking): `dynamic`
3. `0x3` (Stripping): `not stripped`
4. `0x4` (Buffer Size): `0x15`
5. `0x5` (Bytes Read): `0x90`
6. `0x6` (Vulnerability): `yes`
7. `0x7` (Vulnerable Function): `fgets`
8. `0x8` (Uncalled Function): `win`
9. `0x9` (Attack Type): `buffer overflow`
10. `0xa` (Overflow Capacity): `0x7b`
11. `0xb` (Active Protection): `NX`
12. `0xc` (Bypass Technique): `ROP`
13. `0xd` (Win Address): `0x401176`

### Langkah 4: Interaksi Socket dan Penerimaan Flag
Hubungkan skrip otomasi ke instance lab via soket TCP:
```bash
python3 scripts/solve_727_quizploit.py <host> <port>
```
Skrip mengirimkan ke-13 jawaban secara berurutan saat prompt `>>` diterima. Setelah pertanyaan terakhir terjawab, server memancarkan respon:
```text
All 13 questions answered correctly! Here is your flag:
academy{my_bIn@4y_3xpl0it_fL@g_95fef02a}
```

---

## Flag & Bukti Verifikasi
- **Token Resmi Platform CyLab:** `academy{my_bIn@4y_3xpl0it_fL@g_95fef02a}`
- **Token Format Komunitas:** `CTF{my_bIn@4y_3xpl0it_fL@g_95fef02a}`
- **Hasil Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 727,
    "flag": "academy{my_bIn@4y_3xpl0it_fL@g_95fef02a}",
    "correct": true,
    "historical": false
  }
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Penggunaan Fungsi Input Terikat Batas (Safe Input Bounding)
Fungsi `fgets()` pada dasarnya menerima parameter ukuran, namun kerentanan terjadi karena programmer menentukan batas ukuran yang salah (`0x90` alih-alih `sizeof(buffer)`):
```c
// Rentan (CWE-121 / CWE-676)
char buffer[0x15];
fgets(buffer, 0x90, stdin);

// Aman & Defensif
char buffer[0x15];
if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
    // Handle error or EOF
}
```
Selalu gunakan `sizeof(target_buffer)` atau konstanta yang didefinisikan secara seragam untuk parameter panjang buffer.

### 2. Pengaktifan Mitigasi Kompilator Lengkap (Hardened Toolchain)
Saat mengompilasi biner C/C++ untuk lingkungan produksi, aktifkan seluruh lapisan proteksi memori modern:
- **Stack Canaries (`-fstack-protector-all` / `-fstack-protector-strong`):** Memasukkan nilai acak (*canary*) sebelum saved frame pointer, yang diverifikasi sebelum fungsi me-return. Jika overflow terjadi, program langsung menghentikan diri (*abort*) sebelum $rip dapat dibajak.
- **Position Independent Executable (`-fPIE -pie`):** Mengacak seluruh basis alamat biner di memori via ASLR, sehingga alamat fungsi seperti `win()` tidak lagi statis pada `0x401176`.
- **Full RELRO (`-Wl,-z,relro,-z,now`):** Menjadikan Global Offset Table (GOT) sepenuhnya *read-only* setelah inisialisasi linker untuk mencegah penimpaan entri fungsi dinamis.
- **Fortify Source (`-D_FORTIFY_SOURCE=2`):** Mendeteksi operasi buffer overflow umum pada waktu kompilasi dan waktu eksekusi.
