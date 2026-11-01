# Writeup: GDB Test Drive (Challenge ID: 273)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Dynamic Debugging & Instruction Pointer Manipulation
- **Difficulty:** Medium
- **Author:** LT 'syreal' Jones
- **Event:** picoCTF 2022
- **Points:** 100
- **Flag:** `academy{d3bugg3r_dr1v3_4cc75120}`

---

## Problem Statement & Scope
Diberikan sebuah berkas biner ELF 64-bit Linux (`gdbme`). Program dirancang untuk menunda atau menghentikan eksekusi sebelum mencapai rutin pembongkaran flag. Analis diminta mempraktikkan navigasi instruksi tingkat rendah menggunakan GNU Debugger (GDB) guna mengalihkan alur eksekusi (*instruction pointer manipulation*) melewati instruksi penunda (*sleep*) sehingga string flag dicetak ke *stdout*.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Dynamic Execution Flow Control:** Biner kompilasi x86_64 mengeksekusi instruksi secara linier berdasarkan register penunjuk instruksi (`$rip`). Pada fungsi `main`, program memuat nilai konstanta besar ke register argumen `$rdi` kemudian memanggil fungsi `sleep()` di alamat offset `main+99`.
2. **Instruction Pointer Hijacking via Debugger:** Fasilitas debugging ptrace pada sistem operasi Linux memungkinkan inspeksi dan manipulasi seluruh register thread proses. Dengan menyetel breakpoint di `*(main+99)` tepat sebelum pemanggilan `sleep()`, analis dapat menggunakan perintah `jump *(main+104)` pada GDB untuk langsung memperbarui register `$rip` ke alamat sesudah `call sleep`.
3. **Decryption Routine Execution:** Setelah melompati `sleep()`, eksekusi berlanjut ke rutin pembacaan byte terenkripsi dan pembentukan buffer string flag yang langsung dicetak ke konsol via fungsi cetak format (`puts`/`printf`).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Inspeksi tipe berkas biner:
   ```bash
   file gdbme
   # gdbme: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, not stripped
   ```
2. Analisis disasembli fungsi `main` melalui GDB:
   ```bash
   gdb -batch -ex "disas main" ./gdbme
   ```
   Ditemukan instruksi:
   ```asm
   0x0000000000001325 <+94>:  mov    edi, 0x186a0
   0x000000000000132a <+99>:  call   0x10d0 <sleep@plt>
   0x000000000000132f <+104>: mov    eax, 0x0
   ```
3. Pasang breakpoint di instruksi panggilan `sleep` (`main+99` = `0x132a`), jalankan program, dan lompat langsung ke `main+104` (`0x132f`):
   ```bash
   gdb -batch -ex "break *(main+99)" -ex "run" -ex "jump *(main+104)" ./gdbme
   ```
4. Output eksekusi mencetak token penyelesaian resmi:
   ```text
   Breakpoint 1, 0x000055555555532a in main ()
   academy{d3bugg3r_dr1v3_4cc75120}
   ```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{d3bugg3r_dr1v3_4cc75120}`
- **Verifikasi:** Endpoint REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 273, "flag": "academy{d3bugg3r_dr1v3_4cc75120}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Manipulasi Register & Alur Eksekusi ($rip manipulation):** Dalam modul *Binary Analysis & Reverse Engineering* LKS Cyber Security, kemampuan mengendalikan alur program tanpa mengubah biner di disk (*patching*) merupakan keterampilan vital saat menganalisis malware yang memiliki mekanisme *anti-analysis stall/sleep* untuk menghindari analisis sandbox.
- **Implementasi Anti-Debugging & Integrity Checks:** Dari perspektif defensif, aplikasi yang menangani data sensitif wajib menerapkan mekanisme proteksi biner seperti deteksi ptrace (`ptrace(PTRACE_TRACEME, 0, 1, 0)`), verifikasi integritas kode melalui checksum halaman memori, dan penyusutan simbol ekspor (*stripping*) guna mempersulit rekayasa balik.
