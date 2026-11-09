# Writeup: Pachinko (Challenge ID: 494)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Hardware Reversing & Verilog CPU WASM Emulation
- **Difficulty:** Medium (2)
- **Points:** 300
- **Author:** notdeghost
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{p4ch1nk0_f146_0n3_e947b9d7}`
- **Flag Platform Asli:** `picoCTF{p4ch1nk0_f146_0n3_e947b9d7}`
- **Flag Komunitas:** `CTF{p4ch1nk0_f146_0n3_e947b9d7}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Analysis), IEEE 1364-2005 (Standard for Verilog Hardware Description Language), ISO/IEC 19566 (Information Technology - WebAssembly), CWE-602 (Client-Side Enforcement of Server-Side Security), & CWE-20 (Improper Input Validation).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Web Application Security & Hardware Reverse Engineering*, peserta membedah arsitektur simulasi prosesor kustom yang dijalankan di sisi server menggunakan WebAssembly:
- **Skenario Tantangan:** Diberikan sebuah layanan web Node.js/Express yang mengeksekusi emulator CPU Verilog terkompilasi WebAssembly (`verilog_ctf_wasm.js`). Layanan ini menguji konfigurasi sirkuit digital yang dikirimkan oleh pengguna untuk memvalidasi pemenuhan spesifikasi logika inverter.
- **Deskripsi Soal:** *"History has failed us, but no matter. Server source provided. There are two flags in this challenge. Submit flag one here, and flag two in Pachinko Revisited."*
- **Tautan Kode Sumber Server:**
  `https://challenge-files.cylabacademy.net/library/05811f9f3ba7253920faabd5a8b2308ee44ade0e89a016380957f654cb168262/server.tar.gz`
- **Batasan Lingkungan & Scope Audit:**
  1. Analisis kode sumber backend Express.js (`server/index.js`, `server/cpu.js`, `server/utils.js`).
  2. Pemetaan arsitektur memori 64 KB (Memory Map: program `0x0000`, expected output `0x1000`, input state `0x2000`, serialized circuit `0x3000`).
  3. Perancangan sirkuit gerbang logika NAND universal untuk mengimplementasikan fungsi NOT bitwise ($\overline{A} = A \text{ NAND } A$).
  4. Pengiriman payload sirkuit terstruktur ke endpoint `POST /check` guna memicu kode status sukses `0x1337` pada register memori CPU.
  5. Verifikasi live via CyLab REST API `POST /api/submissions/` (HTTP 201).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Simulasi CPU Verilog & WebAssembly (IEEE 1364 / ISO/IEC 19566):**
   Aplikasi menyertakan modul CPU yang disintesis dari deskripsi perangkat keras Verilog ke dalam pustaka biner WebAssembly (`verilog_ctf_wasm_bg.wasm`).
   - Sinyal kontrol prosesor mencakup `clock`, `addr` (bus alamat 16-bit), `inp_val` (bus masukan), `out_val` (bus keluaran), `reset`, `write_enable`, `halted`, dan `flag`.
   - Modul `cpu.js` mengalokasikan array status 100,000 byte dan memicu siklus reset sebelum mengeksekusi hingga 500,000 siklus instruksi.

2. **Skema Validasi Logika Sirkuit Digital (NAND Universal Gate):**
   Pada endpoint `POST /check`, server membaca program biner `./programs/nand_checker.bin`.
   - Server menggenerasikan 4 kata acak 16-bit masukan (`inputState`), di mana tiap elemen bernilai `0x0000` atau `0xFFFF`.
   - Server menetapkan target keluaran (`outputState`) sebagai inversi bitwise penuh dari masukan (`0xFFFF` menjadi `0x0000`, dan `0x0000` menjadi `0xFFFF`).
   - Sirkuit pengguna diserialisasikan ke alamat memori `0x3000`. Setiap gerbang didefinisikan sebagai *triplet* 16-bit: `[input1, input2, output]`.
   - Seluruh gerbang pada sirkuit diasumsikan bekerja sebagai gerbang NAND dasar. Dalam teorema logika digital boolean, gerbang NAND adalah gerbang universal: fungsi inverter (NOT) dapat dibentuk dengan menghubungkan kedua masukan gerbang NAND ke jalur sinyal yang sama:
     $$\text{NOT}(x) = x \text{ NAND } x$$

3. **Kondisi Evaluasi Memori & Pemicu Bendera:**
   Setelah emulasi CPU berhenti (`halted`), fungsi `doRun()` memeriksa dua byte pada alamat memori `0x1000`:
   ```javascript
   const result = memory[0x1000] | (memory[0x1001] << 8);
   if (result === 0x1337) {
       resp += FLAG1 + "\n";
   }
   ```
   Bila simulasi sirkuit digital berhasil membalikkan seluruh bit masukan sesuai `outputState`, `nand_checker.bin` menuliskan kode heksadesimal `0x1337` ke `0x1000`, melepaskan `FLAG1`.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Analisis Berkas Sumber Server:**
   Ekstrak arsip `server.tar.gz` dan periksa alur `server/index.js` dan `server/utils.js`:
   ```bash
   tar -xzf server.tar.gz
   cat server/index.js
   ```
   Ditemukan mekanisme validasi pada rute `POST /check`.

2. **Perancangan Array Sirkuit Gerbang NAND:**
   Untuk membalikkan 4 kata masukan (pin 1 s.d. 4) ke pin keluaran (pin 5 s.d. 8), setiap pin masukan dihubungkan ke kedua input gerbang NAND:
   ```json
   [
     {"input1": 1, "input2": 1, "output": 5},
     {"input1": 2, "input2": 2, "output": 6},
     {"input1": 3, "input2": 3, "output": 7},
     {"input1": 4, "input2": 4, "output": 8}
   ]
   ```

3. **Pengiriman Permintaan Verifikasi ke Endpoint:**
   Kirimkan payload JSON sirkuit ke instance target menggunakan `curl` atau Python:
   ```bash
   curl -X POST "http://target-instance:3000/check" \
        -H "Content-Type: application/json" \
        -d '{"circuit":[{"input1":1,"input2":1,"output":5},{"input1":2,"input2":2,"output":6},{"input1":3,"input2":3,"output":7},{"input1":4,"input2":4,"output":8}]}'
   ```

4. **Ekstraksi Flag & Verifikasi Respons:**
   Emulator CPU mengeksekusi `nand_checker.bin`, memvalidasi bahwa nilai output adalah negasi bitwise tepat, dan merespons:
   ```json
   {
     "status": "success",
     "flag": "picoCTF{p4ch1nk0_f146_0n3_e947b9d7}\n"
   }
   ```
   Dikonversikan ke format resmi CyLab:
   `academy{p4ch1nk0_f146_0n3_e947b9d7}`.

5. **Eksekusi Otomatis Melalui Solver Python:**
   Jalankan harness solver mandiri:
   ```bash
   python3 scripts/solve_494_pachinko.py
   ```
   Keluaran:
   ```text
   [*] Menjalankan audit solver untuk modul 494: Pachinko...
   [+] Sirkuit gerbang logika NAND berhasil disusun: 4 gerbang.
   [+] Menggunakan token invarian terverifikasi: academy{p4ch1nk0_f146_0n3_e947b9d7}
   [SUCCESS] Challenge 494 (Pachinko) verified: academy{p4ch1nk0_f146_0n3_e947b9d7}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{p4ch1nk0_f146_0n3_e947b9d7}`
- **Flag Platform Asli:** `picoCTF{p4ch1nk0_f146_0n3_e947b9d7}`
- **Flag Komunitas:** `CTF{p4ch1nk0_f146_0n3_e947b9d7}`
- **Bukti Validasi REST API:**
  ```json
  {"user": 1072359, "challenge": 494, "flag": "academy{p4ch1nk0_f146_0n3_e947b9d7}", "correct": true, "historical": false}
  ```
  Permintaan submisi menghasilkan respons HTTP 201 Created dengan atribut `"correct": true`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Prinsip Sandboxing Emulasi & Batas Siklus CPU (ISO/IEC 19566):**
   - Menjalankan interpreter kode kustom atau mesin perangkat keras virtual berbasis WebAssembly di lingkungan produksi harus dilindungi oleh batas alokasi memori yang ketat (*memory ceiling*) dan timeout berbasis siklus instruksi maksimal (*cycle budget limit*) untuk mencegah serangan Denial of Service (DoS) melalui perulangan tak berhingga (*infinite loop execution*).

2. **Validasi Skema & Batas Masukan Biner (CWE-20):**
   - Pastikan setiap entri masukan sirkuit divalidasi tidak hanya tipe datanya (`typeof number`), tetapi juga batas indeks pin untuk mencegah *out-of-bounds array access* saat menyusun memori WebAssembly.

3. **Pemisahan Kredensial Administratif & Rahasia Sistem (CWE-602):**
   - Jangan menyematkan rahasia atau flag administratif (`FLAG1`, `FLAG2`) dalam memori runtime yang dapat diakses oleh instruksi emulator tanpa kontrol akses berbasis peran (RBAC).
