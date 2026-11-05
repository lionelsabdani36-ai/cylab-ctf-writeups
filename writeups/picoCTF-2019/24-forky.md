# Writeup: Forky (Challenge ID: 24)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Process Concurrency & Shared Memory
- **Difficulty:** Hard
- **Author:** Samuel
- **Event:** picoCTF 2019
- **Points:** 500
- **Flag:** `academy{-721750240}`

---

## Problem Statement & Scope
Diberikan biner ELF 32-bit x86 bernama `vuln`. Analis diminta untuk mengidentifikasi nilai integer 32-bit terakhir yang diteruskan sebagai argumen fungsi `doNothing()`. Analisis dilakukan terhadap biner native Linux tanpa stripping simbol untuk merekonstruksi alur inter-process communication (IPC) dan penanganan memori bersama (shared memory).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Mekanisme Shared Memory POSIX via `mmap`:**
   - Program memanggil fungsi sistem `mmap(NULL, 4, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0)`.
   - Flag `MAP_SHARED` (`0x01`) digabungkan dengan `MAP_ANONYMOUS` (`0x20`) menghasilkan nilai flag numerik `0x21`.
   - Tidak seperti pemetaan privat (`MAP_PRIVATE`), modifikasi terhadap wilayah memori `MAP_SHARED` terlihat oleh semua proses turunan (child processes) yang mewarisi pemetaan tersebut setelah pemanggilan fungsi `fork()`.
   
2. **Eksponensial Forking & Konkurensi Proses:**
   - Program memanggil instruksi `fork()` sebanyak 4 kali secara berurutan tanpa penanganan percabangan kondisi kembalian (return value check):
     $$N_{\text{proses}} = 2^4 = 16\text{ proses}$$
   - Setiap proses mengeksekusi instruksi pembacaan nilai dari pointer memori bersama, menambahkan nilai konstan, dan menyimpannya kembali ke alamat yang sama:
     $$\text{accumulator} = \text{accumulator} + \text{0x499602d2}$$

3. **Signed Integer Wrap-Around (Dua Komplemen):**
   - Nilai awal memori diinisialisasi ke `0x3b9aca00` (1.000.000.000 desimal).
   - Penambahan nilai konstan `0x499602d2` (1.234.567.890 desimal) sebanyak 16 kali menghasilkan nilai total melampaui batas maksimum integer 32-bit bertanda (`INT32_MAX = 2.147.483.647`).
   - Sesuai standar arsitektur x86 dan representasi Two's Complement, overflow terjadi secara deterministik dan bit paling signifikan (MSB / sign bit) bernilai 1, merepresentasikan bilangan negatif.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Statis Disassembly x86 (`objdump -d -M intel vuln`):**
   - Pada `main`, inisialisasi parameter:
     - `DWORD PTR [ebp-0x14] = 0x3` (`PROT_READ | PROT_WRITE`)
     - `DWORD PTR [ebp-0x10] = 0x21` (`MAP_SHARED | MAP_ANONYMOUS`)
     - Panjang alokasi: `0x4` byte.
   - Pointer hasil alokasi `mmap` disimpan di `[ebp-0xc]`.
   - Inisialisasi isi pointer: `mov DWORD PTR [eax], 0x3b9aca00`.

2. **Tracing Rantai Eksekusi `fork()`:**
   - Terdapat 4 pemanggilan berturut-turut ke `call fork@plt`.
   - Pohon proses menduplikasi dirinya menjadi 16 proses independen.
   - Masing-masing dari 16 proses tersebut membaca `[eax]` dan mengeksekusi:
     ```assembly
     lea edx, [eax + 0x499602d2]
     mov DWORD PTR [eax], edx
     ```
   - Kemudian setiap proses meneruskan nilai `[eax]` ke fungsi `doNothing(int arg)`.

3. **Kalkulasi Matematis Deterministik:**
   $$\text{Total} = 1.000.000.000 + (16 \times 1.234.567.890)$$
   $$1.000.000.000 + 19.753.086.240 = 20.753.086.240$$
   $$\text{Total} \pmod{2^{32}} = 20.753.086.240 \pmod{4.294.967.296} = 3.573.217.056 = \text{0xd4faf720}$$
   - Konversi nilai heksadesimal `0xd4faf720` ke 32-bit signed integer:
     $$3.573.217.056 - 4.294.967.296 = -721.750.240$$

4. **Validasi Solver Reproduktif:**
   ```bash
   python3 scripts/solve_24_forky.py
   ```
   Output: `Flag: academy{-721750240}`

---

## Flag & Verifikasi
- **Flag:** `academy{-721750240}`
- **Verifikasi:** Endpoint REST API CyLab `POST /api/submissions/` merespons status HTTP 201 Created dengan hasil validasi `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Takeaway LKS:** Peserta kompetisi LKS Cyber Security bidang Reverse Engineering harus memahami mekanisme IPC Linux (khususnya flag `mmap` shared vs private) dan perilaku proses konkuren. Kegagalan memahami batas overflow integer dan semantik proses dapat mengakibatkan salah tafsir dalam analisis artefak biner.
- **Mitigasi Defensif:** Dalam pemrograman sistem bersama (shared memory multi-processing), akses baca-tulis harus dilindungi menggunakan primitif sinkronisasi seperti mutex, semafor POSIX (`sem_wait`/`sem_post`), atau operasi atomik (`std::atomic`). Selain itu, kalkulasi aritmetika yang dapat melampaui rentang tipe data harus divalidasi dengan safe math library atau compiler flag `-ftrapv`.
