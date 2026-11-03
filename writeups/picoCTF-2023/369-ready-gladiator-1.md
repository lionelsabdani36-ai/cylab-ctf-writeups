# 369 - Ready Gladiator 1 (Reverse Engineering, picoCTF 2023, Medium)

## Challenge Metadata
- ID: 369 | Event: picoCTF 2023 | Author: CyLab Academy / picoCTF
- Category: Reverse Engineering | Difficulty: Medium (2) | Points: 200
- Flag: `academy{1mp_1n_7h3_cr055h41r5_db62826b}`

## Problem Statement & Scope
Tantangan menyediakan layanan interaktif CoreWars MARS (*Memory Array Redcode Simulator*) yang berjalan pada port TCP lab on-demand (`chatelaine.cylabacademy.net:port`). Pengguna diminta untuk membuat program warrior Redcode yang mampu mengalahkan program lawan (`Imp`) minimal 1 kali dari total 100 ronde pertempuran memori untuk memperoleh flag resmi.

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Arsitektur CoreWars Virtual Machine (Redcode-94):**
   CoreWars mengeksekusi instruksi di dalam ring buffer memori sirkular (*core*). Setiap siklus, MARS simulator mengeksekusi satu instruksi dari antrean proses warrior yang aktif.
2. **Karakteristik Perilaku Lawan (Imp):**
   Program lawan `imp.red` didefinisikan sebagai:
   ```redcode
   ;redcode
   ;name Imp
   ;assert 1
   mov 0, 1
   end
   ```
   Instruksi `mov 0, 1` menyalin instruksi pada posisi offset 0 ke offset +1, bergerak maju menimpa sel memori secara sekuensial. Imp tidak memiliki pertahanan dan sangat rentan terhadap jebakan data (*data traps*).
3. **Mekanisme Terminasi Proses MARS (`DAT` Bombs):**
   Dalam spesifikasi arsitektur Redcode, jika suatu process pointer melangkah ke instruksi `DAT` (misal `dat #0, #0`), instruksi tersebut dianggap bukan executable opcode. Simulator langsung menyingkirkan (*kill/terminate*) thread tersebut dari antrean siklus eksekusi.
4. **Strategi Bomber / Dwarf:**
   Dengan memanfaatkan pola *Dwarf* klasik:
   ```redcode
   start add #4, bomb
   mov bomb, @bomb
   jmp start
   bomb dat #0, #0
   end
   ```
   Warrior secara periodik menembakkan `dat` bombs ke lokasi berjarak lompatan 4 sel. Ketika thread Imp bergerak menyalin memori dan menabrak instruksi `dat` yang telah dijatuhkan Dwarf, Imp mati seketika sementara proses Dwarf tetap aktif, menghasilkan kemenangan (*win*) bagi Warrior 1.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Protokol & Entry Point:**
   Layanan meminta submission file warrior Redcode dan mengevaluasinya hingga token `end`. Sangat krusial agar instruksi pertama yang dieksekusi adalah `start` (instruksi penjumlahan), bukan deklarasi `dat #0, #0`. Jika `dat` diletakkan di instruksi pertama tanpa penunjuk start eksplisit, warrior kita sendiri yang akan mati seketika pada siklus 0.
2. **Konstruksi Kode Redcode:**
   Menyusun warrior Dwarf dengan tata letak memori:
   ```redcode
   ;redcode
   ;name Dwarf
   ;assert 1
   start add #4, bomb
   mov bomb, @bomb
   jmp start
   bomb dat #0, #0
   end
   ```
3. **Pengiriman Payload via TCP Socket:**
   Mengirimkan kode Redcode ke instance on-demand CyLab (`chatelaine.cylabacademy.net:25344`).
4. **Hasil Simulasi & Ekstraksi Flag:**
   Hasil 100 ronde pertarungan MARS:
   ```text
   Rounds: 100
   Warrior 1 wins: 28
   Warrior 2 wins: 0
   Ties: 72
   You did it!
   academy{1mp_1n_7h3_cr055h41r5_db62826b}
   ```
   Target menang minimal 1 kali terpenuhi (28 kemenangan), dan server mencetak token flag resmi.

## Flag & Verifikasi
- **Flag Resmi:** `academy{1mp_1n_7h3_cr055h41r5_db62826b}`
- **Bukti Validasi REST API:** `POST /api/submissions/` mengembalikan `HTTP 201 Created` dengan `correct: true`.

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Eksekusi Sandboxed & Virtual Machine Architecture:**
   Pada lomba LKS Cyber Security (bidang Reverse Engineering / Binary Analysis), pemahaman mengenai arsitektur mesin virtual khusus (custom bytecode / register machines / circular execution buffer) sangat penting saat menghadapi software packer atau emulator-based malware (e.g. VMProtect / OLLVM).
2. **Input Validation pada Parser Assembly Edukatif:**
   Layanan eksekusi kode dinamis harus membatasi waktu eksekusi CPU, kedalaman loop, serta melakukan isolasi proses (sandboxing melalui cgroups / seccomp / ephemeral containers) untuk mencegah denotasi kode berbahaya pada server host penguji.
