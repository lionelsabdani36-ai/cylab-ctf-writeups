# 370 - Ready Gladiator 2 (Reverse Engineering, picoCTF 2023, Medium)

## Challenge Metadata
- ID: 370 | Event: picoCTF 2023 | Author: CyLab Academy / picoCTF
- Category: Reverse Engineering | Difficulty: Medium (2) | Points: 200
- Flag: `academy{d3m0n_3xpung3r_2e26bfb2}`

## Problem Statement & Scope
Tantangan menyediakan lingkungan simulasi CoreWars MARS interaktif via koneksi TCP (`xebec.cylabacademy.net:port`). Berbeda dengan tantangan sebelumnya yang hanya mewajibkan kemenangan parsial, Ready Gladiator 2 mewajibkan pembuatan warrior Redcode yang mampu mengalahkan program lawan (`Imp`) dalam seluruh 100 ronde pertempuran tanpa ada hasil seri (*ties*) maupun kekalahan (100% win rate sweep).

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Analisis Keterbatasan Bomber Tradisional (Dwarf):**
   Strategi *Dwarf* (bomber) menembakkan instruksi `dat #0, #0` dengan stride tetap (misal setiap 4 alamat memori). Meskipun menghasilkan persentase kemenangan tertentu, penempatan acak offset awal antar-warrior di buffer memori sirkular (ring core buffer berukuran 8000 instruksi) sering kali menyebabkan Imp bereplikasi ke arah berlawanan dan bertahan hingga batas maksimum siklus eksekusi simulator tercapai, sehingga menghasilkan banyak ronde imbang (*ties*).
2. **Konsep Imp-Gate & Pre-Decrement Addressing:**
   Dalam arsitektur Redcode (ICWS-88 / ICWS-94), simbol `<` merepresentasikan *indirect pre-decrement addressing mode*.
   Instruksi:
   ```redcode
   jmp 0, <-2
   ```
   Bekerja dengan dua aksi simultan pada setiap siklus eksekusi:
   - **B-field pointer manipulation:** Melakukan pengurangan (*decrement*) nilai field pada offset -2 sebelum pembacaan.
   - **Self-contained infinite loop:** Melompat kembali ke instruksi saat ini (`jmp 0`), menjaga kontinuitas proses Warrior 1 agar tidak pernah mati.
3. **Mekanisme Netralisasi Imp:**
   Lawan (`Imp`) mengeksekusi instruksi replikasi diri `mov 0, 1` yang bergerak sekuensial langkah demi langkah menyusuri memori. Karena warrior kita secara berkesinambungan mendekremen sel memori tepat di belakangnya (`<-2`), instruksi Imp yang menyusup ke area tersebut dimodifikasi nilai opcodenya sebelum dapat dieksekusi. Ketika Imp menabrak instruksi yang rusak atau instruksi `DAT` tak tervalidasi yang dihasilkan proses dekremen, thread eksekusi Imp langsung diterminasi oleh simulator MARS.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Penyusunan Kode Minimalis Imp-Gate:**
   Menggunakan konstruksi warrior satu baris:
   ```redcode
   ;redcode
   ;name Imp Killer
   ;assert 1
   jmp 0, <-2
   end
   ```
2. **Koneksi dan Transmisi Payload via Socket:**
   Menghubungkan socket client ke target lab on-demand CyLab (`xebec.cylabacademy.net:40754`).
3. **Hasil Simulasi Pertarungan MARS:**
   Evaluasi otomatis 100 ronde pertempuran menghasilkan skor mutlak:
   ```text
   Rounds: 100
   Warrior 1 wins: 100
   Warrior 2 wins: 0
   Ties: 0
   You did it!
   academy{d3m0n_3xpung3r_2e26bfb2}
   ```
   Seluruh 100 ronde dimenangkan telak oleh Warrior 1 tanpa satupun tie.

## Flag & Verifikasi
- **Flag Resmi:** `academy{d3m0n_3xpung3r_2e26bfb2}`
- **Bukti Validasi REST API:** `POST /api/submissions/` mengembalikan respon `HTTP 201 Created` dengan `correct: true`.

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Analisis Modifikasi Memori Runtime (Self-Modifying Code):**
   Eksperimen ini memberikan pemahaman mendalam tentang bagaimana proses dalam memori bersama dapat memodifikasi instruksi proses lain secara deterministik. Pada kompetisi LKS Cyber Security, kemampuan menganalisis instruksi self-modifying code sangat krusial saat membedah teknik pertahanan malware (*anti-analysis*, *in-memory packing*, dan *runtime patching*).
2. **Isolasi Memori & Proteksi Ring Privilese (Hardware W^X & DEP):**
   Pada sistem operasi modern, kerentanan modifikasi instruksi lintas proses dicegah secara arsitektural melalui *Virtual Memory Space Isolation* (MMU), segmentasi memori, serta proteksi *Data Execution Prevention* (DEP / W^X) di mana memori yang dapat ditulisi (*writable*) tidak boleh dapat dieksekusi (*executable*).
