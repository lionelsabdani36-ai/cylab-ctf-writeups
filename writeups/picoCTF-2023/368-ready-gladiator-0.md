# 368 - Ready Gladiator 0 (Reverse Engineering, picoCTF 2023, Medium)

## Challenge Metadata
- ID: 368 | Event: picoCTF 2023 | Author: CyLab Academy
- Category: Reverse Engineering | Difficulty: Medium (2) | Points: 200
- Flag: `academy{h3r0_t0_z3r0_4m1r1gh7_1c8e5812}`

## Problem Statement & Scope
Tantangan menguji pemahaman peserta mengenai simulasi CoreWars dan sintaks Redcode. Peserta diminta merancang sebuah program petarung (warrior) yang dipertarungkan melawan warrior standar "Imp". Target spesifik dari tantangan ini adalah membuat warrior yang **selalu kalah (always loses)** dalam 100 ronde pertempuran tanpa pernah menghasilkan hasil seri (no ties).

## Teori & Akar Kerentanan (Root Cause)
1. **Mekanisme Eksekusi Mesin CoreWars (MARS Engine):**
   Dalam CoreWars, program dieksekusi di dalam memori melingkar (circular memory core). Setiap warrior memiliki antrean instruksi eksekusi.
2. **Kondisi Eliminasi Proses (Process Termination via DAT):**
   Instruksi `DAT #A, #B` (Data) tidak berisi kode operasi yang dapat dieksekusi oleh unit pemrosesan MARS. Ketika sebuah thread atau instruksi pointer warrior mengeksekusi instruksi `DAT`, thread tersebut secara otomatis dianggap mati (terminasi instan).
3. **Determinisme Hasil 100-0:**
   Warrior lawan "Imp" mengeksekusi `MOV 0, 1` yang terus menggandakan dirinya secara tak terbatas di memori. Jika warrior kita langsung mati pada siklus ke-1 karena instruksi `DAT #0, #0` tanpa pernah mengeksekusi instruksi pembagian proses atau modifikasi memori, lawan otomatis memenangkan ronde tersebut dengan skor mutlak 100 ronde kalah, 0 menang, 0 seri.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Lawan (Imp):**
   Berkas `imp.red` yang disediakan memiliki kode:
   ```redcode
   ;redcode
   ;name Imp Ex
   ;assert 1
   mov 0, 1
   end
   ```
2. **Konstruksi Warrior Bunuh Diri (Instant Death):**
   Menyusun kode Redcode minimal yang langsung mengeksekusi instruksi `dat` pada baris pertama:
   ```redcode
   ;redcode
   ;name Die
   ;assert 1
   dat #0, #0
   end
   ```
3. **Eksekusi TCP Socket:**
   Mengirimkan teks warrior ke port instans netcat:
   ```bash
   nc xebec.cylabacademy.net <port> < die.red
   ```
   Simulator CoreWars mengonfirmasi:
   `Warrior 1 wins: 0, Warrior 2 wins: 100, Ties: 0. You did it!`
   dan memunculkan flag resmi.

## Script Reproduksi & PoC
Implementasi otomasi Python lengkap tersedia pada `scripts/solve_368_ready_gladiator_0.py`:
```python
import socket

PAYLOAD = b""";redcode
;name Die
;assert 1
dat #0, #0
end
"""

s = socket.create_connection(("xebec.cylabacademy.net", 32636), timeout=20)
s.sendall(PAYLOAD)
data = s.recv(4096)
print(data.decode())
```

## Mitigasi Defensif & Relevansi LKS Cyber Security
1. **Validasi Alur Logika Game/Engine:**
   Dalam pengujian sistem terdistribusi atau permainan berbasis rules engine, pembatasan input harus mencakup validasi terhadap skenario degenerate (program yang langsung bunuh diri atau sengaja mengalah untuk memanipulasi metrik rating/elo).
2. **Relevansi Modul LKS:**
   Materi ini melatih siswa dalam memahami arsitektur eksekusi instruksi assembly non-standar (Redcode/CoreWars), penanganan siklus eksekusi instruksi CPU virtual, dan otomatisasi input stream raw TCP socket.
