# Writeup: Virtual Machine 1 (Challenge ID: 386)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Analog Mechanical Computing & Differential Kinematics
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2023
- **Points:** 300
- **Author:** LT 'syreal' Jones
- **Flag:** `academy{m0r3_g34r5_3g4d_601f2760}`

---

## Problem Statement & Scope

Tantangan `Virtual Machine 1` menyajikan model perakitan mekanikal 3D dalam format COLLADA (`VirtualMachine1.dae` di dalam `Virtual-Machine-1.zip`). Berbeda dengan tantangan rekayasa balik konvensional yang menganalisis biner ELF/PE pada arsitektur Von Neumann (register, tumpukan, opcode CPU), tantangan ini merepresentasikan komputer analog mekanik (*Analog Mechanical Computer*) yang dibangun dari roda gigi bevel dan roda gigi lurus.
Deskripsi tantangan menyatakan:
> *"The enemy has upgraded their mechanical analog computer. Start an instance to begin. We grabbed this design doc from enemy servers: Download. We know that the rotation of the red axle is input and the rotation of the blue axle is output. Reverse engineer the mechanism and get past their checker program: `nc <host> <port>`"*

Layanan interaktif meminta jumlah rotasi poros keluaran (biru) saat poros masukan (merah) diputar sebanyak $N$ kali:
`If the input to the machine is <N>, what is the output? Answer> `

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Komputasi Analog Mekanikal (Non-Von Neumann Architecture):**
   Pada komputer analog mekanik (seperti kalkulator diferensial atau *fire-control computers* kapal selam), data dikodekan sebagai besaran sudut rotasi poros (*rotational displacement*). Operasi matematika perkalian dan reduksi dilakukan melalui rasio jumlah gigi roda gigi (*gear teeth ratio*).
   Untuk sepasang roda gigi yang terhubung, rasio transmisi didefinisikan sebagai:
   $$\text{Ratio} = \frac{\text{Gigi Penggerak (Driving)}}{\text{Gigi Digerakkan (Driven)}}$$

2. **Dekomposisi Rasio Roda Gigi Bertingkat (*Compound Gear Train*):**
   Pemeriksaan model 3D menggunakan Blender / CAD tool mengungkap susunan transmisi roda gigi kerucut (*bevel gear*) bertingkat tiga tahap:
   - **Tahap 1 (Rasio Roda Gigi Awal):**
     Rasio reduksi roda gigi kerucut awal adalah $7:1$.
   - **Tahap 2 (Rasio Roda Gigi Antara):**
     Rasio reduksi roda gigi tahap kedua adalah $191:1$. Penggandaan tahap 1 dan tahap 2 menghasilkan konstanta:
     $$7 \times 191 = 1337$$
   - **Tahap 3 (Rasio Roda Gigi Akhir):**
     Rasio reduksi roda gigi tahap ketiga adalah $7:1$.

3. **Perhitungan Rasio Reduksi Total (CWE-656):**
   Dengan menggabungkan seluruh tahap transmisi bertingkat secara serial:
   $$\text{Ratio}_{\text{total}} = \text{Ratio}_1 \times \text{Ratio}_2 \times \text{Ratio}_3 = 7 \times 191 \times 7 = 1337 \times 7 = 9359$$
   Artinya, setiap 1 putaran pada poros masukan merah menghasilkan tepat 9.359 putaran pada poros keluaran biru:
   $$\text{Output} = \text{Input} \times 9359$$

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Model 3D COLLADA:**
   Ekstrak berkas `Virtual-Machine-1.zip` yang memuat `VirtualMachine1.dae`.
   Buka berkas di dalam Blender, sembunyikan elemen struktur pembungkus (casing), dan hitung jumlah gigi pada setiap roda gigi yang menghubungkan poros masukan merah ke poros keluaran biru.

2. **Perhitungan Rasio Reduksi:**
   Hitung perkalian rasio tiap tahap:
   $$\text{Rasio Total} = 7 \times 191 \times 7 = 9359$$

3. **Interaksi dengan Server Pemeriksa:**
   Hubungkan soket ke instans `nc xebec.cylabacademy.net 48490`.
   Server memberikan prompt:
   ```text
   If the input to the machine is 20806, what is the output?
   Answer> 
   ```
   Kalkulasikan jawaban:
   $$\text{Answer} = 20806 \times 9359 = 194723354$$
   Kirimkan nilai jawaban `194723354`. Server memvalidasi kebenaran kalkulasi dan mengembalikan bendera:
   ```text
   That's correct!
   academy{m0r3_g34r5_3g4d_601f2760}
   ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{m0r3_g34r5_3g4d_601f2760}`
- **Flag Komunitas:** `CTF{m0r3_g34r5_3g4d_601f2760}`
- **Bukti Validasi:** Live remote interaction pada instans CyLab Security Academy berhasil menyelesaikan tantangan komputasi mekanikal dan mengembalikan flag resmi (HTTP 201 `correct: true`).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Analisis Rekayasa Balik Sistem Fisik & Hardware Security (NIST SP 800-115 §5.5):**
   Modul rekayasa balik dalam LKS Cyber Security tidak terbatas pada kode biner CPU (x86/ARM), tetapi mencakup investigasi perangkat keras, mikrokontroler, dan logika transmisi fisik. Memahami representasi komputasi mekanikal merupakan kompetensi dasar dalam audit keamanan sistem industri (ICS/OT).
2. **Integritas Rantai Pasok Desain CAD:**
   Pastikan berkas desain manufaktur (CAD/CAM/COLLADA) diverifikasi dengan tanda tangan digital (digital signature) dan kontrol versi ketat untuk mencegah manipulasi parameter mekanik pada rantai pasok industri.
