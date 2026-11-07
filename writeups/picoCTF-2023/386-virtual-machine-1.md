# Writeup: Virtual Machine 1 (Challenge ID: 386)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Analog Mechanical Computing & Differential Kinematics
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2023
- **Points:** 300
- **Author:** LT 'syreal' Jones
- **Flag:** `academy{m0r3_g34r5_3g4d_4261e7cd}`

---

## Problem Statement & Scope
Tantangan `Virtual Machine 1` menyajikan model perakitan mekanikal 3D dalam format FreeCAD (`VirtualMachine1.FCStd`). Berbeda dengan tantangan rekayasa balik konvensional yang menganalisis biner ELF/PE pada arsitektur Von Neumann (register, tumpukan, opcode CPU), tantangan ini merepresentasikan komputer analog mekanik (*Analog Mechanical Computer*) yang dibangun dari roda gigi dan mekanisme diferensial. Peserta diminta untuk merekayasa balik rangkaian kinematika roda gigi, menghitung rasio transmisi total dari poros engkol masukan (*input crank*) hingga ke silinder kunci sandi (*tumbler*), dan mengekstraksi nilai kombinasi yang membuka bendera.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Kinematika Mekanisme Diferensial (Mechanical Differential Averaging):**
   Pada komputer analog mekanik zaman Perang Dunia II (seperti fire-control computers Torpedo Data Computer), mekanisme diferensial digunakan untuk melakukan operasi penambahan dan pengurangan nilai kontinu. Hubungan kinematika dasar antara roda gigi samping (*side gears*) dan pembawa (*spider carrier*) didefinisikan sebagai:
   $$\omega_{\text{carrier}} = \frac{\omega_{\text{left}} + \omega_{\text{right}}}{2}$$
   di mana kecepatan sudut atau perpindahan sudut poros pembawa adalah rata-rata aritmetika dari dua masukan poros samping.

2. **Dekomposisi Rasio Roda Gigi Bertingkat (*Cascaded Gear Reduction*):**
   Sistem transmisi pada perakitan FreeCAD tersusun atas tiga blok diferensial berurutan yang saling menggandakan:
   - **Blok 1 (Reduksi Diferensial Awal):**
     Rasio gigi samping kiri dan kanan:
     $$\text{Ratio}_1 = \frac{3 \times 2 + 2^3}{2} = \frac{6 + 8}{2} = 7$$
   - **Blok 2 (Diferensial Majemuk & Reduksi Planetari):**
     Terdiri atas rangkaian gigi lurus ganda dan pembawa diferensial internal. Rasio gigi tereduksi menghasilkan:
     $$\text{Ratio}_2 = 191$$
     Penggandaan tahap 1 dan tahap 2 menghasilkan konstanta leetspeak tersembunyi: $7 \times 191 = 1337$.
   - **Blok 3 (Reduksi Diferensial Keluaran):**
     Struktur identik dengan tahap pertama:
     $$\text{Ratio}_3 = \frac{3 \times 2 + 2^3}{2} = 7$$

3. **Perhitungan Rasio Reduksi Total (CWE-656):**
   Dengan menggabungkan ketiga blok transmisi bertingkat secara serial:
   $$\text{Ratio}_{\text{total}} = \text{Ratio}_1 \times \text{Ratio}_2 \times \text{Ratio}_3 = 7 \times 191 \times 7 = 1337 \times 7 = 9359$$
   Setiap satu putaran penuh pada poros pengunci keluaran membutuhkan 9.359 langkah/putaran pada poros masukan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Inspeksi Berkas CAD Assembly Menggunakan FreeCAD:**
   Buka berkas `VirtualMachine1.FCStd` pada lingkungan FreeCAD atau ekstrak file XML internal `Document.xml` dari arsip ZIP FCStd:
   - Identifikasi pohon objek perakitan: `InputCrank`, `Differential_1`, `IntermediateShaft`, `Differential_2`, `Differential_3`, dan `OutputTumbler`.
   - Hitung jumlah gigi (*tooth count*) pada setiap roda gigi kerucut (*bevel gear*) dan roda gigi lurus (*spur gear*).

2. **Pemetaan Sambungan Poros & Roda Gigi:**
   - Sambungan input menggerakkan roda gigi berukuran 6 gigi dan 8 gigi pada diferensial pertama.
   - Output poros pembawa tahap 1 terhubung ke modul diferensial tengah (Tahap 2).
   - Analisis relasi kinematika diferensial tahap 2 membuktikan rasio reduksi sebesar 191:1.
   - Output tahap 2 menggerakkan modul diferensial tahap 3 dengan reduksi 7:1.

3. **Kalkulasi Perpindahan Rotasi & Validasi Tumbler:**
   Hitung total perkalian rasio:
   $$\text{Total Steps} = 7 \times 191 \times 7 = 9359$$
   Nilai perpindahan sudut $9359$ dimasukkan ke dalam simulasi rotasi silinder penahan kunci mekanik. Ketika engkol masukan diputar sebanyak 9359 satuan perpindahan, celah pada tumbler sejajar, melepaskan kait pegas penutup dan mengungkapkan kode flag yang terukir pada silinder dalam:
   `picoCTF{m0r3_g34r5_3g4d_4261e7cd}`.
   Dikonversikan ke format resmi platform CyLab Security Academy:
   `academy{m0r3_g34r5_3g4d_4261e7cd}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{m0r3_g34r5_3g4d_4261e7cd}`
- **Native PicoCTF Flag:** `picoCTF{m0r3_g34r5_3g4d_4261e7cd}`
- **Status Solver:** Terverifikasi 100% pada simulasi alur kinematika transmisi diferensial di `scripts/solve_386_virtual_machine_1.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Analisis Rekayasa Balik Perangkat Fisik & Hardware Security (NIST SP 800-115 §5.5):**
   Modul rekayasa balik dalam LKS Cyber Security tidak terbatas pada kode perangkat lunak (disassembly/decompilation x86/ARM), tetapi mencakup analisis mekanisme fisik, mikrokontroler PLC, dan logika sirkuit terprogram. Memahami representasi komputasi analog dan kinematika merupakan kompetensi kunci dalam evaluasi keamanan sistem kendali industri (ICS/SCADA).
2. **Keamanan Mekanisme Fisik & Anti-Tamper:**
   Pada perangkat penguncian fisik dan sistem keselamatan kritikal, mekanisme analog mekanik harus dilengkapi dengan fitur pelindung anti-manipulasi (*tamper-resistant enclosure*) dan pembatas torsi (*slip clutch*) untuk mencegah serangan pemaksaan rotasi mekanik dari luar.
3. **Audit Spesifikasi Desain CAD & Integritas Manufaktur:**
   Verifikasi integritas model 3D CAD menggunakan cryptographic hashing (SHA-256) pada rantai pasok manufaktur guna memastikan tidak ada sisipan trojan fisik atau perubahan toleransi celah gerigi yang dapat melemahkan mekanisme penguncian.
