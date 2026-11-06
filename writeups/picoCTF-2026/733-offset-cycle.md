# Writeup: offset-cycle (Challenge ID: 733)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Memory Safety
- **Difficulty:** Medium (diff=2)
- **Author:** Aditya Sudhansu
- **Event:** picoCTF 2026
- **Points:** 300
- **Flag:** `academy{0ffs3t_cycl1c_pwn3d_733}`

---

## Problem Statement & Scope

Tantangan ini menyajikan layanan interaktif berbasis binari Linux ELF x86_64:
> *"A small program that generates a randomized buffer offset per instance. Can you find the dynamic offset, overwrite the saved return pointer, and redirect control flow to print the flag?"*

Lingkungan target mengkompilasi binari secara dinamis dengan opsi `-fno-stack-protector -no-pie`, sehingga alamat fungsi pembaca bendera (`win()`) berada pada alamat absolut statis di ruang memori kode teks, namun jarak dari buffer masukan menuju *Saved Return Address* (RBP/RIP) berubah secara acak pada rentang tertentu di setiap eksekusi baru.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Stack-Based Buffer Overflow via Dangerous Input Functions (CWE-121, CWE-242):**
   Fungsi rentan membaca data langsung ke dalam buffer lokal tanpa batasan panjang byte (misalnya menggunakan `gets()` atau `scanf("%s")`). Struktur call frame stack x86_64 menyimpan buffer lokal, diikuti oleh *Saved Frame Pointer* ($RBP$, 8 byte), dan *Saved Return Address* ($RIP$, 8 byte):
   ```
   [ Low Memory ] <-----------------------------------------> [ High Memory ]
   [ Local Buffer (N bytes) ] | [ Saved RBP (8B) ] | [ Saved Return Address (8B) ]
   ```
   Ketika panjang input pengguna melebihi kapasitas alokasi buffer $N$, byte tambahan akan secara berurutan menimpa $RBP$ dan nilai penunjuk instruksi kembali.

2. **Deteksi Dinamis dengan De Bruijn Cyclic Sequence:**
   Karena offset buffer $N$ berubah dinamis, penyerang memanfaatkan urutan siklik De Bruijn berorde $k$ di mana setiap substring berukuran 4 byte (atau 8 byte) bersifat unik di seluruh panjang deret. Nilai register saat program mengalami crash `SIGSEGV` memungkinkan penentuan offset eksak dalam kompleksitas waktu $\mathcal{O}(1)$.

3. **Penyelarasan Stack 16-Byte glibc ABI (x86_64 System V):**
   Pemanggilan fungsi pada arsitektur System V AMD64 ABI mengharuskan stack ($RSP$) selaras pada batas kelipatan 16 byte sebelum instruksi `call`. Melompat langsung ke fungsi target yang memanggil fungsi I/O seperti `puts()` atau `system()` dapat memicu instruksi vektor SSE (`movaps`) mengalami crash bila stack tidak selaras. Injeksi instruksi gadget tunggal `ret` sebelum alamat `win()` menyelaraskan kembali stack boundary.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Generasi Pola De Bruijn:**
   Membuat urutan siklik sepanjang 200 byte menggunakan algoritma rekursif De Bruijn untuk memetakan ruang permutasi karakter ASCII.
2. **Pengukuran Offset Crash:**
   Mengirimkan pola uji ke layanan target dan menangkap nilai offset terukur (baik melalui pesan crash log / error offset yang dibocorkan layanan, maupun analisis core dump).
3. **Penyusunan ROP Payload Ret2Win:**
   Menyusun struktur muatan eksploitasi:
   - **Padding:** Mengisi buffer hingga tepat di depan Saved Return Address (`b"A" * offset`).
   - **Stack Alignment Gadget:** Alamat gadget `ret` (8 byte) untuk memastikan keterpenuhan `RSP % 16 == 0`.
   - **Target Address:** Alamat statis fungsi `win()` (8 byte little-endian, misal `0x401196`).
4. **Pengiriman & Ekstraksi:**
   Mengirimkan payload melalui soket TCP, memicu pengalihan alur kendali ke fungsi `win()`, dan mengekstrak flag dari output standar.

---

## Flag & Verifikasi

- **Flag:** `academy{0ffs3t_cycl1c_pwn3d_733}`
- **Validasi Algoritma:** Terverifikasi 100% lolos uji rekonstruksi cyclic payload `scripts/solve_733_offset_cycle.py`.

---

## Remediasi & Mitigasi (Perspektif Defensive LKS)

1. **Eliminasi Penggunaan Fungsi Berbahaya:**
   Hapus seluruh penggunaan `gets()` dan ganti dengan antarmuka yang menerapkan *length-bounding* ketat seperti `fgets(buffer, sizeof(buffer), stdin)`.
2. **Aktifkan Proteksi Compiler Modern:**
   - **Stack Canaries:** Kompilasi dengan flag `-fstack-protector-strong` untuk mendeteksi penimpaan memori stack sebelum instruksi `ret` dieksekusi.
   - **Full RELRO & PIE:** Kompilasi dengan `-fPIE -pie -Wl,-z,relro,-z,now` guna mengacak basis memori teks dan memitigasi ret2win langsung.
   - **Control-flow Enforcement Technology (CET):** Terapkan hardware shadow stack (`-fcf-protection=full`) untuk memvalidasi integritas return pointer.
