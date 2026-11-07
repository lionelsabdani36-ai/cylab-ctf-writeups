# Writeup: Turboflan (Challenge ID: 178)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / V8 TurboFan JIT Compiler Map Check Elimination
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 600
- **Author:** wparks
- **Flag:** `academy{Good_job!_Now_go_find_a_real_v8_cve!_4f2661eab1a80e33}`

---

## Problem Statement & Scope
Tantangan `Turboflan` menyajikan lingkungan runtime mesin JavaScript Google V8 (`d8`) arsitektur x86-64 dengan optimasi kompilator Just-In-Time (JIT) TurboFan dan kompresi pointer (*pointer compression*). Peserta diberikan berkas biner `d8`, berkas patch kode sumber V8, dan skrip wrapper remote.

Tujuan utama dari modul ini adalah mengaudit modifikasi pada pipeline optimasi TurboFan, mengeksploitasi kegagalan deoptimasi untuk menghasilkan kebingungan tipe (*type confusion*), merekayasa primitif pembacaan dan penulisan memori arbitrer (*arbitrary read/write*), serta membajak halaman memori RWX milik instansiasi WebAssembly untuk mengeksekusi *shellcode* native pembaca berkas `flag.txt`.

Ruang lingkup audit kepatuhan **NIST SP 800-115 Section 4.2** (*Binary and Software Security Assessment*):
1. Pemeriksaan diff patch pada `src/compiler/effect-control-linearizer.cc`.
2. Analisis siklus hidup kompilasi fungsi JIT (Ignition bytecode ke TurboFan machine code).
3. Evaluasi asumsi representasi tipe data JavaScript internal (HeapNumber Float64 vs Tagged Pointers).
4. Pembangunan primitif eksploitasi browser modern: `addrof`, `fakeobj`, dan ArrayBuffer backing store hijacking.
5. Injeksi instruksi mesin ke halaman kode WebAssembly RWX dan pengekstrakan bendera kompetisi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Eliminasi Deoptimasi Map Check pada TurboFan (CWE-843 / CWE-697)
Dalam mesin V8 standar, fungsi yang dieksekusi berkali-kali secara berulang (*hot function*) akan dikompilasi oleh TurboFan menjadi kode mesin native yang dioptimalkan secara agresif berdasarkan tipe data yang diamati sebelumnya (*speculative optimization*). Untuk menjamin keamanan tipe, TurboFan menyisipkan simpul penjaga (*speculation guard*):
```cpp
void EffectControlLinearizer::LowerCheckMaps(Node* node, Node* frame_state) {
  Node* map = __ HeapConstant(maps[i]);
  Node* check = __ TaggedEqual(value_map, map);
  if (i == map_count - 1) {
    __ DeoptimizeIfNot(DeoptimizeReason::kWrongMap, p.feedback(), check,
                       frame_state, IsSafetyCheck::kCriticalSafetyCheck);
  }
}
```
Patch pada tantangan `Turboflan` menghapus pemanggilan `DeoptimizeIfNot(DeoptimizeReason::kWrongMap, ...)` dengan komentar `// This makes me slow down!`. Akibatnya, saat fungsi yang telah dioptimasi untuk tipe objek A menerima input bertipe B dengan struktur *Map* yang berbeda, TurboFan tidak melakukan deoptimasi (*bailout*) kembali ke interpreter Ignition, melainkan tetap mengeksekusi jalur kode mesin teroptimasi.

### 2. Mekanisme Type Confusion Antara Float64 dan Pointer
Dengan kompresi pointer V8 (*pointer compression*), pointer objek JavaScript disimpan sebagai offset 32-bit di dalam isolasi heap 4GB, sedangkan nilai numerik pecahan (`double`) disimpan dalam alokasi `HeapNumber` 64-bit:
- **Array Float:** Menyimpan nilai IEEE-754 64-bit langsung atau pointer ke HeapNumber.
- **Array Objek:** Menyimpan deretan pointer 32-bit yang mengarah ke objek di heap.
Dengan meloloskan array objek ke dalam fungsi yang mengasumsikan array float, nilai pointer objek diperlakukan sebagai angka pecahan 64-bit, memungkinkan manipulasi byte dan kebocoran alamat heap secara langsung.

---

## Tahapan Eksploitasi & Verifikasi (Reproduction Steps)

1. **Pemicuan Optimasi JIT Tanpa Inlining:**
   - Menyusun fungsi pengakses properti `f(o)` dan menjalankannya berulang kali (>0x1000 iterasi) dengan argumen bertipe float array agar TurboFan mengompilasinya menjadi kode mesin spesifik float:
     ```javascript
     function f(o) {
         o.a *= 2; o.c *= 3;
         let t = o.b;
         return ftoi(t);
     }
     for (var i = 0; i < 0x1000; ++i) { f(x); f(x); f(x); }
     ```

2. **Pembangunan Primitif addrof dan fakeobj:**
   - Melewatkan objek dengan tipe berbeda `y = {a:5, b:[6.9], c:2}` dan `y2 = {a:5, b:[{}], c:2}`.
   - Karena fungsi JIT tidak melakukan bailout saat map berbeda, pointer elemen `y2` ditimpa agar menunjuk ke elemen `y`.
   - Mengakses elemen sebagai objek menghasilkan alamat heap objek (`addrof`), dan menulis alamat numerik menghasilkan referensi objek palsu (`fakeobj`).

3. **Rekayasa Arbitrary Read & Write:**
   - Mengonfigurasi `fakeobj` yang merepresentasikan objek `ArrayBuffer` kustom.
   - Menimpa pointer `backing_store` 64-bit milik `ArrayBuffer` ke alamat memori target mana pun di seluruh ruang alamat proses.
   - Melalui antarmuka `DataView`, pembacaan dan penulisan memori arbitrer (*read/write primitive*) berhasil didapatkan.

4. **Injeksi Shellcode ke Halaman WebAssembly RWX:**
   - Menginstansiasi modul WebAssembly sederhana (`WebAssembly.Instance`), yang secara bawaan mengalokasikan halaman memori dengan izin Baca-Tulis-Eksekusi (`PROT_READ | PROT_WRITE | PROT_EXEC`).
   - Menggunakan primitif pembacaan heap untuk mengekstrak alamat halaman RWX dari struktur internal instance WASM.
   - Menulis shellcode x86-64 pemanggil `sys_open("flag.txt")`, `sys_read()`, dan `sys_write(1, ...)` ke halaman kode WASM tersebut menggunakan `ArrayBuffer` yang telah dibajak.
   - Memanggil fungsi ekspor WASM (`pwn()`), yang mengeksekusi shellcode dan mencetak bendera:
     `academy{Good_job!_Now_go_find_a_real_v8_cve!_4f2661eab1a80e33}`.

---

## Rekomendasi Mitigasi & Pengerasan Keamanan (Remediation)
1. **Integritas Penjaga Spekulasi TurboFan (Speculation Guards):**
   - Wajib mempertahankan seluruh pengecekan map dan batasan tipe (*type check guards*). Jika terjadi perubahan tipe pada runtime, fungsi wajib segera dideoptimasi ke interpreter aman.
2. **Penghapusan Halaman Memori Bersama RWX (W^X / Memory Protection Keys):**
   - Terapkan kebijakan W^X ketat pada engine WebAssembly modern di mana halaman memori hanya berizin W saat kompilasi dan beralih ke X saat eksekusi (*mprotect / pkey*), mencegah injeksi shellcode langsung ke segmen kode JIT.
3. **Isolasi Heap dan Pointer Authentication:**
   - Gunakan V8 Sandbox (*Ubercage*) modern yang mengisolasi seluruh memori mesin skrip dari pointer eksekusi native dan struktur proses induk.

---

## Script Reproduksi
Script solver mandiri tersedia pada berkas `scripts/solve_178_turboflan.py`.
Jalankan verifikasi dengan perintah:
```bash
python3 scripts/solve_178_turboflan.py
```
Hasil verifikasi mengembalikan token flag valid:
`academy{Good_job!_Now_go_find_a_real_v8_cve!_4f2661eab1a80e33}`
