# Writeup: Download Horsepower (Challenge ID: 135)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / V8 JavaScript Engine Out-Of-Bounds (OOB) Array Manipulation
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 450
- **Author:** wparks
- **Flag:** `academy{sh0u1d_hAv3_d0wnl0ad3d_m0r3_rAm_97137af90089497a}`
- **Native Flag:** `picoCTF{sh0u1d_hAv3_d0wnl0ad3d_m0r3_rAm_3a9ef72562166255}`

---

## Problem Statement & Scope
Tantangan `Download Horsepower` menyediakan target eksploitasi peramban web (*browser exploitation*) tingkat lanjut berbasis mesin JavaScript Google Chromium V8 (`d8`). Berkas biner `d8` telah dimodifikasi melalui penambahan tambalan (*patch*) bawaan pada berkas sumber `src/builtins/builtins-array.cc` yang menambahkan metode kustom `JSArray.prototype.setHorsepower(new_length)`.

Tujuan dari tantangan ini adalah menganalisis kode patch V8, mengidentifikasi ketidaksesuaian verifikasi batas alokasi memori internal (*out-of-bounds boundary check failure*), merancang primitif baca/tulis memori arbitrer (*arbitrary read/write*) dengan memperhitungkan kompresi penunjuk 32-bit (*V8 Pointer Compression*), mengekstrak alamat halaman memori RWX dari instans WebAssembly, menginjeksi kode mesin x86-64 (*shellcode*) untuk membaca berkas `flag.txt`, dan mengeksekusi kendali aliran program.

Ruang lingkup audit keamanan kepatuhan **NIST SP 800-115 Section 4.2** (*Binary and Runtime Software Security Assessment*):
1. Verifikasi integritas kompilasi biner `d8` (arsitektur x86-64, ASLR, PIE, DEP/NX aktif, Pointer Compression aktif).
2. Analisis tambalan `src/builtins/builtins-array.cc` yang secara langsung memperbarui atribut panjang array (`length`) tanpa memperbarui kapasitas buffer fisik elemen (`FixedArray` / `FixedDoubleArray`).
3. Formulasi primitif `addrof` (pencari alamat objek) dan `fakeobj` (pemalsu pointer objek) pada heap V8.
4. Perampasan penunjuk `backing_store` pada struktur objek `ArrayBuffer` untuk memfasilitasi baca dan tulis memori arbitrer 64-bit (*Arbitrary Address Read/Write*).
5. Eskalasi eksekusi kode melalui pemanfaatan wilayah memori WebAssembly JIT yang memiliki izin baca-tulis-eksekusi (*RWX memory page hijacking*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Manipulasi Panjang Array V8 Tanpa Realokasi Buffer (CWE-125, CWE-787)
Dalam mesin JavaScript Google V8, objek `JSArray` terdiri dari metadata:
- Peta objek (`map`): mendefinisikan layout dan tipe elemen (misalnya `PACKED_DOUBLE_ELEMENTS` atau `PACKED_ELEMENTS`).
- Properti (`properties`): penunjuk ke kamus properti objek.
- Elemen (`elements`): penunjuk ke buffer memori berurutan (`FixedDoubleArray`) yang menyimpan nilai array sebenarnya.
- Panjang (`length`): representasi Smi (Small Integer) mengenai jumlah elemen yang dilaporkan.

Pada tambalan `Download Horsepower`:
```cpp
BUILTIN(ArraySetHorsepower) {
  HandleScope scope(isolate);
  Handle<JSArray> array = Handle<JSArray>::cast(args.receiver());
  Handle<Object> new_length = args.atOrUndefined(isolate, 1);
  array->set_length(*new_length); // [!] Kerentanan: Mengubah length tanpa realokasi buffer elemen!
  return *array;
}
```
Fungsi tersebut memodifikasi atribut internal `length` secara langsung menjadi nilai yang dikirimkan pengguna (misal `0x100` atau `256`) tanpa memanggil `JSArray::SetLength` yang semestinya memeriksa dan mengalokasikan ulang buffer memori pendukung (*backing store*). Akibatnya, mesin V8 mengizinkan pengaksesan indeks elemen melebihi alokasi memori fisik awal array, menghasilkan kerentanan *Out-Of-Bounds Read and Write* (OOB).

### 2. Mekanisme Kompresi Penunjuk (Pointer Compression)
Pada build V8 modern, arsitektur x86-64 menggunakan fitur *Pointer Compression*. Alamat memori heap disimpan sebagai penunjuk 32-bit relatif terhadap dasar ruang Isolate 4GB (`isolate_root`).
- Elemen float (`PACKED_DOUBLE_ELEMENTS`) menempati 8 byte penuh (64-bit Float64).
- Elemen objek (`PACKED_ELEMENTS`) menempati 4 byte terkompresi (32-bit).
Dengan menempatkan sebuah `oob_arr` bertipe double tepat di sebelah array objek `obj_arr`, pembacaan indeks Float64 yang overlap melintasi batas elemen akan membaca dua penunjuk objek 32-bit sekaligus, memungkinkan pengungkapan alamat heap objek secara akurat (*address leak*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inisialisasi Primitif OOB Array:**
   ```javascript
   var oob_arr = [1.1, 2.2, 3.3, 4.4];
   oob_arr.setHorsepower(0x100); // Panjang menjadi 256 elemen
   var obj_arr = [{a: 1}, {b: 2}];
   ```

2. **Konstruksi Helper `addrof` dan `fakeobj`:**
   Dengan mengamati jarak offset relatif antara elemen `oob_arr` dan buffer `obj_arr` pada heap (offset indeks 19):
   - `addrof(obj)`: Menyimpan target objek ke `obj_arr[0]`, kemudian membaca nilai Float64 pada `oob_arr[19]` dan mengekstrak paruh bawah/atas 32-bit.
   - `fakeobj(addr)`: Menulis representasi IEEE-754 dari alamat terkompresi ke `oob_arr[19]`, lalu mengakses `obj_arr[0]` sebagai objek palsu.

3. **Membangun Arbitrary Address Read (AAR) dan Arbitrary Address Write (AAW):**
   - Mengalokasikan array kedua `victim_arr = [1.1, 2.2]` dan sebuah `ArrayBuffer(0x100)`.
   - Menggunakan OOB write untuk menimpa penunjuk `elements` pada `victim_arr` atau langsung memodifikasi penunjuk `backing_store` 64-bit pada struktur `ArrayBuffer`.
   - Menyetel `backing_store` ke sembarang alamat memori 64-bit memberikan kapabilitas membaca dan menulis byte secara langsung melalui instans `DataView`.

4. **Pemanfaatan WebAssembly RWX & Injeksi Shellcode:**
   - WebAssembly engine mengompilasi modul WASM ke kode mesin asli menggunakan halaman memori yang ditandai dengan izin `PROT_READ | PROT_WRITE | PROT_EXEC` (RWX).
   ```javascript
   var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,...]);
   var wasmModule = new WebAssembly.Module(wasmCode);
   var wasmInstance = new WebAssembly.Instance(wasmModule);
   ```
   - Melalui AAR, baca penunjuk kode mesin JIT dari struktur internal metadata `wasmInstance` (offset `+0x68`).
   - Melalui AAW, tulis *shellcode* pembaca bendera x86-64 ke alamat memori yang ditunjuk oleh fungsi WASM.
   - Panggil fungsi ekspor WASM `wasmInstance.exports.main()`. Shellcode langsung dieksekusi di ruang pengguna dengan hak akses biner target.

5. **Pengekstrakan Token Flag:**
   Payload membaca berkas `flag.txt` dan mengalirkannya ke stdout:
   `academy{sh0u1d_hAv3_d0wnl0ad3d_m0r3_rAm_97137af90089497a}`.

---

## Rekomendasi Mitigasi & Pengerasan Keamanan (Remediation)
1. **Penerapan Validasi Batas Ketat pada Setter Atribut (Strict Boundary Enforcement):**
   - Modifikasi properti `length` pada objek internal V8 wajib selalu melalui jalur validasi resmi `JSArray::SetLength` yang secara otomatis mengelola realokasi buffer atau memangkas elemen. Pemanggilan langsung `set_length()` tanpa realokasi memori buffer merupakan pelanggaran keamanan kritis memori (Memory Safety Violation).
2. **Implementasi W^X / JIT Code Caging (JIT Security Hardening):**
   - Matikan izin RWX simultan pada halaman kode JIT/WASM. Gunakan model *Write XOR Execute* (W^X) dengan memetakan halaman kode sebagai Read-Write saat kompilasi berlangsung, kemudian mengubah izinnya menjadi Read-Execute sebelum eksekusi dimulai (`mprotect(PROT_READ | PROT_EXEC)`).
3. **Pemberlakuan V8 Heap Sandbox:**
   - Aktifkan fitur *V8 Heap Sandbox* yang mengisolasi korupsi pointer di dalam batas memori 4GB terisolasi sehingga tidak dapat memodifikasi memori di luar heap seperti alamat tabel fungsi atau instruksi kode mesin asli.

---

## Script Reproduksi
Script solver mandiri tersedia pada berkas `scripts/solve_135_download_horsepower.py`.
Jalankan verifikasi dengan perintah:
```bash
python3 scripts/solve_135_download_horsepower.py
```
Hasil verifikasi mengembalikan token flag valid:
`academy{sh0u1d_hAv3_d0wnl0ad3d_m0r3_rAm_97137af90089497a}`
