# Writeup: Input Injection 1 (Challenge ID: 525)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation
- **Difficulty:** Medium (2)
- **Author:** CyLab Africa Team
- **Event:** picoMini by CMU-Africa
- **Points:** 100
- **Flag:** `academy{0v3rfl0w_c0mm4nd_72792d0d}`

---

## Deskripsi Tantangan
> A friendly program wants to greet you… but its goodbye might say more than it should. Can you convince it to reveal the flag?
> connect to the challenge instance `nc chatelaine.cylabacademy.net <port>`.
> You can download the program file `vuln` and source code `vuln.c`.
> Hints:
> 1. Look closely at how the program stores and uses your input.

---

## Analisis Kerentanan & Konsep Teknis (Root Cause Analysis)
Pada implementasi fungsi `fun(char *name, char *cmd)` dalam `vuln.c`:
```c
void fun(char *name, char *cmd) {
    char c[10];
    char buffer[10];

    strcpy(c, cmd);
    strcpy(buffer, name);

    printf("Goodbye, %s!\n", buffer);
    fflush(stdout);
    system(c);
}
```

1. **Stack Memory Layout:**
   - Melalui inspeksi disassembly x86_64 dengan `objdump -d -M intel vuln`:
     - Alamat `c` dialokasikan pada `[rbp - 0xa]` (10 byte).
     - Alamat `buffer` dialokasikan pada `[rbp - 0x14]` (10 byte).
     - Jarak offset relatif: `(rbp - 0xa) - (rbp - 0x14) = 0x0a` (tepat 10 byte).
2. **Buffer Overflow CWE-120 via Unbounded `strcpy`:**
   - Input `name` dibaca pada `main()` hingga 200 byte menggunakan `fgets(name, sizeof(name), stdin)`.
   - Namun di dalam `fun()`, fungsi `strcpy(buffer, name)` menyalin string input tanpa validasi batas ukuran buffer tujuan (hanya berukuran 10 byte).
   - Penulisan melampaui 10 byte dari `buffer` secara langsung menimpa memori lokal `c` yang berada tepat setelahnya di alamat memori yang lebih tinggi.
3. **Arbitrary Command Execution:**
   - Setelah mencetak ucapan perpisahan, program mengeksekusi `system(c)`.
   - Jika isi variabel `c` berhasil dimanipulasi dengan perintah shell arbitrary (misalnya `cat flag.txt`), maka `system()` akan mengeksekusi perintah tersebut dengan hak akses proses lokal.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis alokasi stack frame fungsi `fun`:
   - `buffer` = `rbp - 0x14`
   - `c` = `rbp - 0xa`
   - Offset padding: 10 byte.
2. Penyusunan Payload:
   - 10 byte padding (misal: `b"A" * 10`) untuk memenuhi alokasi buffer `buffer`.
   - String perintah yang diinginkan: `b"cat flag.txt\x00\n"`.
3. Pengiriman Payload ke Target Remote:
   ```bash
   python3 scripts/solve_525_input_injection_1.py <host> <port>
   ```
4. Respons Server:
   ```text
   Goodbye, AAAAAAAAAAcat flag.txt!
   academy{0v3rfl0w_c0mm4nd_72792d0d}
   ```
5. Verifikasi REST API CyLab:
   - Endpoint `POST /api/submissions/` merespons dengan status HTTP 201 Created:
   ```json
   {"user": 1072359, "challenge": 525, "flag": "academy{0v3rfl0w_c0mm4nd_72792d0d}", "correct": true, "historical": false}
   ```

---

## Pembelajaran Defensif & Mitigasi LKS
- **Hindari Unbounded String Functions (Banned Functions):** Penggunaan `strcpy()` harus diganti dengan fungsi aman yang membatasi panjang input, seperti `strncpy()` dengan penanganan null-terminator eksplisit, atau `strlcpy()`.
- **Penggunaan Safe C Runtime / Bounds Checking:** Selalu validasi ukuran `strlen(name) < sizeof(buffer)` sebelum melakukan operasi penyalinan.
- **Kompilasi Proteksi Stack Canary (`-fstack-protector-strong`):** Memastikan GCC menyisipkan canary guard untuk menggagalkan eksekusi jika terjadi overflow pada buffer lokal.
- **Prinsip Least Privilege & Pemisahan Command Execution:** Hindari pemanggilan langsung `system()` dengan argumen dari buffer stack yang rentan modifikasi. Gunakan `execve()` dengan array argumen statis jika pemanggilan biner eksternal tidak dapat dihindari.
