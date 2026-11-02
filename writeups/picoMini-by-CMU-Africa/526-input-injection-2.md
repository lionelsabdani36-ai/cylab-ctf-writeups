# Writeup: Input Injection 2 (Challenge ID: 526)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation
- **Difficulty:** Medium (2)
- **Author:** CyLab Africa Team
- **Event:** picoMini by CMU-Africa
- **Points:** 100
- **Flag:** `academy{us3rn4m3_2_sh3ll_819f0acb}`

---

## Deskripsi Tantangan
> This program greets you and then runs a command. But can you take control of what command it executes?
> Connect to the program with netcat:
> `nc chatelaine.cylabacademy.net <port>`
> You can download the program file `vuln` and source code `vuln.c`.
> Hints:
> 1. Notice how `username` and `shell` are both heap-allocated.
> 2. Offsets often hide in the memory addresses you see at runtime.
> 3. Try to overwrite what command gets executed.

---

## Analisis Kerentanan & Konsep Teknis (Root Cause Analysis)
Pada berkas sumber `vuln.c`:
```c
int main(void) {
	char* username = malloc(28);
	char* shell = malloc(28);
	
	printf("username at %p\n", username);
    fflush(stdout);
	printf("shell at %p\n", shell);
    fflush(stdout);
	
	strcpy(shell, "/bin/pwd");
	
	printf("Enter username: ");
    fflush(stdout);
	scanf("%s", username);
	
	printf("Hello, %s. Your shell is %s.\n", username, shell);
	system(shell);
    fflush(stdout);
	
	return 0;
}
```

1. **Heap Memory Layout & Chunk Alignment:**
   - Kedua pointer `username` dan `shell` dialokasikan secara berurutan di heap menggunakan `malloc(28)`.
   - Pada alokator glibc 64-bit, permintaan 28 byte menghasilkan ukuran chunk minimum 0x30 (48 byte) untuk menampung metadata chunk dan perataan memori 16-byte.
   - Program secara terbuka membocorkan (leaks) alamat memori heap kedua variabel: `username at %p` dan `shell at %p`.
   - Offset relatif dari `username` ke `shell` dihitung dinamis: `shell - username = 48` byte.
2. **Heap Buffer Overflow CWE-122 via Unbounded `scanf("%s")`:**
   - Pembacaan input `scanf("%s", username)` tidak menyertakan batas lebar string (width specifier).
   - Pengguna dapat memasukkan data yang jauh melampaui kapasitas 28 byte. Penulisan melebihi 48 byte secara langsung menimpa header chunk berikutnya dan isi buffer string `shell`.
3. **Bypass Whitespace Delimiter pada `scanf("%s")`:**
   - Spesifikasi format `scanf("%s")` memotong pembacaan input pada karakter spasi (whitespace / `0x20`).
   - Perintah standar seperti `cat flag.txt` akan terpotong menjadi hanya `cat`.
   - Untuk mengeksekusi perintah dengan argumen tanpa menggunakan spasi, kita memanfaatkan mekanisme shell redirection input Unix: `cat<flag.txt`.
   - Ketika `system(shell)` dipanggil, program menjalankan `/bin/sh -c "cat<flag.txt"`, yang secara sah membuka dan mencetak konten `flag.txt`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Koneksi socket ke instance remote:
   - Tangkap output awal yang memuat alamat heap `username` dan `shell`.
   - Hitung selisih offset: `offset = shell_addr - username_addr` (dihasilkan 48 byte).
2. Konstruksi Payload:
   - 48 byte karakter pengisi (padding `b"A" * 48`) untuk menjangkau awal buffer `shell`.
   - Perintah injeksi: `b"cat<flag.txt\n"`.
3. Eksekusi Script Solver:
   ```bash
   python3 scripts/solve_526_input_injection_2.py chatelaine.cylabacademy.net 47228
   ```
4. Respons Server:
   ```text
   academy{us3rn4m3_2_sh3ll_819f0acb}Hello, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcat<flag.txt. Your shell is cat<flag.txt.
   ```
5. Verifikasi REST API CyLab:
   - Endpoint `POST /api/submissions/` merespons status HTTP 201 Created:
   ```json
   {"user": 1072359, "challenge": 526, "flag": "academy{us3rn4m3_2_sh3ll_819f0acb}", "correct": true, "historical": false}
   ```

---

## Pembelajaran Defensif & Mitigasi LKS
- **Validasi Panjang Input pada Format String Scanner:** Selalu gunakan width specifier saat memakai `scanf`, misal `scanf("%27s", username)`.
- **Gunakan Fungsi Pembacaan Berbatas (`fgets`):** Lebih disarankan menggunakan `fgets(username, 28, stdin)` yang secara eksplisit membatasi panjang pembacaan memori.
- **Pembersihan Pointer & Heap Isolation:** Hindari meletakkan pointer perintah sensitif yang dieksekusi oleh `system()` berdekatan dengan buffer yang dapat dikontrol oleh pengguna di heap tanpa validasi integritas.
- **Penggunaan Executable Whitelist:** Gantikan pemanggilan `system()` dengan `execve()` yang menerima argumen array tetap dan tidak memicu parsing subshell.
