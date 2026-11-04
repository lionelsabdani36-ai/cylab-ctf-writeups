# 269 - flag leak (Binary Exploitation, picoCTF 2022, Medium)

## Challenge Metadata
- ID: 269 | Event: picoCTF 2022
- Category: Binary Exploitation | Difficulty: Medium (2)
- Author: LT 'syreal' Jones
- Points: 100 Pts
- Flag: `academy{L34k1ng_Fl4g_0ff_St4ck_0845a0aa}`

## Problem Statement & Scope
Tantangan menyajikan sebuah biner ELF 32-bit x86 interaktif bernama `vuln`. Pengguna diminta menceritakan sebuah kisah melalui prompt:
`Tell me a story and then I'll tell you one >> `
Setelah pengguna memasukkan teks cerita, program mencetak ulang teks tersebut. Sebelum menerima masukan pengguna, biner memanggil fungsi internal `readflag()` yang membaca berkas `flag.txt` ke dalam buffer memori stack.
Objektif pengujian (NIST SP 800-115 / OWASP Binary Security Analysis): Menganalisis mekanisme alokasi buffer pada frame stack fungsi `vuln()`, mengidentifikasi ketidakpatuhan penanganan string format, merekonstruksi offset parameter dereferensi stack pointer, dan membocorkan flag rahasia langsung dari memori proses tanpa merusak aliran eksekusi program.

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Format String Vulnerability (CWE-134: Use of Externally-Controlled Format String):**
   Pada berkas kode sumber `vuln.c`, fungsi `vuln()` memiliki implementasi berikut:
   ```c
   void vuln(){
      char flag[BUFSIZE];
      char story[128];

      readflag(flag, FLAGSIZE);

      printf("Tell me a story and then I'll tell you one >> ");
      scanf("%127s", story);
      printf("Here's a story - \n");
      printf(story);
      printf("\n");
   }
   ```
   Panggilan `printf(story)` mengevaluasi string masukan pengguna secara langsung sebagai string pemformat (*format string specifier*), bukan sebagai parameter data (`printf("%s", story)`).
2. **x86 32-Bit Calling Convention & Stack Frame Parameter Resolution:**
   Dalam arsitektur 32-bit (x86 cdecl), seluruh parameter pemanggilan fungsi ditempatkan berurutan pada stack. Saat mesin pemformatan `printf` mendeteksi penentu format (seperti `%p`, `%x`, atau `%s`), fungsi tersebut mengambil argumen berikutnya dari alamat memori yang lebih tinggi dari stack pointer (`ESP`).
3. **Arbitrary Pointer Dereference via Positional Specifier (`%k$s`):**
   Buffer `flag[64]` dialokasikan pada frame stack fungsi `vuln()` sebelum `story[128]`. Pointer atau konten buffer `flag` terletak pada offset stack tertentu relatif terhadap panggilan `printf`.
   Dengan menyuplai penentu format posisional `%{k}$s`, mesin `printf` memperlakukan nilai 4-byte yang berada pada indeks argumen ke-$k$ sebagai alamat memori (`char *`) dan mendereferensikannya secara langsung untuk mencetak karakter string null-terminated yang ditunjuk.

## Rekonstruksi Eksploitasi Step-by-Step
1. Analisis statis biner dan frame stack:
   - Target adalah biner 32-bit ELF dynamically linked.
   - Variabel `flag` diisi string dari `flag.txt` via `readflag(flag, 64)`.
   - String `story` dibaca menggunakan `scanf("%127s", story)`.
2. Probing offset argumen stack:
   - Dibuat skrip pengujian iteratif yang mengirimkan payload `%k$s` dari indeks $k = 1$ hingga $k = 45$ ke socket TCP layanan target `nc xebec.cylabacademy.net 24998`.
   - Pada indeks 1 sampai 19, server mengembalikan string lingkungan, pustaka standar, atau nilai null pointer.
3. Eksfiltrasi nilai flag pada Offset 20:
   - Pada pengiriman payload `%20$s\n`:
     Masukan: `%20$s`
     Keluaran server: `Here's a story - \nacademy{L34k1ng_Fl4g_0ff_St4ck_0845a0aa}`
   - Format specifier `%20$s` berhasil mendereferensikan buffer `flag` pada frame stack dan mencetak flag secara lengkap.
4. Verifikasi REST API CyLab:
   - Mengirim token flag ke REST API `POST /api/submissions/` dengan payload `{"challenge": 269, "flag": "academy{L34k1ng_Fl4g_0ff_St4ck_0845a0aa}"}`.
   - Platform merespons dengan HTTP Status 201 Created:
     `{"user": 1072359, "challenge": 269, "flag": "academy{L34k1ng_Fl4g_0ff_St4ck_0845a0aa}", "correct": true, "historical": false}`.
5. Terminasi instance:
   - Mengirim permintaan `DELETE /api/challenges/269/instance/` untuk membersihkan slot instance lab on-demand.

## Flag & Verifikasi
- Flag Resmi: `academy{L34k1ng_Fl4g_0ff_St4ck_0845a0aa}`
- Bukti Validasi: REST API CyLab `POST /api/submissions/` mengembalikan respons `correct: true` (HTTP Status 201 Created).

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Strict Format String Enforcement:** Jangan pernah meneruskan string yang dapat dimanipulasi oleh pengguna sebagai parameter pertama fungsi keluarga `printf` (`printf`, `fprintf`, `sprintf`, `snprintf`, `syslog`). Gunakan format konstan:
  ```c
  printf("%s", story);
  ```
  atau fungsi output string langsung:
  ```c
  fputs(story, stdout);
  ```
- **Compiler Security Hardening Flag:** Aktifkan peringatan dan proteksi kompilasi GCC:
  `-Wformat=2 -Werror=format-security -D_FORTIFY_SOURCE=2`. Opsi ini membuat kompilator menolak kompilasi format string yang tidak konstan atau berpotensi bahaya.
- **Secure Buffer Lifecycle & Ephemeral Secrets (NIST SP 800-115 Defensif):** Rahasia sensitif (seperti token, kunci kriptografi, atau flag) harus segera dibersihkan dari memori stack menggunakan `explicit_bzero()` atau `memset_s()` setelah selesai digunakan, guna mencegah eksfiltrasi melalui kebocoran memori (memory leak/disclosure) pada fungsi lanjutan.
