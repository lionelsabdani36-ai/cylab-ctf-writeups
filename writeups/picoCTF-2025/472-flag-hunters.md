# Writeup: Flag Hunters (Challenge ID: 472)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Python Interpreter Logic Subversion & State Injection
- **Difficulty:** Easy
- **Author:** picoCTF Team
- **Event:** picoCTF 2025
- **Points:** 75
- **Flag:** `academy{70637h3r_f0r3v3r_42783b07}`

---

## Problem Statement & Scope
Disediakan skrip Python `lyric-reader.py` yang berfungsi sebagai interpreter lirik lagu khusus. Skrip ini melompat di antara bait (`[VERSE]`) dan refrein (`[REFRAIN]`) seperti pemanggilan subrutin (*subroutine call*). Terdapat bagian intro rahasia (`secret_intro`) di awal lirik yang menyimpan token flag, namun tidak pernah dieksekusi dalam alur normal. Peserta diminta memanipulasi input pengguna untuk mengarahkan alur eksekusi kembali ke baris intro rahasia tersebut.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Model Mesin Status dan Pointer Instruksi Lirik (Instruction Pointer Manipulation):**
   Program membaca daftar baris teks menggunakan variabel indeks pointer baris `lip` (*lyric instruction pointer*). Setiap instruksi baris dipisahkan oleh karakter titik koma (`;`).
2. **Injeksi Perintah Melalui Input Tanpa Sanitasi (Command Injection in Custom AST):**
   Pada bagian refrein, program meminta input penonton melalui prompt `CROWD`:
   ```python
   elif re.match(r"CROWD.*", line):
       crowd = input('Crowd: ')
       song_lines[lip] = 'Crowd: ' + crowd
       lip += 1
   ```
   Nilai input pengguna disimpan langsung kembali ke dalam larik `song_lines[lip]`. Ketika bagian refrein dipanggil kembali pada bait berikutnya, baris tersebut dievaluasi kembali dan dipecah berdasarkan titik koma:
   ```python
   for line in song_lines[lip].split(';'):
   ```
3. **Pembajakan Return Pointer:**
   Instruksi `RETURN [0-9]+` memindahkan nilai `lip` ke nomor baris tertentu:
   ```python
   elif re.match(r"RETURN [0-9]+", line):
       lip = int(line.split()[1])
   ```
   Dengan menyuntikkan `;RETURN 0` pada input `crowd`, penyerang membuat instruksi lompatan baru yang memaksa interpreter melompat ke baris ke-0 (`secret_intro`), di mana flag tersimpan dan dicetak ke layar.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Luncurkan instance lab container:
   `PUT /api/challenges/472/instance/`
2. Hubungkan ke layanan netcat:
   ```bash
   nc xebec.cylabacademy.net 29364
   ```
3. Tunggu hingga bait pertama selesai dan prompt refrein muncul:
   ```text
   Crowd: 
   ```
4. Masukkan payload injeksi instruksi:
   ```text
   ;RETURN 0
   ```
5. Program melanjutkan bait kedua, kemudian memanggil kembali refrein. Saat memproses baris yang telah termutasi, interpreter mengeksekusi instruksi `RETURN 0` dan mengatur pointer `lip = 0`.
6. Program mulai mencetak baris intro tersembunyi:
   ```text
   Pico warriors rising, puzzles laid bare,
   Solving each challenge with precision and flair.
   With unity and skill, flags we deliver,
   The ether’s ours to conquer, academy{70637h3r_f0r3v3r_42783b07}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{70637h3r_f0r3v3r_42783b07}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pemisahan Instruksi Kode dan Data Input (Separation of Code and Data):** Jangan pernah memodifikasi larik instruksi program (*self-modifying code*) menggunakan input pengguna mentah tanpa validasi sintaksis ketat.
- **Sanitasi Karakter Pembatas (Delimiter Sanitization):** Bersihkan karakter kontrol dan pembatas sintaksis (seperti titik koma `;`, tanda baris baru `\n`, atau tanda kutip) sebelum menyimpan atau menggabungkan input ke dalam konteks yang akan dievaluasi oleh parser.
