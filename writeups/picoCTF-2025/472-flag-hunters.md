# Writeup: Flag Hunters (Challenge ID: 472)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Reverse Engineering / Python Interpreter Logic Subversion & Instruction Pointer Hijacking
- **Difficulty:** Easy (1)
- **Points:** 75
- **Author:** syreal
- **Event:** picoCTF 2025
- **Flag Resmi CyLab:** `academy{70637h3r_f0r3v3r_42783b07}`
- **Flag Platform Asli:** `picoCTF{70637h3r_f0r3v3r_42783b07}`
- **Flag Komunitas:** `CTF{70637h3r_f0r3v3r_42783b07}`
- **Standar Referensi:** NIST SP 800-115 §4.2 (Target Verification & Software Security Assessment), RFC 9110 (HTTP Semantics), CWE-20 (Improper Input Validation), CWE-74 (Improper Neutralization of Special Elements / Delimiter Injection), & CWE-94 (Improper Control of Generation of Code / Instruction Injection).

---

## Problem Statement & Scope

Pada modul kurikulum bimbingan teknis persiapan LKS Cyber Security Nasional bidang *Reverse Engineering & Secure Code Review*:
- **Skenario Tantangan:** Disediakan program `lyric-reader.py` yang berfungsi sebagai interpreter naskah lirik lagu interaktif berbasis konsol. Program memuat baris intro rahasia (`secret_intro`) yang menyimpan token flag dari berkas `flag.txt`. Namun, dalam alur eksekusi default, program langsung melompat ke bait pertama (`[VERSE1]`) dan tidak pernah mengeksekusi baris intro rahasia tersebut.
- **Deskripsi Soal:** *"Lyrics jump from verses to the refrain kind of like a subroutine call. There's a hidden refrain this program doesn't print by default. Can you get it to print it? There might be something in it for you. The program's source code can be downloaded here. Hints: 1. This program can easily get into undefined states. Don't be shy about Ctrl-C. 2. Unsanitized user input is always good, right? 3. Is there any syntax that is ripe for subversion?"*
- **Batasan Lingkungan & Scope Audit:**
  1. Audit statis terhadap kode sumber Python `lyric-reader.py`.
  2. Identifikasi kerentanan pemisahan instruksi dan data pada loop mesin status (*state machine loop*).
  3. Pemanfaatan interaksi input pengguna pada prompt `Crowd:` untuk menyuntikkan instruksi kontrol.
  4. Pembajakan pointer baris instruksi `lip` (*lyric instruction pointer*) menuju baris intro `secret_intro` (baris ke-0).
  5. Verifikasi live submission melalui REST API CyLab `POST /api/submissions/` (HTTP Status 201 Created).

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Arsitektur Custom Interpreter & Instruction Pointer (LIP):**
   Program `lyric-reader.py` mengimplementasikan interpreter baris sederhana:
   - Seluruh teks lagu dipecah menjadi larik baris: `song_lines = song.splitlines()`.
   - Eksekusi dipandu oleh pointer baris instruksi `lip` (*lyric instruction pointer*) yang diinisialisasi pada baris awal bait: `lip = start`.
   - Subrutin refrein (`[REFRAIN]`) dipanggil melalui instruksi `REFRAIN;` pada akhir setiap bait.
   - Lokasi kembali (*return address*) dicatat secara dinamis pada baris kontrol `RETURN`:
     ```python
     if line == 'REFRAIN':
         song_lines[refrain_return] = 'RETURN ' + str(lip + 1)
         lip = refrain
     ```

2. **Injeksi Pembatas & Modifikasi Kode di Memori (CWE-74 / CWE-94):**
   Pada bagian refrein, program meminta partisipasi penonton:
   ```python
   elif re.match(r"CROWD.*", line):
       crowd = input('Crowd: ')
       song_lines[lip] = 'Crowd: ' + crowd
       lip += 1
   ```
   Program memproses perintah dengan memecah setiap baris berdasarkan karakter titik koma (`;`):
   ```python
   for line in song_lines[lip].split(';'):
   ```
   Karena input dari pengguna (`crowd`) disimpan langsung kembali ke dalam larik instruksi aktif `song_lines[lip]` tanpa validasi atau sanitasi karakter pembatas (`;`), pengguna dapat menyuntikkan instruksi baru ke dalam memori program (*in-memory self-modifying code*).

3. **Pembajakan Alur Kendali (Control Flow Hijacking via Instruction Pointer Overwrite):**
   Pada lintasan pertama melalui refrein:
   - Pointer `lip` berada pada baris `CROWD (Singalong here!);` (indeks 11).
   - Pengguna memasukkan payload `;RETURN 0`.
   - Nilai pada indeks 11 termutasi menjadi `'Crowd: ;RETURN 0'`.
   - Program melanjutkan eksekusi bait berikutnya secara normal.
   Pada lintasan kedua melalui refrein (setelah Verse 2 selesai):
   - Ketika interpreter mengeksekusi kembali baris 11, ekspresi `song_lines[11].split(';')` menghasilkan larik: `['Crowd: ', 'RETURN 0']`.
   - Elemen kedua memicu aturan evaluasi instruksi:
     ```python
     elif re.match(r"RETURN [0-9]+", line):
         lip = int(line.split()[1])
     ```
   - Nilai pointer diatur paksa menjadi:
     $$\text{lip} = 0$$
   - Interpreter melompat langsung ke baris ke-0, yaitu `secret_intro`, yang mencetak seluruh baris pembuka beserta string token flag `flag.txt` ke layar.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Inspeksi Naskah dan Struktur Indeks Baris:**
   Menghitung indeks baris program:
   - Baris 0–3: `secret_intro` (memuat flag rahasia).
   - Baris 6: `[REFRAIN]`.
   - Baris 11: `CROWD (Singalong here!);`.
   - Baris 12: `RETURN`.
   - Baris 14: `[VERSE1]`.

2. **Koneksi ke Layanan Lab Interaktif:**
   Membuka koneksi ke container lab via socket TCP / netcat:
   ```bash
   nc xebec.cylabacademy.net 29364
   ```

3. **Injeksi Payload pada Prompt Interaktif:**
   Menunggu hingga bait pertama selesai dilantunkan dan prompt `Crowd:` muncul:
   ```text
   Command line wizards, we’re starting it right,
   Spawning shells in the terminal, hacking all night.
   Scripts and searches, grep through the void,
   Every keystroke, we're a cypher's envoy.
   Brute force the lock or craft that regex,
   Flag on the horizon, what challenge is next?
   We’re flag hunters in the ether, lighting up the grid,
   No puzzle too dark, no challenge too hid.
   With every exploit we trigger, every byte we decrypt,
   We’re chasing that victory, and we’ll never quit.
   Crowd: ;RETURN 0
   ```

4. **Pemicuan Eksekusi Instruksi Termutasi:**
   Program memutar bait kedua (`Echoes in memory, packets in trace...`) lalu kembali memanggil refrein. Ketika interpreter membaca baris ke-11 yang kini berisi `Crowd: ;RETURN 0`, instruksi `RETURN 0` dieksekusi, memaksa `lip = 0`.

5. **Pencetakan Intro Rahasia & Flag:**
   Program mencetak intro rahasia:
   ```text
   Pico warriors rising, puzzles laid bare,
   Solving each challenge with precision and flair.
   With unity and skill, flags we deliver,
   The ether’s ours to conquer, academy{70637h3r_f0r3v3r_42783b07}
   ```

---

## Flag & Verifikasi

- **Flag Resmi CyLab:** `academy{70637h3r_f0r3v3r_42783b07}`
- **Flag Platform Asli:** `picoCTF{70637h3r_f0r3v3r_42783b07}`
- **Status API Verification:** `POST /api/submissions/` mengembalikan respons `HTTP 201 Created` dengan `{"correct": true, "status": "correct"}`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

1. **Pemisahan Tegas Antara Kode dan Data (Separation of Code and Data):**
   Prinsip fundamental arsitektur von Neumann dan pertahanan aplikasi menyatakan bahwa data input eksternal tidak boleh pernah diperlakukan atau dieksekusi sebagai instruksi kode mesin/interpreter tanpa isolasi ketat (*W^X / Data Execution Prevention*).

2. **Sanitasi dan Validasi Input Berbasis Whitelist (CWE-20 / CWE-74):**
   Sebelum menyimpan data dari antarmuka pengguna ke buffer program:
   - Buang atau loloskan (*escape*) seluruh karakter pembatas sintaksis (seperti titik koma `;`, tanda petik, dan karakter kontrol baris baru `\n`).
   - Terapkan validasi berbasis pola ketat: hanya izinkan karakter alfanumerik dan spasi standar:
     ```python
     crowd = re.sub(r"[^a-zA-Z0-9\s]", "", input('Crowd: '))
     ```

3. **Integritas Struktur Data Runtime (Immutability of Instruction Memory):**
   Struktur program (`song_lines`) harus bersifat *read-only* (immutable) setelah inisialisasi awal. Variabel dinamis atau status pengguna harus disimpan dalam larik memori status yang terpisah (*state store / execution context*) sehingga tidak dapat mencemari larik instruksi program.
