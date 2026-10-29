# bytemancy 1 (Challenge 762, General Skills)

- **ID:** 762 | **Event:** picoCTF 2026 | **Kategori:** General Skills / Scripting & Byte Encoding | **Level:** Easy
- **Flag:** `academy{h0w_m4ny_e's???_6fd2faa9}` (terverifikasi writeup batch awal)

## Skenario
Server `app.py` meminta conjuring byte yang tepat. Source: `user_input ==
"\x65"*1751` → cetak `flag.txt`. Petunjuk: "No copy-pasta, please - use
Python!" Lab on-demand `chatelaine.cylabacademy.net:41819`.

## Root Cause
`0x65` = 101 desimal = karakter ASCII `'e'`. Validasi server membandingkan
string input dengan `'e'` diulang tepat 1751 kali — logika perbandingan
string eksak tanpa proof-of-work, sehingga payload terprogram lolos.
Pelajaran: validasi input sisi server tidak sama dengan autentikasi.

## Rekonstruksi
1. Hubungkan socket ke host:port, baca banner.
2. Kirim `'e'*1751 + '\n'` via `sendall` (jangan ketik manual).
3. Server cocok → cetak isi `flag.txt`. Otomasi:
   `python3 scripts/solve_762_bytemancy_1.py [host] [port]`.
4. Submit `POST /api/submissions/` → correct (saat instance RUNNING).

## Mitigasi
Jangan jadikan teka-teki panjang-string sebagai kontrol akses nyata;
gunakan token sesi acak, rate-limit, dan timeout. Untuk input interaktif,
validasi panjang maksimum + circuit breaker.

## Takeaway LKS
Klasifikasi General Skills: scripting socket + encoding byte (hex→ASCII).
Fondasi otomasi CTF: `socket.create_connection`, framing newline, parsing
regex `academy{...}` dari stream.
