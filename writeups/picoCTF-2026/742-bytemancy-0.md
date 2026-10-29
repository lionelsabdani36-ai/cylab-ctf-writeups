# bytemancy 0 (Challenge 742, General Skills)

- **ID:** 742 | **Event:** picoCTF 2026 | **Kategori:** General Skills / Scripting & Byte Encoding | **Level:** Easy
- **Flag:** `academy{pr1n74813_ch4r5_544482cc}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
Server `app.py` mencetak banner `[ BYTEMANCY-0 ]` lalu meminta:
"Send me ASCII DECIMAL 101, 101, 101, side-by-side, no space."
Source: `user_input == "\x65\x65\x65"` → cetak `flag.txt`, lalu `break`.
Lab on-demand `xebec.cylabacademy.net:42602` (port rotasi per launch via
`PUT /api/challenges/742/instance/`).

## Root Cause
`0x65` heksadesimal = 101 desimal = karakter ASCII `'e'`. Validasi server
membandingkan string input dengan `'eee'` eksak — tanpa proof-of-work,
tanpa rate-limit, tanpa sesi. Payload terprogram 3 byte lolos langsung.
Pelajaran: validasi string sisi server bukan kontrol akses; teka-teki
encoding hanya melatih pemetaan desimal→heks→ASCII, bukan autentikasi.

## Rekonstruksi
1. Unduh `app.py` dari CDN challenge-files, baca logika perbandingan.
2. Launch instance: `PUT /api/challenges/742/instance/` → tunggu
   `GET .../instance/` sampai `status == "RUNNING"`, catat `nc host port`.
3. Hubungkan socket, baca banner, kirim `eee\n` via `sendall`.
4. Server cocok → cetak isi `flag.txt`. Otomasi:
   `python3 scripts/solve_742_bytemancy_0.py [host] [port]`.
5. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

## Mitigasi
Jangan jadikan teka-teki string pendek sebagai kontrol akses nyata;
gunakan token sesi acak, rate-limit per IP, dan timeout instance.
Untuk input interaktif, batasi panjang maksimum + circuit breaker agar
brute-force byte pendek tidak murah.

## Takeaway LKS
Klasifikasi General Skills: pemetaan encoding byte (desimal→heks→ASCII)
+ scripting socket dasar (`create_connection`, framing newline, parsing
regex `academy{...}`). Fondasi seri bytemancy: one-liner di sini
menyiapkan pola payload terprogram untuk `bytemancy 1` (742→762).
