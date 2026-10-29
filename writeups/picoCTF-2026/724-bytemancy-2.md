# bytemancy 2 (Challenge 724, General Skills)

- **ID:** 724 | **Event:** picoCTF 2026 | **Kategori:** General Skills | **Level:** Medium
- **Flag:** `academy{3ff5_4_d4yz_31bc4875}` (interaksi socket langsung OK;
  submit API `{"correct": true}` status 201)

## Skenario
Server menantang: "Send me the HEX BYTE 0xFF 3 times, side-by-side,
no space", lalu membandingkan input dengan `b"\xff\xff\xff"`.
Byte 0xFF bukan karakter printable (hint: "There's no way to print these
bytes") — harus dikirim sebagai raw bytes via socket. Lab on-demand
`nc chatelaine.cylabacademy.net <port>`.

## Root Cause
`sys.stdin.buffer.readline()` membaca bytes mentah, bukan teks. Program
tidak memvalidasi encoding — ia membandingkan 3 byte mentah.
Kesalahpahaman umum: mengetik "ÿ" (U+00FF → UTF-8 `0xC3 0xBF`, 2 byte)
atau string "\xff" literal (4 byte ASCII) gagal. Solusinya adalah
mengirim byte 0xFF yang sebenarnya — konsep fundamental perbedaan teks
vs bytes dalam protokol jaringan.

## Rekonstruksi
1. Launch lab: `PUT /api/challenges/724/instance/` → RUNNING, catat port.
2. `socket.create_connection((host, port))`, baca banner.
3. Kirim `b"\xff\xff\xff\n"` (readline memotong newline).
4. Server mencetak `flag.txt`: `academy{3ff5_4_d4yz_31bc4875}`.
5. Submit `POST /api/submissions/` → `{"correct": true}` (201).
   Otomasi: `python3 scripts/solve_724_bytemancy_2.py [host] [port]`.

## Mitigasi
Validasi input di level bytes dengan panjang eksplisit; jangan andalkan
representasi teks untuk data biner. Dokumentasikan encoding yang
diharapkan di setiap antarmuka.

## Takeaway LKS
Klasifikasi General Skills: manipulasi bytes vs teks — kirim byte
non-printable secara programatik (Python socket/pwntools), bukan
copy-paste terminal. Pola "conjure bytes" bersama hex/octal/decimal.
