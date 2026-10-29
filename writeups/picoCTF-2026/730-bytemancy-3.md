# bytemancy 3 (Challenge 730, General Skills)

- **ID:** 730 | **Event:** picoCTF 2026 | **Kategori:** General Skills | **Level:** Hard
- **Flag:** `academy{0bjdump_m4g1c_c79394e0}` (interaksi socket langsung OK;
  submit API `{"correct": true}` status 201)

## Skenario
Server (`app.py`) menyebut 3 prosedur acak dari `spellbook` (ember_sigil,
glyph_conflux, astral_spark, binding_word) dan meminta alamat 4-byte
masing-masing dalam bentuk little-endian mentah (`p32`). 3 jawaban benar
membuka flag. Lab on-demand `nc chatelaine.cylabacademy.net <port>`.

## Root Cause
Binary `spellbook` adalah ELF 32-bit non-PIE (`readelf -h`: Type EXEC),
jadi alamat simbol statis dan dapat dibaca dari tabel simbol:
`objdump -t` / `nm` → ember_sigil 0x08049156, glyph_conflux 0x08049176,
astral_spark 0x08049199, binding_word 0x080491b7. Tantangan ini menguji
pemahaman endianness dan pengiriman data biner mentah — `struct.pack`
`<I` mengonversi integer menjadi 4 byte little-endian yang diharapkan
`read_exact_bytes(4)`.

## Rekonstruksi
1. `nm spellbook` → petakan 4 nama prosedur ke alamat (tetap, non-PIE).
2. Launch lab: `PUT /api/challenges/730/instance/` → RUNNING, catat port
   (`nc xebec.cylabacademy.net 23788` saat pengerjaan; catatan: backend
   butuh ~4x PUT / ~30 menit hingga RUNNING — antrean provisioning).
3. Baca prompt `procedure '<nama>'` per ronde, kirim `p32(alamat)` —
   tepat 4 byte mentah tanpa newline (server membuang satu newline).
4. Setelah ronde 3, server mencetak flag `academy{0bjdump_m4g1c_c79394e0}`;
   submit `POST /api/submissions/` → `{"correct": true}` (201).
   Otomasi: `python3 scripts/solve_730_bytemancy_3.py [host] [port]`
   — terverifikasi penuh, pertama vs app.py asli via TCP lokal lalu
   vs instance live.

## Mitigasi
Untuk tantangan produksi: gunakan PIE + ASLR agar alamat tidak statis;
baca tepat N byte dengan timeout agar client lambat tidak menggantung
server; rate-limit koneksi per IP.

## Takeaway LKS
Klasifikasi General Skills: analisis tabel simbol ELF statis + encoding
little-endian + I/O biner presisi-byte. Pola "conjure bytes" bersama
`objdump`/`nm` dan `p32`.
