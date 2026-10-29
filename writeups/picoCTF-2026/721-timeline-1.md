# Timeline 1 (Challenge 721, Forensics)

- **ID:** 721 | **Event:** picoCTF 2026 | **Kategori:** Forensics | **Level:** Hard
- **Flag:** `academy{573417h13r_7h4n_7h3_1457_58527bb222}` (carving lokal + base64 OK;
  submit API `{"correct": true}` status 201)

## Skenario
Diberikan disk image `timeline-1-partition4.img.gz` (ext4, ~490MB).
Berbeda dari Timeline 0, tidak ada timestamp absurd. Petunjuk: "Look at
recent timestamps", "Pay close attention to timestamps near an
anti-forensic action", "Filter only new files by grepping for `macb`".

## Root Cause
Entri `macb` (semua timestamp m/a/c/b cocok) menandai file yang baru
dibuat dan belum pernah dimodifikasi sesudahnya — karakteristik artefak
serangan baru. Pelaku melakukan aksi anti-forensik (membersihkan jejak,
`poweroff`), tetapi satu file payload (`/etc/chat`) yang dibuat sesaat
sebelum shutdown lolos dari pembersihan. `/root/.ash_history` yang hanya
berisi `poweroff` mengonfirmasi upaya penghapusan riwayat — ironisnya
justru menjadi penanda waktu insiden.

## Rekonstruksi
1. `gzip -dc timeline-1-partition4.img.gz > p721.img`.
2. `fls -r -m / -o 0 p721.img | mactime -d > tl.csv`, lalu `grep macb` →
   aktivitas terbaru: 1 Des 2025 21:41–21:50 (install paket, lalu
   `/root/.ash_history` + `/etc/chat`).
3. `icat -o 0 p721.img 4943` (`/root/.ash_history`) → `poweroff` —
   konfirmasi anti-forensic action.
4. `icat -o 0 p721.img 32716` (`/etc/chat`) → blob Base64
   `NTc3NDE3aDEzcl83aDRuXzdoM18xNDU3XzU4NTI3YmIyMjIK`.
5. `base64 -d` → `573417h13r_7h4n_7h3_1457_58527bb222` → bungkus `academy{...}`.
6. Submit `POST /api/submissions/` → `{"correct": true}` (201).
   Otomasi: `python3 scripts/solve_721_timeline_1.py [image]`.

## Mitigasi
Forward log ke SIEM remote agar penghapusan lokal tidak menghilangkan
bukti; monitor pembuatan file di direktori sistem (`/etc`, `/bin`).

## Takeaway LKS
Klasifikasi Forensics: korelasi temporal insiden — filter `macb` +
riwayat shell yang "terlalu bersih" sebagai indikator anti-forensik.
Pola "payload lolos di samping aksi pembersihan" bersama log-wiping.
