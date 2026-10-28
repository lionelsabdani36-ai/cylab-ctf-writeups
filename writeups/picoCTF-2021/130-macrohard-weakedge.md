# Writeup: MacroHard WeakEdge (Challenge ID: 130)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / Office Document
- **Difficulty:** Medium
- **Author:** madStacks
- **Event:** picoCTF 2021
- **Points:** 200
- **Flag:** `academy{D1d_u_kn0w_ppts_r_z1p5}`

---

## Problem Statement & Scope
File `Forensics_is_fun.pptm` (PowerPoint bermakro, 100 KB): 58 slide kosong, 1 slide hidden decoy ("Not the flag"), dan makro VBA decoy (`sorry_but_this_isn't_it`). Flag disembunyikan di dalam container ZIP itu sendiri.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Format OOXML = ZIP:** `.pptm` adalah arsip ZIP; semua part (slide, makro, properti) dapat diinspeksi tanpa PowerPoint (`unzip -l`, `grep -r`).
2. **Decoy berlapis:** makro, slide hidden, dan thumbnail (`docProps/thumbnail.jpeg`, hanya teks "Forensics is fun") semuanya pengalih perhatian — analis harus memverifikasi setiap artefak, bukan berhenti di temuan pertama.
3. **File sisipan non-standar:** entri `ppt/slideMasters/hidden` (99 byte, tanggal 2026) bukan bagian dari paket Office normal; isinya teks spasi-disamarkan yang setelah spasi dihapus menjadi base64 valid (dengan padding `==`) → decode menjadi `flag: academy{...}`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Challenge statis: unduh `.pptm` dari CDN.
2. `unzip -l` → temukan entri asing `ppt/slideMasters/hidden`.
3. Ekstrak isinya: `Z m x h Z z o g Y W N h Z G V t e X t E M W R f d V 9 r b j B 3 X 3 B w d H N f c l 9 6 M X A 1 f Q`.
4. Hapus spasi, tambah padding `==`, base64-decode → `flag: academy{D1d_u_kn0w_ppts_r_z1p5}`.
5. Submit via API → `correct: true`.

---

## Flag & Verifikasi
- **Flag:** `academy{D1d_u_kn0w_ppts_r_z1p5}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Jangan percaya ekstensi file:** kenali magic/container (ZIP, OLE) dan selalu daftar isi (`unzip -l`) sebelum analisis dalam.
- **Waspadai decoy:** satu temuan "flag-like" (makro, hidden slide) bukan alasan berhenti; verifikasi hingga ke sumber resmi.
- **Spasi-disamarkan base64** adalah pola penyamaran umum — normalisasi whitespace sebelum decode.

---

## Solver
Lihat `scripts/solve_130_macrohard_weakedge.py` — membuka pptm sebagai ZIP, mengekstrak entri hidden, dan men-decode flag.
