# Writeup: It is my Birthday (Challenge ID: 109)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / MD5 Collision
- **Difficulty:** Easy
- **Author:** madStacks
- **Event:** picoCTF 2021
- **Points:** 100
- **Flag:** `academy{c0ngr4ts_u_r_1nv1t3d_44f9d0a}`

---

## Problem Statement & Scope
Aplikasi PHP menerima dua unggahan "undangan" PDF dan mengundang pengunggah jika kedua file berbeda tetapi memiliki hash MD5 yang sama (verifikasi via `md5_file`, batas ukuran 18 KiB, tipe MIME harus `application/pdf`, pengecekan ekstensi saja).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **MD5 Broken (Wang et al. 2004):** Kolisi MD5 *identical-prefix* dapat dipakai langsung; pasangan blok kolisi publik `TEXTCOLLBYfGiJUETHQ...` memberi dua file berbeda dengan MD5 sama `faad49866e9498fc1719f5289e7a0269`.
2. **Validasi File Lemah:** Pengecekan hanya tipe MIME/ekstensi sisi klien, bukan *magic number* — file teks 69-byte lolos sebagai `.pdf`.
3. **Logika Bisnis Berbahaya:** Kesetaraan hash ≠ kesetaraan identitas; desain "dua undangan mirip" justru memberi oracle kolisi.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Mulai instance on-demand; dapatkan URL (contoh `http://xebec.cylabacademy.net:30077/`).
2. Buat pasangan kolisi tanpa newline:
   ```bash
   printf '%s' 'TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak' > c1.pdf
   printf '%s' 'TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak' > c2.pdf
   md5sum c1.pdf c2.pdf  # identik
   ```
3. Unggah dengan tipe eksplisit `application/pdf`:
   ```bash
   curl -F "file1=@c1.pdf;type=application/pdf" -F "file2=@c2.pdf;type=application/pdf" \
        -F "submit=Upload" http://xebec.cylabacademy.net:30077/index.php
   ```
4. Server menampilkan source via `highlight_file` dengan flag pada komentar HTML: `academy{c0ngr4ts_u_r_1nv1t3d_44f9d0a}`.

---

## Flag & Verifikasi
- **Flag:** `academy{c0ngr4ts_u_r_1nv1t3d_44f9d0a}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Tinggalkan MD5/SHA-1:** Gunakan SHA-256+ untuk integritas; anggap MD5 hanya checksum non-keamanan.
- **Validasi Server-Side:** Periksa *magic bytes*, batasi ukuran, simpan di luar webroot dengan nama acak.
- **Jangan Bocorkan Source:** Nonaktifkan `highlight_file`/stack trace di produksi.

---

## Solver
Lihat `scripts/solve_109_it_is_my_birthday.py` — membangun pasangan kolisi MD5 dan mengunggahnya.
