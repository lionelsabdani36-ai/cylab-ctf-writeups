# Writeup: mus1c (Challenge ID: 15)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Esoteric Language (Rockstar)
- **Difficulty:** Easy
- **Author:** picoCTF
- **Event:** picoCTF 2019
- **Points:** 100
- **Flag:** `academy{rrrocknrn0113r}`

---

## Problem Statement & Scope
Diberikan file lirik lagu (`mus1c-lyrics.txt`) sepanjang 55 baris yang tampak seperti puisi rock. Petunjuk tantangan ("master rockstar") mengarahkan ke bahasa pemrograman esoterik **Rockstar**, di mana kode sumber menyerupai lirik lagu. Tugas: jalankan "lagu" sebagai program, baca keluarannya, dan kemas dalam format `academy{...}`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Bahasa Esoterik Rockstar:** Variabel berupa *proper noun* (`Pico`, `CTF`, `Fun`), *common noun* (`my song`, `my lyric`), dan pronomina (`It`, `it`) yang merujuk variabel terakhir disebut. Literal angka puitis (*poetic number literal*): tiap kata menyumbang digit = jumlah huruf mod 10 (mis. `waitin` = 6).
2. **Operator Kata Inggris:** `Put X into Y` (penugasan), `with` (tambah), `without` (kurang), `times` (kali), `of` (kali), `Knock X down` (kurangi 1), `Build X up` (tambah 1), `Shout X` (cetak).
3. **Kelemahan yang Dieksploitasi:** Program menyembunyikan data sebagai **kode ASCII desimal** yang dicetak satu per satu — pola klasik penyamaran data dalam CTF forensik.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Unduh artefak statis:
   ```bash
   curl -sL -O https://challenge-files.cylabacademy.net/library/d67c9614df4e4d89b88fd6b36560c74a0644cd3ecc3b9c82af762568eb7c875d/mus1c-lyrics.txt
   ```
2. Jalankan dengan transpiler `rockstar-py` 2.1.0 (sezaman dengan tantangan, 2018). Normalisasi yang diperlukan agar sesuai dialeknya:
   - Kapitalisasi keyword (`Put`, `Knock`, `Build`, `Shout`).
   - `my flag is not found` → `My flag is vague` (menghindari parse `is not` sebagai perbandingan; nilai baris ini tertimpa sehingga tidak memengaruhi hasil).
   - `security`/`fun` → `Security`/`Fun` (variabel umum harus kapital/diawali artikel).
   - Pronomina sisi-kiri (`Build it up`, `Shout it`) diganti nama variabel terakhir yang dirujuk.
   - `Build X up, up` multi-inkremen dipecah menjadi baris tunggal.
3. Keluaran program:
   ```text
   114 114 114 111 99 107 110 114 110 48 49 49 51 114
   ```
4. Konversi tiap angka via tabel ASCII: 114=`r`, 111=`o`, 99=`c`, 107=`k`, 110=`n`, 48=`0`, 49=`1`, 51=`3` → `rrrocknrn0113r`.

---

## Flag & Verifikasi
- **Flag:** `academy{rrrocknrn0113r}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Kenali Bahasa Esoterik Populer:** Rockstar, Brainfuck, Whitespace, dan Piet sering muncul di kategori General Skills. Bangun *playbook*: "kode aneh → cari bahasa → cari interpreter".
- **Pin Versi Interpreter:** Dialek bahasa esoterik berubah antar versi; untuk reproduksibilitas, catat versi interpreter yang dipakai (di sini `rockstar-py==2.1.0`).
- **Mitigasi:** Jangan mengandalkan *security by obscurity* — menyamarkan data sebagai "puisi" bukan enkripsi. Data sensitif harus dienkripsi dengan algoritma standar, bukan disamarkan formatnya.
