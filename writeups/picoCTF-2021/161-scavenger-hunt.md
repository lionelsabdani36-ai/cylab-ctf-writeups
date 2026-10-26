# Writeup: Scavenger Hunt (Challenge ID: 161)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Web Reconnaissance & Configuration File Exposure
- **Difficulty:** Easy
- **Author:** madStacks
- **Event:** picoCTF 2021
- **Points:** 50
- **Flag:** `academy{th4ts_4_l0t_0f_pl4c3s_2_lO0k_2b9c61f}`

---

## Problem Statement & Scope
Disediakan sebuah situs web statis sederhana. Peserta ditantang untuk mengikuti jejak petunjuk berantai (*scavenger hunt*) yang tersebar di berbagai berkas konfigurasi web server dan artefak sistem berkas untuk merekonstruksi pecahan token flag yang terpisah.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Sensitivitas File Metadata & Server Control Files:**
   - **Komentar Markup & Stylesheet:** Browser mengunduh komentar HTML (`<!-- ... -->`) dan CSS (`/* ... */`) secara publik.
   - **`robots.txt`:** Berkas instruksi perayap mesin pencari (*crawlers*) sering kali secara tidak sengaja mengungkap direktori dan rute rahasia yang ingin disembunyikan.
   - **`.htaccess`:** Berkas konfigurasi tingkat direktori pada web server Apache. Jika konfigurasi web server mengizinkan pembacaan berkas titik (*dotfiles*), aturan akses dan data internal dapat bocor.
   - **`.DS_Store` (Desktop Services Store):** Berkas metadata kepemilikan macOS yang dibuat secara otomatis oleh Finder untuk menyimpan atribut tata letak folder. Mengunggah folder proyek dari macOS tanpa filter `.gitignore` membocorkan struktur direktori privat.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Langkah 1 (HTML Comment):**
   Akses `index.html` dan periksa komentar penutup:
   ```bash
   curl -s http://xebec.cylabacademy.net:46774/ | grep -o "academy{[a-z0-9_]*"
   # Part 1: academy{t
   ```
2. **Langkah 2 (CSS Comment):**
   Periksa berkas stylesheet `mycss.css`:
   ```bash
   curl -s http://xebec.cylabacademy.net:46774/mycss.css | tail -n 1
   # /* CSS makes the page look nice, and yes, it also has part of the flag. Here's part 2: h4ts_4_l0 */
   # Part 2: h4ts_4_l0
   ```
3. **Langkah 3 (Robots.txt):**
   Petunjuk pada `myjs.js` menyebutkan *"How can I keep Google from indexing my website?"*, yang mengarah pada `robots.txt`:
   ```bash
   curl -s http://xebec.cylabacademy.net:46774/robots.txt
   # # Part 3: t_0f_pl4c
   # # I think this is an apache server... can you Access the next flag?
   # Part 3: t_0f_pl4c
   ```
4. **Langkah 4 (Apache `.htaccess`):**
   Kata kunci *"Access"* merujuk pada berkas konfigurasi Apache `.htaccess`:
   ```bash
   curl -s http://xebec.cylabacademy.net:46774/.htaccess
   # # Part 4: 3s_2_lO0k
   # # I love making websites on my Mac, I can Store a lot of information there.
   # Part 4: 3s_2_lO0k
   ```
5. **Langkah 5 (macOS `.DS_Store`):**
   Kata kunci *"Mac"* dan *"Store"* merujuk pada artefak metadata macOS `.DS_Store`:
   ```bash
   curl -s http://xebec.cylabacademy.net:46774/.DS_Store
   # Congrats! You've completed the scavenger hunt! Part 5: _2b9c61f}
   # Part 5: _2b9c61f}
   ```
6. **Penggabungan Pecahan Flag:**
   $$\text{academy\{t} + \text{h4ts\_4\_l0} + \text{t\_0f\_pl4c} + \text{3s\_2\_lO0k} + \text{\_2b9c61f\}} = \text{academy\{th4ts\_4\_l0t\_0f\_pl4c3s\_2\_lO0k\_2b9c61f\}}$$

---

## Flag & Verifikasi
- **Flag:** `academy{th4ts_4_l0t_0f_pl4c3s_2_lO0k_2b9c61f}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Pemblokiran Akses Dotfiles (Apache & Nginx Hardening):** Konfigurasikan aturan server global untuk menolak akses ke seluruh berkas yang diawali titik:
  ```nginx
  location ~ /\. {
      deny all;
      return 404;
  }
  ```
- **Filter Berkas Build / Deployment:** Sertakan pola `.DS_Store`, `.git*`, `*.swp`, dan `.env*` pada berkas `.gitignore` serta bersihkan direktori kerja sebelum pembuatan image container produksi.
