# Writeup: dont-use-client-side (Challenge ID: 66)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Client-Side Logic Flaws
- **Difficulty:** Easy
- **Author:** Alex Fulton/Danny
- **Event:** picoCTF 2019
- **Points:** 100
- **Flag:** `academy{no_clients_plz_737003cf}`

---

## Problem Statement & Scope
Disediakan sebuah halaman login web ("Secure Login Portal") yang mengklaim memiliki verifikasi kredensial super aman. Pengguna diminta memasukkan kata sandi yang valid untuk melewati portal dan membuktikan autentikasi berhasil.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pemeriksaan Kredensial di Sisi Klien (Client-Side Verification):** Logika autentikasi dieksekusi secara lokal di dalam browser klien menggunakan fungsi JavaScript `verify()`. Seluruh kode logika, nilai string perbandingan, dan pemotongan substring terbuka untuk dibaca oleh siapapun yang memiliki akses ke kode sumber dokumen HTML.
2. **Ketiadaan Otentikasi Server:** Server hanya berperan sebagai penyaji berkas HTML statis. Formulir tidak mengirimkan kredensial ke endpoint backend yang aman, melainkan mengandalkan `onclick="verify(); return false;"`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Akses halaman instance target menggunakan `curl`:
   ```bash
   curl -s http://xebec.cylabacademy.net:44685/
   ```
2. Analisis fungsi JavaScript `verify()` di dalam tag `<script>`:
   ```javascript
   function verify() {
     checkpass = document.getElementById("pass").value;
     split = 4;
     if (checkpass.substring(0, split) == 'acad') {
       if (checkpass.substring(split*6, split*7) == '3700') {
         if (checkpass.substring(split, split*2) == 'emy{') {
          if (checkpass.substring(split*4, split*5) == 'ts_p') {
           if (checkpass.substring(split*3, split*4) == 'lien') {
             if (checkpass.substring(split*5, split*6) == 'lz_7') {
               if (checkpass.substring(split*2, split*3) == 'no_c') {
                 if (checkpass.substring(split*7, split*8) == '3cf}') {
                   alert("Password Verified")
                   }
                 }
               }
             }
           }
         }
       }
     }
     else {
       alert("Incorrect password");
     }
   }
   ```
3. Susun kembali urutan potongan string berdasarkan offset blok 4 karakter:
   - Offset `[0:4]` (`0, split`): `acad`
   - Offset `[4:8]` (`split, split*2`): `emy{`
   - Offset `[8:12]` (`split*2, split*3`): `no_c`
   - Offset `[12:16]` (`split*3, split*4`): `lien`
   - Offset `[16:20]` (`split*4, split*5`): `ts_p`
   - Offset `[20:24]` (`split*5, split*6`): `lz_7`
   - Offset `[24:28]` (`split*6, split*7`): `3700`
   - Offset `[28:32]` (`split*7, split*8`): `3cf}`
4. Gabungkan seluruh segmen:
   $$\text{acad} + \text{emy\{} + \text{no\_c} + \text{lien} + \text{ts\_p} + \text{lz\_7} + \text{3700} + \text{3cf\}} = \text{academy\{no\_clients\_plz\_737003cf\}}$$

---

## Flag & Verifikasi
- **Flag:** `academy{no_clients_plz_737003cf}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Arsitektur Zero Trust Client:** Klien browser harus diperlakukan sebagai lingkungan yang sepenuhnya tidak terpercaya (*untrusted environment*). Validasi kata sandi, otorisasi peran pengguna, dan logika bisnis kritis wajib selalu dijalankan pada server backend.
- **Penyimpanan Kredensial Terproteksi:** Kredensial tidak boleh disimpan dalam kode sumber mentah maupun skrip frontend. Gunakan hash satu arah bergaram (*salted password hash*) di database terproteksi.
