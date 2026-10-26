# Writeup: Bookmarklet (Challenge ID: 406)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Client-Side Cryptography
- **Difficulty:** Easy
- **Author:** Jeffery John
- **Event:** picoCTF 2024
- **Points:** 50
- **Flag:** `academy{p@g3_turn3r_f1291985}`

---

## Problem Statement & Scope
Disediakan sebuah aplikasi web sederhana yang mendistribusikan flag melalui kode JavaScript Bookmarklet. Kode bookmarklet disediakan dalam elemen `<textarea>` agar dieksekusi di browser oleh pengguna untuk menampilkan flag terdekripsi.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Client-Side Obfuscation vs Real Security:** Aplikasi web menyimpan algoritma dekripsi dan ciphertext flag langsung di sisi klien (browser). Penggunaan kunci simetris statis (`picoctf`) yang tertanam langsung di kode sumber JavaScript (*hardcoded key*) tidak memberikan perlindungan keamanan substantif.
2. **Reversibilitas Operasi Aritmatika Byte:** Skema enkripsi yang diterapkan berupa substitusi pergeseran byte modular sederhana:
   $$C_i = (P_i + K_{i \pmod{|K|}}) \pmod{256}$$
   Operasi inversi dapat dilakukan secara trivial:
   $$P_i = (C_i - K_{i \pmod{|K|}} + 256) \pmod{256}$$

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Akses halaman instance web menggunakan browser atau `curl`:
   ```bash
   curl -s http://xebec.cylabacademy.net:25770/
   ```
2. Temukan blok kode JavaScript Bookmarklet pada elemen `<textarea id="bookmarkletCode">`:
   ```javascript
   javascript:(function() {
       var encryptedFlag = "ÑÌÄÓÈáßëÙ£Ö\x96ÓÚåÛÑ¢ÕÓÌ¡\x9b\x9c\xa0\x9c¬\x9bí";
       var key = "picoctf";
       var decryptedFlag = "";
       for (var i = 0; i < encryptedFlag.length; i++) {
           decryptedFlag += String.fromCharCode((encryptedFlag.charCodeAt(i) - key.charCodeAt(i % key.length) + 256) % 256);
       }
       alert(decryptedFlag);
   })();
   ```
3. Eksekusi logika dekripsi menggunakan skrip Python mandiri:
   ```python
   enc = "ÑÌÄÓÈáßëÙ£Ö\x96ÓÚåÛÑ¢ÕÓÌ¡\x9b\x9c\xa0\x9c¬\x9bí"
   key = "picoctf"
   flag = "".join(chr((ord(enc[i]) - ord(key[i % len(key)]) + 256) % 256) for i in range(len(enc)))
   print(flag)
   # Output: academy{p@g3_turn3r_f1291985}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{p@g3_turn3r_f1291985}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Zero Trust pada Client-Side Execution:** Jangan pernah melakukan autentikasi data sensitif atau menyimpan rahasia penting di sisi browser klien. Semua otorisasi akses dan payload rahasia wajib diproses dan divalidasi di lingkungan backend server.
- **Prinsip Kerckhoffs:** Keamanan sebuah sistem kriptografi harus bergantung pada kerahasiaan kunci, bukan pada kerahasiaan algoritma. Menempatkan ciphertext dan kunci bersamaan di frontend membuat enkripsi menjadi tidak berarti (*security by obscurity*).
