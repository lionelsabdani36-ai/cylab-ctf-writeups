# Writeup: MatchTheRegex (Challenge ID: 356)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Regular Expression Analysis & Client-Side Logic
- **Difficulty:** Medium
- **Author:** Sunday Cyber
- **Event:** picoCTF 2023
- **Points:** 100
- **Flag:** `academy{succ3ssfully_matchtheregex_4d5352dc}`

---

## Problem Statement & Scope
Tantangan menyediakan layanan web interaktif pada kontainer on-demand. Aplikasi meminta pengguna memasukkan string ke dalam formulir input teks untuk divalidasi terhadap pola ekspresi reguler (regular expression). Peserta diminta menganalisis aturan pencocokan regex dan mengirimkan nilai input yang memenuhi kriteria untuk memperoleh flag.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Pola Regex pada Validasi Klien dan Server:**
   Inspeksi kode sumber front-end HTML/JavaScript pada fungsi pengiriman formulir `send_request()` mengungkap komentar pengembang yang membocorkan pola regex sasaran:
   ```javascript
   function send_request() {
       let val = document.getElementById("name").value;
       // ^a.....y!?
       fetch(`/flag?input=${val}`)
           .then(res => res.text())
           .then(res => {
               const res_json = JSON.parse(res);
               alert(res_json.flag)
               return false;
           })
       return false;
   }
   ```
2. **Semantik Ekspresi Reguler (`^a.....y`):**
   - Karakter anchor awal `^a`: String harus diawali dengan karakter huruf `a`.
   - Wildcard dot `.` sebanyak 5 kali: Mengharuskan tepat 5 sembarang karakter di antara awalan dan akhiran.
   - Karakter penutup `y`: Karakter ke-7 harus berupa huruf `y`.
   Nilai string `academy` memiliki panjang tepat 7 karakter, diawali huruf `a`, dan diakhiri huruf `y`, sehingga memenuhi predikat regex secara sempurna.
3. **Eksposur Endpoint API Langsung:**
   Aplikasi mengekspos endpoint HTTP GET `/flag?input=<value>` tanpa otorisasi bertingkat atau proteksi CSRF. Ketika parameter query `input` memuaskan regex validator di backend, server merespons dengan objek JSON memuat kunci `flag`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Inspeksi HTTP Response Webpage:**
   ```bash
   curl -s http://xebec.cylabacademy.net:24006/
   ```
   Ditemukan petunjuk regex `// ^a.....y!?` di dalam blok `<script>`.
2. **Penyusunan Payload yang Memenuhi Regex:**
   Memilih kata `academy` (panjang 7 karakter, diawali `a` dan diakhiri `y`).
3. **Pengiriman Permintaan ke Endpoint Flag:**
   ```bash
   curl -s "http://xebec.cylabacademy.net:24006/flag?input=academy"
   ```
   Respon JSON server:
   ```json
   {"flag":"academy{succ3ssfully_matchtheregex_4d5352dc}"}
   ```

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{succ3ssfully_matchtheregex_4d5352dc}`
- **Verifikasi Platform:** Endpoint REST API CyLab `POST /api/submissions/` merespons dengan status HTTP 201 Created:
  ```json
  {"user": 1072359, "challenge": 356, "flag": "academy{succ3ssfully_matchtheregex_4d5352dc}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
1. **Pembersihan Komentar Kode Produksi (Source Code Hygiene):** Komentar yang berisi logika bisnis sensitif, struktur kueri, atau petunjuk ekspresi reguler internal tidak boleh disertakan pada artefak produksi yang dikirim ke browser klien.
2. **Defensive Regex Implementation:** Saat merancang validasi input berbasis regex, pastikan batasan awal (`^`) dan akhir (`$`) didefinisikan secara tegas untuk mencegah bypassing parsial. Hindari regex kompleks yang rentan terhadap serangan ReDoS (Regular Expression Denial of Service).
3. **Rate Limiting & Access Control:** Endpoint yang menghasilkan token kredensial atau informasi sensitif harus menerapkan mekanisme pembatasan laju permintaan (rate limiting) dan otentikasi sesi terverifikasi.
