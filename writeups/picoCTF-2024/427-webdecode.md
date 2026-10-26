# Writeup: WebDecode (Challenge ID: 427)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / DOM Inspection
- **Difficulty:** Easy
- **Author:** Nana Ama Atombo-Sackey
- **Event:** picoCTF 2024
- **Points:** 50
- **Flag:** `academy{web_succ3ssfully_d3c0ded_9d72a8f6}`

---

## Problem Statement & Scope
Diberikan situs web profil sederhana yang terdiri dari beberapa halaman (`index.html`, `about.html`, `contact.html`). Peserta diminta menavigasi struktur situs dan menggunakan kapabilitas Web Inspector untuk menemukan flag tersembunyi.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Penggunaan Custom Attribute pada Tag HTML:** Pengembang sering menyematkan atribut kustom (seperti `notify_true`, `data-*`) untuk keperluan internal JavaScript atau penandaan status. Atribut ini terbaca sepenuhnya oleh klien.
2. **Kelemahan Enkoding Base64:** Pengkodean Base64 hanyalah representasi biner-ke-teks ASCII untuk transmisi data melalui media berbasis teks, bukan algoritma kriptografi yang aman. Penyerang dapat langsung membalikkan (*decode*) string Base64 dalam waktu konstan.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Lakukan enumerasi tautan yang ada pada halaman utama (`http://chatelaine.cylabacademy.net:33003/`):
   - `index.html`
   - `about.html`
   - `contact.html`
2. Periksa kode sumber halaman `about.html`:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:33003/about.html
   ```
3. Temukan elemen section dengan atribut kustom `notify_true`:
   ```html
   <section class="about" notify_true="YWNhZGVteXt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfOWQ3MmE4ZjZ9">
   ```
4. Lakukan decoding Base64 pada payload atribut:
   ```bash
   echo "YWNhZGVteXt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfOWQ3MmE4ZjZ9" | base64 -d
   # Output: academy{web_succ3ssfully_d3c0ded_9d72a8f6}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{web_succ3ssfully_d3c0ded_9d72a8f6}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Sensitivitas Data dalam DOM:** Informasi otentikasi, ID pengguna privat, atau data operasional rahasia tidak boleh disematkan ke dalam atribut elemen HTML DOM.
- **Penyimpanan Status Berbasis Server:** Jika data diperlukan oleh antarmuka pengguna, kirimkan hanya saat otentikasi telah terverifikasi melalui API terproteksi dengan header otorisasi (Bearer Token / Cookie HttpOnly).
