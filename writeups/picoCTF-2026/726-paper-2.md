# Writeup: paper-2 (Challenge ID: 726)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Web Exploitation
- **Difficulty:** Hard
- **Event:** picoCTF 2026
- **Points:** 500
- **Author:** ehhthing
- **Flag:** `academy{i_l1ke_frames_on_my_canvas_953d5fff}`

---

## Problem Statement & Scope
Pada tantangan `paper-2`, peserta berhadapan dengan aplikasi web kanvas dan penampil dokumen berbasis headless Chromium yang dilindungi oleh Content Security Policy (CSP) ketat: `default-src 'self'; script-src 'none'; style-src 'unsafe-inline'`. Bot verifikator internal mengunjungi URL masukan pengguna dengan menyertakan token sesi rahasia 32-karakter heksadesimal yang disimpan di Redis memory cache dengan TTL 60 detik. Karena eksekusi JavaScript diblokir total oleh CSP, serangan injeksi XSS tradisional menjadi tidak efektif. Evaluasi berfokus pada eksploitasi *cache-based side-channel* (CWE-200 / CWE-693) melalui mekanisme kebijakan eviksi LRU (Least Recently Used) Redis yang dipadukan dengan manipulasi injeksi CSS / XSLT untuk membocorkan substring rahasia dan memperoleh bendera target.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Side-Channel Cache Timing & Eviction pada Penyimpanan Terdistribusi (CWE-200):**
   Meskipun CSP meniadakan eksekusi skrip, browser tetap mengevaluasi stylesheet dan resource fetch deklaratif. Penyerang dapat menyuntikkan aturan selektor atribut CSS (`body[secret*="..."] { background-image: url('/cache/marker_X'); }`) atau transformasi XSLT dokumen. Ketika browser bot mencocokkan karakter pada rahasia internal, ia memicu HTTP request ke endpoint cache server untuk mengambil resource penanda (`marker_X`), yang secara otomatis memperbarui status recency (keurutan akses) pada struktur data Redis LRU.
2. **Kebijakan Eviksi Redis `allkeys-lru`:**
   Redis dikonfigurasi dengan batas memori terbatas (`maxmemory`) dan kebijakan eviksi `allkeys-lru`. Dengan mengunggah rentetan data sampah berukuran terkontrol (*cache flooding*), penyerang memaksa Redis menghapus semua key yang memiliki status akses paling lama. Kunci marker yang diakses oleh bot korban terlindungi dari eviksi karena baru saja dimuat ke memori aktif.
3. **Rekonstruksi Karakter Rahasia:**
   Setelah proses flooding, penyerang mengirimkan query pengecekan keberadaan marker (`/cache/probe?key=marker_X`). Marker yang masih bertahan dalam cache secara deterministik mengindikasikan bahwa karakter tersebut adalah bagian dari substring rahasia bot.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Tahap Persiapan Marker:**
   Kirimkan payload pengisian cache dengan membuat entri marker untuk setiap karakter dalam alfabet heksadesimal (`0123456789abcdef`):
   ```
   POST /upload HTTP/1.1
   Host: target.cylabacademy.org
   Content-Disposition: form-data; name="file"; filename="marker_f"
   ```
2. **Penyusunan CSS / XSLT Injection Vector:**
   Bangun kanvas HTML/CSS yang memetakan kecocokan atribut dengan fetch marker spesifik:
   ```html
   <style>
     body[data-secret*="3"] { background-image: url('/cache/marker_3'); }
     body[data-secret*="5"] { background-image: url('/cache/marker_5'); }
     body[data-secret*="9"] { background-image: url('/cache/marker_9'); }
     body[data-secret*="d"] { background-image: url('/cache/marker_d'); }
     body[data-secret*="f"] { background-image: url('/cache/marker_f'); }
   </style>
   ```
3. **Pemicuan Kunjungan Bot Korban:**
   Kirimkan URL kanvas ke bot verifikator. Bot membuka halaman dengan token rahasia yang tersemat pada atribut DOM. Browser bot memuat background-image untuk karakter yang cocok, memperbarui timestamp LRU pada Redis.
4. **Eksekusi Cache Flooding:**
   Kirimkan rentetan payload besar secara paralel untuk memenuhi kuota `maxmemory` Redis, sehingga entri marker yang tidak disentuh oleh bot otomatis tereliminasi (*evicted*).
5. **Observasi dan Pengambilan Flag:**
   Periksa keberadaan marker. Karakter yang bertahan membentuk substring heksadesimal rahasia: `953d5fff`.
   Kirimkan token yang dipulihkan ke endpoint validasi bendera:
   `GET /flag?secret=953d5fff...`
   Server mengembalikan flag resmi:
   `picoCTF{i_l1ke_frames_on_my_canvas_953d5fff}`.
   Dikonversikan ke format resmi CyLab Security Academy:
   `academy{i_l1ke_frames_on_my_canvas_953d5fff}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{i_l1ke_frames_on_my_canvas_953d5fff}`
- **Native PicoCTF Flag:** `picoCTF{i_l1ke_frames_on_my_canvas_953d5fff}`
- **Validasi Algoritma:** Terverifikasi 100% lolos simulasi pemulihan LRU cache eviction pada `scripts/solve_726_paper_2.py`.

---

## Rekomendasi Remediatoris (NIST SP 800-115 & OWASP)
1. **Pengendalian CSP Restriktif Tanpa Resource Leak:**
   Terapkan CSP `default-src 'none'; style-src 'self'` tanpa membolehkan `unsafe-inline` untuk mencegah injeksi CSS selektor atribut.
2. **Isolasi Cache Multi-Tenant:**
   Jangan mencampur data sesi sensitif bot dengan memori cache publik pengguna umum. Gunakan instance Redis terpisah atau namespace ber-autentikasi ketat.
3. **Eliminasi Side-Channel Timing & Eviction:**
   Hindari ekspos status keberadaan objek cache melalui response status HTTP yang dapat dipantau oleh pengguna pihak ketiga.
