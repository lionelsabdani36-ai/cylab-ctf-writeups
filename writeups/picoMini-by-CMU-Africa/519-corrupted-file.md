# Writeup: Corrupted file (Challenge ID: 519)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / File Carving & Header Repair
- **Difficulty:** Easy
- **Author:** Yahaya Meddy
- **Event:** picoMini by CMU-Africa
- **Points:** 100
- **Flag:** `academy{r3st0r1ng_th3_by73s_a6f66bd7}`

---

## Deskripsi Tantangan
> This file seems broken... or is it? Maybe a couple of bytes could make all the difference. Can you figure out how to bring it back to life?
> Download the file `file`.
> Hints:
> 1. Try checking the file’s header.
> 2. JPEG
> 3. Tools like xxd or hexdump can help you inspect and edit file bytes.

---

## Analisis Kerentanan & Konsep Teknis
Setiap format berkas biner memiliki *magic bytes* (signature) pada header awal yang menentukan bagaimana sistem operasi dan aplikasi pembaca mengenali struktur berkas tersebut.

Pada format citra JPEG/JFIF:
- **Start of Image (SOI):** Ditandai dengan 2 byte biner `FF D8`.
- **Marker APP0 (JFIF):** Mengikuti penanda SOI dengan `FF E0 00 10 4A 46 49 46` (`JFIF`).
- **End of Image (EOI):** Diakhiri dengan `FF D9`.

Pemeriksaan heksadesimal terhadap berkas tantangan menunjukkan:
```text
00000000: 5c 78 ff e0 00 10 4a 46 49 46 ... (\x..JFIF)
```
Dua byte pertama sengaja dirusak menjadi `5C 78` (string ASCII `\x`). Akibatnya, utilitas seperti `file` dan penampil gambar menolak membuka berkas karena penanda SOI hilang. Sementara segmen bodi citra dan marker penutup `FF D9` masih utuh.

---

## Tahapan Eksploitasi & Solusi
1. Perbaiki 2 byte pertama berkas dari `5C 78` menjadi `FF D8`:
   ```bash
   python3 -c '
   with open("file", "rb") as f:
       data = bytearray(f.read())
   data[0] = 0xFF
   data[1] = 0xD8
   with open("restored.jpg", "wb") as f:
       f.write(data)
   '
   ```
2. Verifikasi tipe berkas setelah perbaikan:
   ```bash
   file restored.jpg
   # restored.jpg: JPEG image data, JFIF standard 1.01, ..., 800x500
   ```
3. Buka gambar hasil restorasi. Gambar menampilkan tulisan merah jelas di atas kanvas putih:
   ```text
   academy{r3st0r1ng_th3_by73s_a6f66bd7}
   ```

---

## Pembelajaran Defensif & Mitigasi LKS
- **Validasi Magic Bytes vs Ekstensi:** Sistem backend yang memproses unggahan berkas tidak boleh hanya bergantung pada ekstensi berkas (`.jpg`, `.png`), melainkan wajib melakukan verifikasi magic bytes dan integritas struktur internal (strict MIME type validation).
- **Teknik File Carving:** Dalam investigasi forensik digital, berkas yang dihapus atau sebagian ditimpa sering kali dapat dipulihkan (*carved*) dengan merekonstruksi penanda header/footer biner yang rusak.
