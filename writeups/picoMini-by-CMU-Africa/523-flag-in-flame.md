# Writeup: Flag in Flame (Challenge ID: 523)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Forensics / File Reconstruction & Image Inspection
- **Difficulty:** Easy
- **Author:** Prince Niyonshuti N.
- **Event:** picoMini by CMU-Africa
- **Points:** 100
- **Flag:** `academy{forensics_analysis_is_amazing_2043dbd1}`

---

## Deskripsi Tantangan
> The SOC team discovered a suspiciously large log file after a recent breach. When they opened it, they found an enormous block of encoded text instead of typical logs. Could there be something hidden within? Your mission is to inspect the resulting file and reveal the real purpose of it.
> Download the encoded data here: `logs.txt`.
> Hints:
> 1. Use base64 to decode the data and generate the image file.

---

## Analisis Kerentanan & Konsep Teknis
Dalam insiden eksfiltrasi data, penyerang sering kali mengenkapsulasi berkas biner (gambar tangkapan layar, dokumen curian) ke dalam format teks Base64 agar dapat diselipkan di antara lalu lintas log atau komunikasi HTTP biasa tanpa memicu deteksi inspeksi ASCII sederhana.

1. Berkas `logs.txt` berisi satu blok data Base64 panjang. Header Base64 dimulai dengan `iVBORw0KGgoAAAANSUhEUg...`, yang merupakan representasi baku dari signature berkas PNG (`\x89PNG\r\n\x1a\n`).
2. Setelah didekode, dihasilkan gambar PNG berukuran 896x1152 piksel yang menampilkan ilustrasi bertema hacker/cyberpunk.
3. Di bagian margin bawah ilustrasi, tepat di bawah meja laptop, terdapat teks heksadesimal yang dicetak bersih:
   ```text
   61636164656D797B666F72656E736963735F616E616C797369735F69735F616D617A696E675F32303433646264317D
   ```
4. Mengonversi string hex ke representasi ASCII menghasilkan token flag lengkap.

---

## Tahapan Eksploitasi & Solusi
1. Dekode berkas teks Base64 menjadi berkas citra PNG:
   ```bash
   base64 -d logs.txt > reconstructed.png
   ```
2. Baca string heksadesimal yang tercetak di batas bawah gambar dan dekode ke teks ASCII:
   ```python
   hex_str = "61636164656D797B666F72656E736963735F616E616C797369735F69735F616D617A696E675F32303433646264317D"
   print(bytes.fromhex(hex_str).decode("utf-8"))
   ```
3. Hasil dekode:
   ```text
   academy{forensics_analysis_is_amazing_2043dbd1}
   ```

---

## Pembelajaran Defensif & Mitigasi LKS
- **Deteksi Anomali Entropi Log:** Berkas log teks yang normal memiliki rasio karakter dan entropi Shannon yang teratur. Lonjakan string Base64 monolitik dapat dideteksi secara otomatis melalui aturan analitik SIEM (misal Sigma / Elastic rules berbasis deteksi entropi tinggi).
