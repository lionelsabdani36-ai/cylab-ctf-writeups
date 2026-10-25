# Writeup: Piece by Piece (Challenge ID: 740)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / File Carving & Split Archives
- **Difficulty:** Easy
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Points:** 50
- **Flag:** `academy{z1p_and_spl1t_f1l3s_4r3_fun_6af185ac}`

---

## Deskripsi Tantangan
> After logging in, you will find multiple file parts in your home directory. These parts need to be combined and extracted to reveal the flag.

---

## Analisis & Rekonstruksi Arsip Split
Setelah login via SSH ke container (`ctf-player@xebec.cylabacademy.net`), direktori home berisi `instructions.txt` dan serangkaian file split: `part_aa`, `part_ab`, `part_ac`, `part_ad`, `part_ae`.

Header `part_aa` menunjukkan signature PK (`\x50\x4b\x03\x04`), menandakan file zip standar yang dipecah menggunakan perintah Unix `split`.

### Langkah Eksploitasi
1. Rekombinasi seluruh potongan file sesuai urutan alfabetis:
   ```bash
   cat part_aa part_ab part_ac part_ad part_ae > combined.zip
   ```
2. Ekstrak file zip dengan password yang tercantum pada instruksi (`supersecret`):
   ```bash
   unzip -P supersecret combined.zip
   ```
3. Baca isi file yang diekstrak:
   ```bash
   cat flag.txt
   ```
   *Output:* `academy{z1p_and_spl1t_f1l3s_4r3_fun_6af185ac}`
