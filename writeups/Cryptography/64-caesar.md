# Writeup: caesar (Challenge ID: 64)

- **Platform:** CyLab Security Academy (picoCTF 2019)
- **Category:** Cryptography / Caesar Cipher
- **Difficulty:** Easy
- **Playlist:** Cryptography and Challenge Library Learning Intro (Module 133)
- **Points:** 100
- **Flag:** `academy{crossingtherubiconulqcojpd}`

---

## Deskripsi Tantangan
> Decrypt this message.
> Ciphertext file: `data.enc`

---

## Analisis & Solusi
Berkas `data.enc` berisi:
```text
academy{jyvzzpunaolybipjvubsxjvqwk}
```
Karakter di dalam kurung kurawal `jyvzzpunaolybipjvubsxjvqwk` dienkripsi menggunakan substitusi Caesar shift.
Melakukan brute force pergeseran dari shift 1 hingga 25:
Pada shift 7:
- `'j'` - 7 = `'c'`
- `'y'` - 7 = `'r'`
- `'v'` - 7 = `'o'`
- `'z'` - 7 = `'s'`
- ...
Membentuk kata bahasa Inggris valid: `crossingtherubiconulqcojpd`.

Flag: `academy{crossingtherubiconulqcojpd}`.
