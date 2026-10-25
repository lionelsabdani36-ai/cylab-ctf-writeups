# Writeup: StegoRSA (Challenge ID: 719)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Steganography
- **Difficulty:** Easy
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Points:** 100
- **Flag:** `academy{rs4_k3y_1n_1mg_21d0a083}`

---

## Deskripsi Tantangan
> A message has been encrypted using RSA. The public key is gone... but someone might have been careless with the private key. Can you recover it and decrypt the message?

---

## Analisis & Ekstraksi Metadata Gambar
Tantangan menyediakan dua berkas: `image.jpg` dan ciphertext RSA `flag.enc`.

Pemeriksaan raw byte dan string pada `image.jpg` menemukan payload berukuran 3.410 karakter heksadesimal yang diawali dengan:
`2d2d2d2d2d424547494e2050524956415445204b4559...`

Nilai heksadesimal tersebut diterjemahkan menjadi ASCII teks:
`-----BEGIN PRIVATE KEY-----`

### Langkah Eksploitasi
1. Ekstraksi string heksadesimal dari JPEG dan konversi kembali ke format PEM:
   ```python
   pem_key = bytes.fromhex(hex_string).decode()
   ```
2. Dekripsi ciphertext `flag.enc` menggunakan OpenSSL utility:
   ```bash
   openssl pkeyutl -decrypt -inkey recovered_priv.pem -in flag.enc
   ```
   *Output:* `academy{rs4_k3y_1n_1mg_21d0a083}`
