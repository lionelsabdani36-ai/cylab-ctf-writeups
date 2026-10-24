# Writeup: rsa_oracle (Challenge ID: 422)

- **Platform:** CyLab Security Academy (picoCTF 2024)
- **Category:** Cryptography / RSA Chosen Ciphertext Attack (CCA)
- **Difficulty:** Medium
- **Playlist:** Cryptography and Challenge Library Learning Intro (Module 140)
- **Points:** 300
- **Flag:** `academy{su((3ss_(r@ck1ng_r3@_4263a53c}`

---

## Deskripsi Tantangan
> Can you abuse the oracle? An attacker was able to intercept communications between a bank and a fintech company. They managed to get the message (ciphertext) and the password that was used to encrypt the message. The bank has an oracle that was used to encrypt the password: nc chatelaine.cylabacademy.net 40788.
> Files: `secret.enc`, `password.enc`

---

## Analisis & Eksploitasi Sifat Homomorfik RSA
Server oracle menyediakan antarmuka Enkripsi (`E`) dan Dekripsi (`D`), namun menolak mendeskripsi langsung ciphertext target $C_{target} = M^e \pmod N$.

Karena RSA bersifat multiplikatif homomorfik:
$$(m_1 \cdot m_2)^e \equiv m_1^e \cdot m_2^e \pmod N$$

### Langkah Eksploitasi
1. Mengirim perintah enkripsi untuk karakter `\x02` ke oracle untuk memperoleh $C_2 = 2^e \pmod N$.
2. Membentuk ciphertext terselubung (*blinded ciphertext*):
   $$C_{blind} = C_{target} \times C_2 \equiv (2M)^e \pmod N$$
3. Karena $C_{blind} \ne C_{target}$, oracle menerima dan mendeskripsinya:
   $$M_{blind} = (C_{blind})^d \equiv 2M \pmod N$$
4. Menghitung nilai asli password:
   $$M = M_{blind} // 2$$
   Hasil desimal $M$ dikonversi menjadi byte teks: `4263a`.
5. Mendeskripsi berkas `secret.enc` via OpenSSL menggunakan cipher AES-256-CBC dan password `4263a`:
   ```bash
   openssl enc -aes-256-cbc -d -in secret.enc -k 4263a -md sha256
   ```
   Output: `academy{su((3ss_(r@ck1ng_r3@_4263a53c}`.

Flag: `academy{su((3ss_(r@ck1ng_r3@_4263a53c}`.
