# Writeup: Shared Secrets (Challenge ID: 715)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Cryptography / Diffie-Hellman Key Exchange
- **Difficulty:** Easy
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Points:** 100
- **Flag:** `academy{dh_s3cr3t_e3954beb}`

---

## Deskripsi Tantangan
> A message was encrypted using a shared secret... but it looks like one side of the exchange leaked something. Can you piece together the secret and get the flag?

---

## Analisis Kriptografi (Diffie-Hellman Key Derivation)
Protokol pertukaran kunci Diffie-Hellman menetapkan parameter publik modulus $p$ dan generator $g = 2$.
Server menghasilkan kunci publik $A = g^a \pmod p$.
Klien menghasilkan kunci publik $B = g^b \pmod p$ dengan rahasia pribadi $b$.
Kunci bersama dihitung sebagai:
$$K = A^b \equiv (g^a)^b \equiv g^{ab} \pmod p$$
Flag dienkripsi menggunakan operasi XOR byte-wise dengan kunci $k = K \pmod{256}$.

Karena file `message.txt` membocorkan nilai rahasia klien $b$, kunci bersama $K$ dapat dihitung secara instan tanpa perlu memecahkan *Discrete Logarithm Problem* (DLP).

### Langkah Rekonstruksi Kunci
1. Hitung `shared = pow(A, b, p)`.
2. Ambil nilai byte kunci `k = shared % 256` ($k = 214$).
3. Dekripsi ciphertext XOR:
   ```python
   flag = bytes([x ^ 214 for x in bytes.fromhex(enc)])
   ```
   *Output:* `academy{dh_s3cr3t_e3954beb}`
