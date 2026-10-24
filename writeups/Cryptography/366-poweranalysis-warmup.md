# Writeup: PowerAnalysis: Warmup (Challenge ID: 366)

- **Platform:** CyLab Security Academy (picoCTF 2023)
- **Category:** Cryptography / Side-Channel Power Leakage
- **Difficulty:** Medium
- **Playlist:** Cryptography and Challenge Library Learning Intro (Module 142)
- **Points:** 200
- **Flag:** `academy{2c6f64dd531cfdc60257085fac8336c6}`

---

## Deskripsi Tantangan
> This encryption algorithm leaks a "bit" of data every time it does a computation. Use this to figure out the encryption key.
> File: `encrypt.py`
> Running server: `nc xebec.cylabacademy.net 31265`

---

## Analisis & Solusi
Program menghitung jumlah bit 1 pada LSB keluaran S-Box:
$$\text{leakage}(P) = \sum_{i=0}^{15} (\text{Sbox}[p_i \oplus k_i] \ \& \ 1)$$

### Isolasi Kunci Per Byte
Dengan menetapkan 15 byte bernilai tetap `0x00` dan hanya memvariasikan byte target $p_i \in [0, 24]$:
$$\text{leakage}(p_i) = (\text{Sbox}[p_i \oplus k_i] \ \& \ 1) + C_i$$
di mana $C_i = \sum_{j \ne i} (\text{Sbox}[k_j] \ \& \ 1)$ bernilai konstan.

Untuk setiap tebakan kunci $k \in [0, 255]$, selisih:
$$\Delta(k, p_i) = \text{leakage}(p_i) - (\text{Sbox}[p_i \oplus k] \ \& \ 1)$$
akan konstan untuk seluruh $p_i$ jika dan hanya jika $k = k_i$.

Dengan 25 kueri per byte (total 400 kueri jaringan), seluruh 16 byte kunci recovered secara deterministik tanpa tabrakan:
`2c6f64dd531cfdc60257085fac8336c6`

Flag: `academy{2c6f64dd531cfdc60257085fac8336c6}`.
