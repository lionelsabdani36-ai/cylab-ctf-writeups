# Writeup: Mind your Ps and Qs (Challenge ID: 162)

- **Platform:** CyLab Security Academy (picoCTF 2021)
- **Category:** Cryptography / RSA Factorization
- **Difficulty:** Easy
- **Playlist:** Cryptography and Challenge Library Learning Intro (Module 138)
- **Points:** 20
- **Flag:** `academy{sma11_N_n0_g0od_a3ac7152}`

---

## Deskripsi Tantangan
> In RSA, a small e value can be problematic, but what about N? Can you decrypt this?
> File: `values`

---

## Analisis & Solusi
Parameter RSA yang diberikan:
- $c = 717608817902276639011922897702552744324264244069272484013719744328086856277690292$
- $n = 1368992139315019955067447961537607041364451719382349005056752379702694554965203011$
- $e = 65537$

Modulus $n$ hanya memiliki panjang ~270 bit (~82 digit desimal), jauh di bawah standar aman 2048 bit.
Menggunakan database faktorisasi `factordb`:
- $p = 2074606527507983503944226222695401999839$
- $q = 659880377875535146491994798968813949893149$

### Rekonstruksi Kunci Privat & Dekripsi
```python
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
flag = m.to_bytes((m.bit_length() + 7) // 8, 'little')
print(flag.decode())
```
Output: `academy{sma11_N_n0_g0od_a3ac7152}`.

Flag: `academy{sma11_N_n0_g0od_a3ac7152}`.
