# Writeup: Mini RSA (Challenge ID: 188)

- **Platform:** CyLab Security Academy (picoCTF 2021)
- **Category:** Cryptography / Low Exponent RSA Attack
- **Difficulty:** Medium
- **Playlist:** Cryptography and Challenge Library Learning Intro (Module 139)
- **Points:** 70
- **Flag:** `academy{e_sh0u1d_b3_lArg3r_35f26e1a}`

---

## Deskripsi Tantangan
> What happens if you have a small exponent? There is a twist though, we padded the plaintext so that (M ** e) is just barely larger than N. Let's decrypt this:
> File: `values`

---

## Analisis & Solusi
Parameter enkripsi:
- $e = 3$
- $N \approx 2500\text{ bit}$
- $c = M^e \pmod N \implies M^3 = c + k \cdot N$

Karena nilai $M^3$ hanya sedikit lebih besar dari $N$ (atau bahkan tidak melewati modulus jika $k=0$), kita dapat menguji integer cube root dari $c + k \cdot N$ untuk nilai integer kecil $k \ge 0$.

### Algoritma Integer Cube Root
Pada $k = 0$:
$$M = \sqrt[3]{c}$$
Menghitung akar kubik bilangan bulat besar via binary search integer:
```python
def cbrt_int(n):
    lo = 1 << ((n.bit_length() - 1) // 3)
    hi = 1 << ((n.bit_length() + 2) // 3)
    while lo <= hi:
        mid = (lo + hi) // 2
        m3 = mid ** 3
        if m3 == n: return mid
        elif m3 < n: lo = mid + 1
        else: hi = mid - 1
    return None

m = cbrt_int(c)
print(m.to_bytes((m.bit_length() + 7) // 8, 'big').decode())
```
Nilai $k=0$ menghasilkan dekripsi valid: `academy{e_sh0u1d_b3_lArg3r_35f26e1a}`.

Flag: `academy{e_sh0u1d_b3_lArg3r_35f26e1a}`.
