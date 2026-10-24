# Writeup: interencdec (Challenge ID: 418)

- **Platform:** CyLab Security Academy (picoCTF 2024)
- **Category:** Cryptography / Multi-layer Encoding & Caesar
- **Difficulty:** Easy
- **Playlist:** Cryptography and Challenge Library Learning Intro (Module 135)
- **Points:** 100
- **Flag:** `academy{caesar_d3cr9pt3d_82243097}`

---

## Deskripsi Tantangan
> Can you decode the layered encryption?
> File: `enc_flag`

---

## Analisis & Solusi
Isi berkas `enc_flag`:
```text
YidhR3BvYTJ4MFpudHFhR3g2YUhsZmF6TnFlVGwzWVROclh6Z3lNalF6TURrM2ZRPT0nCg==
```

### Dekripsi Bertahap
1. **Base64 Decode Tahap 1:**
   ```python
   base64.b64decode("YidhR3BvYTJ4MFpudHFhR3g2YUhsZmF6TnFlVGwzWVROclh6Z3lNalF6TURrM2ZRPT0nCg==")
   # Hasil: b"b'aGpoa2x0ZntqaGx6aHlfazNqeTl3YTNrXzgyMjQzMDk3fQ=='"
   ```

2. **Base64 Decode Tahap 2:**
   ```python
   base64.b64decode("aGpoa2x0ZntqaGx6aHlfazNqeTl3YTNrXzgyMjQzMDk3fQ==")
   # Hasil: b"hjhkltf{jhlzhy_k3jy9wa3k_82243097}"
   ```

3. **Caesar Shift Decode (Shift 7):**
   Melakukan pergeseran rotasi alfabet sebanyak 7 karakter mundur:
   - `'h'` $\rightarrow$ `'a'`
   - `'j'` $\rightarrow$ `'c'`
   - `'k'` $\rightarrow$ `'d'`
   - ...
   Membentuk: `academy{caesar_d3cr9pt3d_82243097}`.

Flag: `academy{caesar_d3cr9pt3d_82243097}`.
