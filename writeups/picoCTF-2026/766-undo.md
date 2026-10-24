# Writeup: Undo (Challenge ID: 766)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Linux Text Processing
- **Difficulty:** Easy
- **Author:** Yahaya Meddy
- **Event:** picoCTF 2026
- **Points:** 100
- **Flag:** `academy{Revers1ng_t3xt_Tr4nsf0rm@t10ns_c77d80cc}`

---

## Deskripsi Tantangan
> Can you reverse a series of Linux text transformations to recover the original flag?

---

## Analisis & Solusi Rantai Transformasi
Tantangan menyajikan string terenkripsi berurutan dan meminta perintah CLI Linux standar untuk membalikkan (*reverse*) setiap tahap transformasi:

1. **Tahap 1 (Base64 Encoding):**
   - *Input:* `KXBwMDhxNzdwLWZhMDFnQHplMHNmYTRlRy1nazNnLXRhMWZlcmlyRShsenJxbnBu`
   - *Perintah Pembalik:* `base64 -d`
   - *Hasil:* `)pp08q77p-fa01g@ze0sfa4eG-gk3g-ta1ferirE(lzrqnpn`
2. **Tahap 2 (String Reversal):**
   - *Perintah Pembalik:* `rev`
   - *Hasil:* `npnqrzl(Eriref1at-g3kg-Ge4afs0ez@g10af-p77q80pp)`
3. **Tahap 3 (Dash-to-Underscore Replacement):**
   - *Perintah Pembalik:* `tr '-' '_'`
   - *Hasil:* `npnqrzl(Eriref1at_g3kg_Ge4afs0ez@g10af_p77q80pp)`
4. **Tahap 4 (Parentheses-to-Curly-Braces Replacement):**
   - *Perintah Pembalik:* `tr '()' '{}'`
   - *Hasil:* `npnqrzl{Eriref1at_g3kg_Ge4afs0ez@g10af_p77q80pp}`
5. **Tahap 5 (ROT13 Caesar Cipher):**
   - *Perintah Pembalik:* `tr 'A-Za-z' 'N-ZA-Mn-za-m'`
   - *Hasil:* `academy{Revers1ng_t3xt_Tr4nsf0rm@t10ns_c77d80cc}`

Flag: `academy{Revers1ng_t3xt_Tr4nsf0rm@t10ns_c77d80cc}`.
