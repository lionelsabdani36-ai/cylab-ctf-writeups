# Writeup: Whats Your Input (Challenge ID: 138)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Python Eval Injection
- **Difficulty:** Medium
- **Flag:** `academy{v4lua4bl3_1npu7_6fd920cb}`

---

## Problem Statement & Scope
Program Python2 meminta input lalu `eval()` langsung. Target: baca flag.

## Root Cause
`eval(input())` tanpa sanitasi = eksekusi kode sewenang-wenang.

## Exploit
```python
# input dikirim: city
# variabel global bocor dari list-comprehension Python2 (leak variabel loop)
city
```
Kirim nama variabel yang bocor ke scope global → program cetak nilainya = flag.

## Mitigasi
Jangan `eval()` input user. Pakai `ast.literal_eval()` atau parsing eksplisit.

## Verifikasi
Submit via `/api/submissions/` → `correct:true`.
