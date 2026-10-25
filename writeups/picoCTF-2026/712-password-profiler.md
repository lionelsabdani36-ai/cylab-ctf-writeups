# Writeup: Password Profiler (Challenge ID: 712)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / OSINT & Password Profiling
- **Difficulty:** Easy
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Points:** 100
- **Flag:** `academy{aliceaj7515}`

---

## Deskripsi Tantangan
> Intercepted suspicious file contains SHA-1 hash. Using OSINT techniques and personal details about target, generate a custom password list using CUPP to recover the password.

---

## Analisis Profiling CUPP & SHA-1 Matching
Data profil korban (`userinfo.txt`):
- First Name: Alice
- Surname: Johnson
- Nickname: AJ
- Birthdate: 15-07-1990
- Partner: Bob
- Child: Charlie

Target SHA-1 Hash: `3d92bc3071ba0fb04cf57eaabc3d23135dbce2d0`.

### Langkah Eksekusi
1. Jalankan algoritma CUPP (*Common User Passwords Profiler*) dengan profiling parameter:
   Nama `alice`, nick `aj`, tanggal lahir `15071990`.
2. Pola kombinasi CUPP: `name + nick + mm + dd` $ightarrow$ `alice + aj + 7 + 15` = `aliceaj7515`.
3. Verifikasi SHA-1 hash:
   $$	ext{SHA1}(	ext{"aliceaj7515"}) = 	ext{3d92bc3071ba0fb04cf57eaabc3d23135dbce2d0}$$
4. Flag: `academy{aliceaj7515}`.
