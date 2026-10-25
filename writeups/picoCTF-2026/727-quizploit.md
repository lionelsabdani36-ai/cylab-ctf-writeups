# Writeup: Quizploit (Challenge ID: 727)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Mitigation Analysis
- **Difficulty:** Easy
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Points:** 50
- **Flag:** `academy{my_bIn@4y_3xpl0it_fL@g_95fef02a}`

---

## Deskripsi Tantangan
> Solve the quiz. Download the source code and binary to answer 13 questions.

---

## Analisis Statis Binary (`vuln`) & Questionnaire Solves
Program `vuln.c` memanggil `fgets(buffer, 0x90, stdin)` pada buffer berukuran `0x15` bytes. Fungsi `win()` berada di alamat `0x401176` dan memanggil `system("cat flag.txt")`.

### Jawaban 13 Pertanyaan Kuis Binary Exploitation:
1. **0x1 (Architecture):** `64-bit` (ELF 64-bit LSB executable, x86-64).
2. **0x2 (Linking):** `dynamic` (Dynamically linked interpreter `/lib64/ld-linux-x86-64.so.2`).
3. **0x3 (Stripping):** `not stripped` (Symbol table `.symtab` utuh).
4. **0x4 (Buffer Size):** `0x15` (Deklarasi `char buffer[0x15]`).
5. **0x5 (Bytes Read):** `0x90` (`fgets(buffer, 0x90, stdin)`).
6. **0x6 (Vulnerability):** `yes` (Input 144 bytes pada buffer 21 bytes).
7. **0x7 (Vulnerable Function):** `fgets` (Fungsi pembacaan input).
8. **0x8 (Uncalled Function):** `win` (Fungsi target eksploitasi).
9. **0x9 (Attack Type):** `buffer overflow` (Stack-based buffer overwrite).
10. **0xa (Overflow Capacity):** `0x7b` ($0x90 - 0x15 = 123 = 0x7b$).
11. **0xb (Active Protection):** `NX` (GNU_STACK RW, stack No-eXecute).
12. **0xc (Bypass Technique):** `ROP` (Return-Oriented Programming untuk membypass NX).
13. **0xd (Win Address):** `0x401176` (Alamat fungsi `win` pada ELF base).

Setelah 13 pertanyaan dijawab dengan akurat, socket mencetak:
`academy{my_bIn@4y_3xpl0it_fL@g_95fef02a}`
