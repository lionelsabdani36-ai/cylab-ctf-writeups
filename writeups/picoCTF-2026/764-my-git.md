# MY GIT (Challenge 764, General Skills)

- **ID:** 764 | **Event:** picoCTF 2026 | **Kategori:** General Skills / Version Control Security | **Level:** Easy
- **Flag:** `academy{1mp3rs0n4t4_g17_345y_f382bd68}` (terverifikasi writeup batch awal)

## Skenario
Server Git kustom dengan aturan sendiri; README: hanya `flag.txt` yang
di-push oleh `root:root@academy` yang diberi flag. Clone via
`ssh://git@xebec.cylabacademy.net:34513/git/challenge.git`.

## Root Cause
Git tidak mengautentikasi nama/email committer kecuali penandatanganan
GPG/SSH diwajibkan dan diverifikasi hook. Metadata author sepenuhnya
dikendalikan klien (`-c user.name`, `-c user.email`), sehingga hook yang
hanya memeriksa string identitas dapat dipalsukan (impersonasi).

## Rekonstruksi
1. `git clone ssh://git@HOST:PORT/git/challenge.git`.
2. `echo "give me the flag" > flag.txt && git add flag.txt`.
3. `git -c user.name="root" -c user.email="root@academy" commit -m "Add flag.txt"`.
4. `git push origin master` → hook remote menjawab flag. Otomasi:
   `python3 scripts/solve_764_my_git.py [host] [port]`.
5. Submit `POST /api/submissions/` → correct (saat instance RUNNING).

## Mitigasi
Wajibkan commit signing (GPG/SSH) + verifikasi tanda tangan di hook;
ikat identitas ke akun SSH terautentikasi, bukan string author; tolak
push unsigned di `pre-receive`.

## Takeaway LKS
Klasifikasi General Skills: keamanan version control + trust boundary.
Relevan defensif: supply-chain (signed commits, branch protection) dan
audit provenance artefak di pipeline LKS.
