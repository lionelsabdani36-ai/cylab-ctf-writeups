# Writeup: chrono (Challenge ID: 347)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Linux Task Scheduling
- **Difficulty:** Easy
- **Event:** picoCTF 2023
- **Flag:** `academy{Sch3DUL7NG_T45K3_L1NUX_9bb09823}`

---

## Problem Statement & Scope

SSH lab (`picoplayer@<host>:<port>`, kredensial dari deskripsi instance on-demand). Home directory kosong; pertanyaan "how to automate tasks at intervals on linux servers?" mengarah ke cron.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Cron = scheduler interval standar Linux:** `crontab -l` (user), `/etc/crontab` + `/etc/cron.d/` (sistem).
2. **Flag sebagai komentar di `/etc/crontab`:** `# academy{...}` di baris pertama — kredensial baca file sistem cukup (`cat`), tanpa privilege escalation.
3. **Home kosong itu pengecoh:** peserta yang hanya `ls ~` akan buntu; metodologi "enumerasi scheduler" yang menyelesaikan.

---

## Rekonstruksi Eksploitasi Step-by-Step

1. Launch: `PUT /api/challenges/347/instance/` → catat `Server/Port/Username/Password`.
2. `python3 scripts/solve_347_chrono.py <host> <port> <password>` (SSH via `sshpass`, `cat /etc/crontab`, regex flag).
3. Submit `POST /api/submissions/` → `correct: true` (live 2026-10-29).

---

## Flag & Verifikasi

- **Flag:** `academy{Sch3DUL7NG_T45K3_L1NUX_9bb09823}`
- **Bukti:** `solved_by_user=True` via `GET /api/challenges/347/`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

Audit cron sistem (`/etc/crontab`, `/etc/cron.d/*`, `systemctl list-timers`) adalah langkah enumerasi standar pasca-akses. Defensif: jangan simpan rahasia di file world-readable; gunakan permission ketat + secret manager.
