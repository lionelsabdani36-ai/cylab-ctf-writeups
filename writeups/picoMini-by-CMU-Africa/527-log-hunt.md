# Writeup: Log Hunt (Challenge ID: 527)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Log Analysis & Parsing
- **Difficulty:** Easy
- **Author:** Yahaya Meddy
- **Event:** picoMini by CMU-Africa
- **Points:** 50
- **Flag:** `academy{us3_y0urlinux_sk1lls_cedfa5fb}`

---

## Deskripsi Tantangan
> Our server seems to be leaking pieces of a secret flag in its logs. The parts are scattered and sometimes repeated. Can you reconstruct the original flag?
> Download the logs `server.log` and figure out the full flag from the fragments.
> Hints:
> 1. You can use `grep` to filter only matching lines from the log.
> 2. Some lines are duplicates; ignore extra occurrences.

---

## Analisis Kerentanan & Konsep Teknis
Dalam pengelolaan sistem operasi Linux dan investigasi insiden SIEM/SOC, log server sering kali mencatat ribuan baris aktivitas per menit. Kegagalan konfigurasi logging level (`DEBUG`/`INFO`) dapat membocorkan kredensial atau informasi sensitif secara terfragmentasi (Information Disclosure).

Pada berkas `server.log`, log dipenuhi pesan rutin seperti `WARN Disk space low`, `INFO Service restarted`, dan `ERROR Failed login attempt`. Namun, terdapat baris khusus dengan label `FLAGPART:` yang tersebar sepanjang log.

### Rekonstruksi Fragmen Berdasarkan Waktu
Ketika baris `FLAGPART:` dianalisis berdasarkan urutan timestamp log:
- `[1990-08-09 10:00:10]` -> `academy{us3_`
- `[1990-08-09 10:02:55]` -> `y0urlinux_`
- `[1990-08-09 10:05:54]` -> `sk1lls_`
- `[1990-08-09 10:10:54]` -> `cedfa5fb}`

Fragmen berulang pada interval waktu berikutnya (`11:04`, `12:19`), tetapi urutan kronologis kemunculan pertamanya merepresentasikan struktur utuh dari flag.

---

## Tahapan Eksploitasi & Solusi
1. Filter fragmen log unik dengan perintah Unix:
   ```bash
   grep "FLAGPART:" server.log | awk '{print $5}' | awk '!seen[$0]++' | tr -d '\n'
   ```
2. Penggabungan string menghasilkan token:
   ```text
   academy{us3_y0urlinux_sk1lls_cedfa5fb}
   ```

---

## Pembelajaran Defensif & Mitigasi LKS
- **Sanitasi Log (Data Masking):** Pengembang aplikasi wajib memastikan parameter sensitif (token autentikasi, kata sandi, PII) disaring sebelum dicatat ke syslog atau log aplikasi.
- **Konfigurasi Level Logging:** Di lingkungan produksi, level logging harus diatur minimal ke `WARN` atau `ERROR` untuk meminimalkan paparan data diagnostik berlebih.
