# Writeup: Perceptron Train Classic 1 (Challenge ID: 778)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Machine Learning Foundations (CWE-684 / NIST SP 800-115 §4.2)
- **Difficulty:** Easy (1)
- **Points:** 1
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Flag (Resmi CyLab):** `academy{perceptron_classic_5rates_a95545ef}`
- **Flag Komunitas:** `CTF{perceptron_classic_5rates_a95545ef}`

---

## Problem Statement & Scope

Tantangan menguji pemahaman stabilitas konvergensi algoritma perceptron diskrit dan penanganan sesi HTTP berbasis state:
> *"Watch a perceptron learn in real time using the classic update rule: only misclassified points trigger updates, with no weight decay. In this variant you must find 5 successful learning rates (each reaching 100% accuracy) before the flag is revealed. Dial in a rate, trigger a run, and the interface animates each step."*

Layanan web mempertahankan state pengguna menggunakan *session cookie* HTTP. Backend mensyaratkan peserta membuktikan konvergensi model dengan mengirimkan 5 nilai *learning rate* berlainan yang seluruhnya mencapai akurasi $100\%$ dalam batas 16 langkah pembelajaran (`maxSteps = 16`). Jika counter sesi mencapai `successTarget = 5`, server akan mengembalikan token flag resmi.

---

## Teori & Akar Kerentanan (Root Cause Theory)

1. **Stabilitas Solusi Pembaruan Diskrit pada Margin Lebar:**
   Pada dataset 2D yang memiliki margin separasi besar antar klaster ($\gamma \gg 0$), hiperbidang separasi memiliki *region of attraction* yang luas. Selama laju pembelajaran $\eta$ bernilai positif dan tidak memicu lompatan bobot yang melampaui batas ruang data (*bounded step size*), setiap vektor kesalahan $(y - \hat{y}) \vec{x}$ secara monoton memutar vektor bobot $\vec{w}$ ke arah kerucut solusi (*solution cone*).
2. **Evaluasi Empiris Multi-Rate Konvergensi:**
   Dengan dataset 8 titik yang sama dengan varian Classic 0:
   - Kelas 0: $(-4, -2)$, $(-3, -4)$, $(-2, -3)$, $(-3, -1)$
   - Kelas 1: $(3, 4)$, $(4, 2)$, $(2, 3)$, $(3, 1)$
   Pengujian matematis menunjukkan bahwa untuk sembarang $\eta \in [0.02, 0.10]$ dengan step $0.02$, perceptron selalu mencapai akurasi $100\%$ dalam $\le 4$ langkah pembaruan.
3. **Penyimpanan State Berbasis Sesi (RFC 6265 & CWE-384):**
   Aplikasi melacak akumulasi keberhasilan via memori sesi sisi server yang dipetakan ke identifier cookie `connect.sid`. Permintaan HTTP terpisah tanpa penanganan cookie yang benar akan memulai ulang counter `successCount` menjadi $0$. Diperlukan otomasi klien yang mematuhi protokol penanganan cookie persisten (*Cookie Jar*).

---

## Rekonstruksi Eksploitasi Step-by-Step

1. **Reconnaissance Konfigurasi Target:**
   Mengakses endpoint `/config.json` untuk mengidentifikasi kriteria backend:
   ```bash
   curl -s http://chatelaine.cylabacademy.net:36775/config.json
   ```
   Respons:
   ```json
   {
     "successTarget": 5,
     "maxSteps": 16,
     "dataset": "separable_classic"
   }
   ```

2. **Perancangan Pipeline Otomasi Stateful (Cookie-Aware Client):**
   Menggunakan `http.cookiejar.CookieJar` pada Python untuk mempertahankan token sesi sepanjang interaksi. Mengirim 5 permintaan berurutan dengan $\eta \in \{0.02, 0.04, 0.06, 0.08, 0.10\}$:
   ```python
   import urllib.request, json, http.cookiejar

   cj = http.cookiejar.CookieJar()
   opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

   rates = [0.02, 0.04, 0.06, 0.08, 0.10]
   for r in rates:
       req = urllib.request.Request(
           'http://chatelaine.cylabacademy.net:36775/train',
           data=json.dumps({'learningRate': r}).encode('utf-8'),
           headers={'Content-Type': 'application/json'}
       )
       with opener.open(req) as resp:
           res = json.loads(resp.read().decode())
           print(f"Rate: {r}, Count: {res.get('successCount')}")
           if res.get('flag'):
               print("FLAG:", res.get('flag'))
   ```

3. **Ekstraksi Flag & Validasi Live:**
   Pada iterasi kelima ($\eta = 0.10$), `successCount` bernilai $5$ dan respons memuat token:
   `academy{perceptron_classic_5rates_a95545ef}`.

---

## Flag & Verifikasi

- **Flag Resmi:** `academy{perceptron_classic_5rates_a95545ef}`
- **Format Flag Komunitas:** `CTF{perceptron_classic_5rates_a95545ef}`
- **Bukti Validasi REST API:** HTTP 201 Created via `POST /api/submissions/`:
  ```json
  {"user": 1072359, "challenge": 778, "flag": "academy{perceptron_classic_5rates_a95545ef}", "correct": true, "historical": false}
  ```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)

1. **Integritas Sesi Aplikasi Stateful:**
   Dalam pengujian penetrasi web dan API LKS Cyber Security, verifikasi integritas sesi wajib memastikan bahwa counter progres sensitif dilindungi dari manipulasi *race condition* atau *replay attacks* lintas sesi paralel.
2. **Defensive Validation pada Nilai Hyperparameter:**
   Server AI yang menerima parameter dari pengguna (*user-supplied hyperparameters*) harus menerapkan validasi batas ketat (*boundary checks*) untuk mencegah Denial of Service (DoS) melalui nilai ekstrim (misalnya $\eta \le 0$ atau $\eta = \infty$ yang memicu nilai `NaN` atau `Infinity` pada bobot komputasi).
3. **Pemberlakuan Rate Limiting pada API Training:**
   API yang memicu eksekusi algoritma iteratif (seperti training loop) wajib dibatasi frekuensi panggilannya (*rate limiting*) guna mencegah konsumsi CPU berlebih yang dapat melumpuhkan server.
