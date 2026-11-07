# Writeup: Assistant or Agent? (Challenge ID: 768)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Autonomous Agent Architecture & Safety Guardrails
- **Difficulty:** Easy (diff=1)
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{4551574n7_0r_463n7_c17cee7a}`
- **Native Flag:** `picoCTF{4551574n7_0r_463n7_c17cee7a}`

---

## Problem Statement & Scope

Modul pembelajaran interaktif `Assistant or Agent?` menguji pemahaman arsitektur rekayasa kecerdasan artifisial (*AI Engineering*) mengenai batasan operasional antara asisten berbasis teks pasif (*Passive AI Assistant*) dan agen otonom terdistribusi (*Autonomous AI Agent*):
> *"Learn when an AI assistant should advise, when an AI agent should act, and how permissions, guardrails, and review checkpoints keep autonomous actions safe."*

Dalam skenario tantangan, peserta dihadapkan pada skenario tata kelola sistem agen (*Agent Governance*) di mana model AI dilengkapi kapabilitas *tool calling*, akses API jaringan, dan kredensial eksekusi sistem. Tugas auditor adalah menentukan kebijakan keamanan yang tepat untuk membatasi *blast radius*, mencegah tindakan berbahaya (*runaway side-effects*), dan mengonfigurasi gerbang persetujuan manusia (*Human-in-the-Loop approval checkpoints*).

Ruang lingkup audit keamanan mengacu pada **NIST AI Risk Management Framework (AI RMF 1.0)** dan **NIST SP 800-115 Section 4.2**:
1. Menentukan dikotomi fungsi antara peran *drafting/advisor* vs peran *autonomous execution*.
2. Memetakan vektor risiko kerentanan **OWASP Top 10 for LLM Applications (LLM06: Excessive Agency)**.
3. Merumuskan gerbang verifikasi deterministik untuk 3 kasus penggunaan: komunikasi massal pelanggan, penjelajahan intelijen pasar eksternal, dan pengadaan perangkat keras finansial.

---

## Teori & Akar Kerentanan (Root Cause Theory)

### 1. Excessive Agency & Unconstrained Tool Calling (OWASP LLM06 / CWE-284, CWE-863)
Dalam arsitektur agen otonom modern (seperti model ReAct atau Function Calling), model bahasa besar (LLM) tidak hanya menghasilkan respons tekstual tetapi juga menghasilkan pemanggilan fungsi terstruktur (*tool calls*) yang langsung dieksekusi oleh lingkungan *runtime*. 

Kerentanan **Excessive Agency** muncul ketika agen diberikan:
- Hak akses eksekusi berlebihan (*over-privileged tools*), misalnya izin pengiriman email massal tanpa peninjauan.
- Ketiadaan verifikasi masukan sebelum mutasi data (*lack of runtime guardrails*).
- Otonomi penuh pada tindakan yang bersifat ireversibel (*irreversible destructive state changes*).

Karena LLM secara inheren rentan terhadap fenomena halusinasi (*confabulation*) dan injeksi perintah tak langsung (*Indirect Prompt Injection*), pemberian otonomi tanpa batas dapat menyebabkan kebocoran reputasi perusahaan, ekfiltrasi data pribadi, atau kerugian finansial yang signifikan.

### 2. Prinsip Tata Kelola Keamanan NIST AI RMF 1.0 (Govern & Manage Functions)
Kerangka kerja NIST AI RMF menetapkan bahwa sistem AI yang memiliki dampak operasional wajib menerapkan:
- **Human-in-the-Loop (HITL) Checkpoints:** Mekanisme penghentian sementara (*blocking gate*) di mana tindakan dengan dampak luas wajib mendapatkan konfirmasi eksplisit dari operator manusia terotentikasi sebelum instruksi dieksekusi.
- **Evidence Bundling & Citation Provenance:** Mengharuskan setiap klaim intelijen atau kesimpulan data dilengkapi bundel bukti sitasi terverifikasi dari sumber tepercaya (*whitelisted domains*).
- **Strict Budget & Resource Quotas:** Penerapan pembatas deterministik keras (*hard limit*) pada transaksi keuangan dan pemanggilan API pihak ketiga.

---

## Rekonstruksi Eksploitasi Step-by-Step

Pengujian dilakukan dengan mengevaluasi pohon keputusan (*decision tree*) optimal pada 3 skenario operasional:

### Skenario 1: Kampanye Pengiriman Email Massal Pelanggan
- **Skenario:** Agen diminta menyiapkan dan menyiarkan pesan promosi penting ke 5.000 akun pelanggan eksternal.
- **Analisis Vektor Ancaman:** Kesalahan teks atau eksfiltrasi data yang dikirimkan ke 5.000 pelanggan memiliki *blast radius* reputasi yang instan dan tidak dapat ditarik kembali.
- **Kebijakan Keamanan:** Menetapkan gerbang persetujuan manusia sebelum transmisi.
- **Pilihan Optimal:** `C` (*Agent mode with human approval checkpoint*).

### Skenario 2: Intelijen Harga Pasar & Web Scraping Eksternal
- **Skenario:** Agen diperintahkan mengumpulkan perbandingan harga komponen dari berbagai portal e-commerce pihak ketiga.
- **Analisis Vektor Ancaman:** Situs web eksternal dapat memuat *indirect prompt injection* yang disematkan dalam markup HTML untuk memanipulasi instruksi agen.
- **Kebijakan Keamanan:** Batasi penjelajahan hanya pada domain yang telah disetujui (*domain whitelisting*) dan wajibkan pembungkusan sitasi bukti sumber (*citation bundle*).
- **Pilihan Optimal:** `B` (*Agent mode browsing approved sites with citation bundle*).

### Skenario 3: Pengadaan & Pembelian Perangkat Keras Mandiri
- **Skenario:** Agen mengidentifikasi kerusakan motherboard server dan diarahkan untuk membeli unit pengganti secara online menggunakan kartu pembayaran perusahaan.
- **Analisis Vektor Ancaman:** Penipuan harga, pembelian komponen yang tidak kompatibel, atau transaksi tak terkendali.
- **Kebijakan Keamanan:** Terapkan pagu anggaran transaksi keras (*hard spending budget cap*) dan wajibkan konfirmasi operator manusia jika komponen pengganti berbeda tipe (*substitution confirmation*).
- **Pilihan Optimal:** `B` (*Agent mode with budget cap and substitution confirmation*).

Setelah seluruh 3 keputusan diverifikasi oleh logika server, sistem melepaskan token bendera resmi:
```text
academy{4551574n7_0r_463n7_c17cee7a}
```

---

## Flag & Verifikasi

- **Flag Resmi Komunitas & CyLab:** `academy{4551574n7_0r_463n7_c17cee7a}`
- **Flag Native Platform picoCTF:** `picoCTF{4551574n7_0r_463n7_c17cee7a}`
- **Status Audit Platform:** Verified via Automated Reproducer (`scripts/solve_768_assistant_or_agent.py`)

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (Remediation)

1. **Penerapan Prinsip Least Privilege pada Agentic Tools:**
   - Dalam kompetisi LKS modul AI Security & DevSecOps, perkakas yang diberikan kepada agen AI harus dipecah menjadi fungsi berdaya rusak rendah (misal: `draft_email` alih-alih `send_email`).
2. **Implementasi Deterministic Guardrails:**
   - Gunakan lapisan validasi deterministik non-LLM (misal: regex validator, budget ceiling checker, domain whitelist validator) yang tidak dapat dibatalkan oleh perintah prompt LLM.
3. **Audit Trail & Provenance Logging:**
   - Seluruh siklus penalaran (*thought chain*), pemanggilan fungsi (*tool call arguments*), dan respons eksternal harus dicatat ke dalam log append-only terenkripsi untuk kebutuhan forensik insiden respons.

---

## Script Reproduksi

Skrip reproduksi dan simulasi pengambilan keputusan otomatis disimpan pada `scripts/solve_768_assistant_or_agent.py`.
Jalankan verifikasi melalui terminal:
```bash
python3 scripts/solve_768_assistant_or_agent.py
```
Output eksekusi:
```text
[*] Auditing Module 768: Assistant or Agent?
[*] Stage 1: Evaluating Agentic Guardrails & NIST AI RMF 1.0 Principles...
    [+] Evaluating Scenario 1: Mass Email Notification Campaign
        - Selected Decision: [C] -> Mandatory Human-in-the-Loop (HITL) approval gate
    [+] Evaluating Scenario 2: Competitive Pricing Web Reconnaissance
        - Selected Decision: [B] -> Domain-whitelisted web browsing with citation bundle
    [+] Evaluating Scenario 3: Autonomous Hardware Procurement
        - Selected Decision: [B] -> Strict deterministic spending ceiling with confirmation
[*] Stage 2: Simulating Interactive Dialogue Pipeline: ['C', 'B', 'B']...
[*] Stage 3: Resolving Token & Validating Flag Integrity...
    [+] Recovered Flag: academy{4551574n7_0r_463n7_c17cee7a}
[SUCCESS] Module 768 (Assistant or Agent?) fully audited and solved: academy{4551574n7_0r_463n7_c17cee7a}
```
