# Writeup: Assistant or Agent? (Challenge ID: 768)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Artificial Intelligence / Autonomous Agent Architecture
- **Difficulty:** Easy
- **Author:** LT 'syreal' Jones
- **Event:** AI Foundations I
- **Points:** 1
- **Flag:** `academy{4551574n7_0r_463n7_c17cee7a}`

---

## Deskripsi Tantangan
> Learn when an AI assistant should advise, when an AI agent should act, and how permissions, guardrails, and review checkpoints keep autonomous actions safe.

---

## Analisis & Arsitektur Keamanan Agentik
Game interaktif fiksi etika AI ini mengeksplorasi perbedaan mendasar antara:
1. **AI Assistant:** Beroperasi dalam mode read-only / drafting, hanya menghasilkan saran teks di antarmuka obrolan tanpa memodifikasi state sistem luar.
2. **AI Agent:** Memiliki *hands* (tool calling, eksekusi kode, akses API), mampu merencanakan langkah dan melakukan mutasi state di sistem terdistribusi.

Prinsip keamanan agentik yang diuji:
- **Human-in-the-Loop Approval Gate:** Menahan tindakan dengan blast-radius tinggi (misal: mengirim pesan massal) hingga disetujui manusia.
- **Evidence Bundling & Citation Provenance:** Mengharuskan agent mengumpulkan bukti sitasi dan tingkat keyakinan (high/medium/low).
- **Strict Budget & Tool Scoping:** Membatasi akses finansial dan otorisasi substitusi melalui batasan guardrail deterministik.

Pilihan optimal di seluruh 3 skenario:
- Skenario 1: `C` (Agent mode with human approval checkpoint)
- Skenario 2: `B` (Agent mode browsing approved sites with citation bundle)
- Skenario 3: `B` (Agent mode with budget cap and substitution confirmation)

Flag: `academy{4551574n7_0r_463n7_c17cee7a}`.
