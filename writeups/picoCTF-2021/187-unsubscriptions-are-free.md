# Writeup: Unsubscriptions Are Free (Challenge ID: 187)

- **Platform:** CyLab Security Academy (picoCTF)
- **Category:** Binary Exploitation / Heap Use-After-Free (UAF & Function Pointer Hijack, CWE-416)
- **Difficulty:** Hard (diff=3)
- **Event:** picoCTF 2021
- **Points:** 100
- **Author:** thelshell
- **Flag:** `academy{d0ubl3_j30p4rdy_cff1f12d}`

---

## Problem Statement & Scope
Tantangan `Unsubscriptions Are Free` menyajikan layanan interaktif berbasis perintah teks Linux x86 32-bit (`vuln`) yang mensimulasikan platform streaming daring "Twixer". Program menyediakan menu interaktif berikut:
1. `(S)ubscribe to my channel`: Mencetak pesan terima kasih dan secara tidak sengaja membocorkan alamat memori fungsi internal `hahaexploitgobrrr`.
2. `(I)nquire about account deletion`: Meminta konfirmasi penghapusan akun pengguna (`free(user)`).
3. `(M)ake an Twixer account`: Mengalokasikan string nama pengguna.
4. `(P)ay for premium membership`: Memperbarui status langganan.
5. `(l)eave a message(with or without logging in)`: Mengalokasikan buffer pesan 8-byte via `malloc(8)` dan membaca input dari pengguna.
6. `(e)xit`: Mengakhiri proses.

Tantangan ini menuntut peserta untuk menganalisis pengelolaan memori dinamis glibc pada arsitektur x86 32-bit, mengidentifikasi kelemahan *Use-After-Free* (CWE-416) akibat pointer menggantung (*dangling pointer*), memahami mekanisme daur ulang chunk memori dalam daftar *fastbins/tcache*, serta membajak alur kontrol (*control flow hijack*) fungsi utama untuk mengekstraksi isi berkas rahasia `flag.txt`.

---

## Teori & Akar Kerentanan (Root Cause Theory)
1. **Struktur Objek Pengguna & Tata Letak Memori Heap:**
   Pada kode sumber `vuln.c`, objek akun pengguna direpresentasikan oleh struktur data:
   ```c
   typedef struct {
       void (*whatToDo)(); // offset 0: function pointer (4 byte pada 32-bit)
       char *username;     // offset 4: pointer ke string username (4 byte)
   } cmd;
   cmd *user;
   ```
   Pada inisialisasi program di `main()`, sistem memanggil:
   ```c
   user = (cmd *)malloc(sizeof(user));
   ```
   *Catatan:* Terdapat *bug* alokasi implisit di mana `sizeof(user)` mengembalikan ukuran pointer (4 byte pada arsitektur 32-bit), namun glibc mengalokasikan ukuran minimum chunk sebesar 16 byte (header 8 byte + payload 8 byte yang diratakan kelipatan 8).

2. **Pointer Menggantung Akibat Ketiadaan Nullifikasi (Dangling Pointer / CWE-416):**
   Fungsi penghapusan akun `i()` mengeksekusi dealokasi memori saat pengguna memilih 'Y':
   ```c
   void i() {
       char response;
       puts("You're leaving already(Y/N)?");
       scanf(" %c", &response);
       if (toupper(response) == 'Y') {
           puts("Bye!");
           free(user);
       } ...
   }
   ```
   Program memanggil `free(user)` namun lalai mengenolkan variabel pointer (`user = NULL;`). Variabel global `user` tetap menyimpan alamat virtual chunk memori lama yang statusnya telah dikembalikan ke pengelola heap glibc.

3. **Mekanisme Daur Ulang Alokasi Memori (Fastbin / Tcache Allocation Recycling):**
   Pada fungsi penulisan pesan `leaveMessage()`:
   ```c
   char *msg = (char *)malloc(8);
   read(0, msg, 8);
   ```
   Saat `malloc(8)` dipanggil, pengelola heap mencari chunk yang cocok pada antrean *fastbin* / *tcache* untuk ukuran 16 byte (payload 8 byte). Karena chunk `user` baru saja dibebaskan dan memiliki ukuran yang identik, glibc mengalokasikan kembali alamat memori chunk yang sama persis kepada variabel `msg`. Input pengguna sebanyak 8 byte ditulis langsung ke alamat chunk tersebut.

4. **Eksekusi Otomatis Pointer Fungsi pada Loop Utama:**
   Pada fungsi `main()`, setelah pemrosesan setiap input, program secara konsisten mengeksekusi dereferensi pointer fungsi `user`:
   ```c
   void doProcess(cmd *obj) {
       (*obj->whatToDo)();
   }
   ...
   while (1) {
       printMenu();
       processInput();
       doProcess(user);
   }
   ```
   Dengan menimpa 4 byte pertama chunk melalui `leaveMessage()`, penyerang langsung mengontrol alamat tujuan eksekusi `user->whatToDo`.

---

## Rekonstruksi Eksploitasi Step-by-Step
1. **Mendapatkan Kebocoran Alamat Target (Information Disclosure):**
   Kirimkan opsi `S` (Subscribe). Program mencetak baris:
   ```text
   OOP! Memory leak...0x80487d6
   ```
   Alamat virtual fungsi `hahaexploitgobrrr` adalah `0x080487d6`. Fungsi ini bertugas membaca dan mencetak isi `flag.txt`.
2. **Memicu Dealokasi Chunk Objek Pengguna (Free):**
   Kirimkan opsi `I` (Inquire) lalu respons dengan `Y`.
   Fungsi `free(user)` membebaskan chunk `0x0804b008` ke antrean fastbin/tcache. Pointer `user` tetap bernilai `0x0804b008`.
3. **Mengalokasikan Ulang Chunk & Menimpa Pointer Fungsi:**
   Kirimkan opsi `l` (Leave message). Program memanggil `malloc(8)`, menghasilkan pointer `msg` yang identik dengan `user` (`0x0804b008`).
   Kirimkan payload 4 byte alamat target dalam format little-endian:
   ```python
   payload = p32(0x080487d6)  # b"\xd6\x87\x04\x08"
   ```
   Byte tersebut menimpa posisi `user->whatToDo`.
4. **Pemicuan Eksekusi (Dispatching Flag Function):**
   Setelah perintah `L` selesai diproses, alur eksekusi loop `main()` memanggil `doProcess(user)`.
   Program mendereferensikan `*user->whatToDo` yang kini berisi `0x080487d6` dan mengeksekusi `hahaexploitgobrrr()`.
5. **Hasil Pembacaan Flag:**
   Program mencetak bendera:
   - Native Flag: `picoCTF{d0ubl3_j30p4rdy_cff1f12d}`
   - Token Platform CyLab: `academy{d0ubl3_j30p4rdy_cff1f12d}`

---

## Flag & Verifikasi
- **Flag Resmi:** `academy{d0ubl3_j30p4rdy_cff1f12d}`
- **Native PicoCTF Flag:** `picoCTF{d0ubl3_j30p4rdy_cff1f12d}`
- **Status Solver:** Terverifikasi 100% pada skrip reproduksi `scripts/solve_187_unsubscriptions_are_free.py`.

---

## Takeaway Kompetensi LKS & Mitigasi Defensif (NIST SP 800-115)
1. **Penetapan Pointer ke NULL Pasca Dealokasi (Pointer Zeroization):**
   Setiap kali memanggil fungsi `free()`, wajib segera mengenolkan pointer terkait guna memutus kondisi *dangling pointer*:
   ```c
   free(user);
   user = NULL;
   ```
   Dengan demikian, dereferensi berikutnya akan memicu *segmentation fault* seketika alih-alih mengeksekusi memori yang telah terkontaminasi.
2. **Validasi State Objek Sebelum Dereferensi (Defensive Assertion):**
   Pada fungsi `doProcess()`, terapkan validasi ketat status objek sebelum memanggil pointer fungsi:
   ```c
   if (obj != NULL && obj->whatToDo != NULL) {
       (*obj->whatToDo)();
   }
   ```
3. **Eliminasi Debugging Leak pada Lingkungan Rilis:**
   Jangan pernah mengekspos alamat fungsi internal atau alamat memori heap/stack ke antarmuka pengguna (`printf("%p", ...)`). Informasi tersebut merusak mitigasi keamanan ASLR (*Address Space Layout Randomization*).
4. **Penggunaan Modern Memory Allocator Guard:**
   Kompilasi biner dengan flag proteksi modern seperti `-fstack-protector-strong`, ASLR, dan manfaatkan fitur integritas memori seperti *Safe Linking* pada glibc modern guna membatasi manipulasi pointer heap.
