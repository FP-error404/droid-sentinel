# 🛡️ Droid Sentinel (v0.3.1)

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Android%20%7C%20Termux-green.svg?style=flat-square&logo=android&logoColor=white)]()
[![Database](https://img.shields.io/badge/Database-SQLite-lightgrey.svg?style=flat-square&logo=sqlite)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

**Droid Sentinel** adalah alat pemantauan keamanan (*defensive monitoring*) berbasis CLI untuk Android (via **Termux**). Alat ini memantau koneksi jaringan secara *real-time* (TCP/UDP, IPv4/IPv6), mendeteksi file/APK mencurigakan, mencatat riwayat ke database SQLite, dan mengirim peringatan langsung ke *status bar* Android.

> **⚠️ Disclaimer:** Droid Sentinel beroperasi di dalam ruang pengguna non-root Termux. Alat ini **tidak** memblokir lalu lintas jaringan atau membunuh proses Android lain. Gunakan hanya pada perangkat dan jaringan milik Anda sendiri atau yang Anda miliki izin untuk memantaunya.

---

## ✨ Fitur Utama

- 🌐 **Network Monitor (TCP & UDP):** Memantau koneksi *outbound* langsung dari `/proc/net/` (IPv4 & IPv6).
- 🚨 **Anomaly Detection:** Deteksi koneksi ke port mencurigakan (C2 Server, Backdoor, dll).
- 🛡️ **Allowlist System:** Mendukung filter IP tunggal, CIDR Network (`10.0.0.0/8`), dan Domain/Wildcard (`*.google.com`) agar *output* tidak berisik.
- 📁 **Smart File Watcher:** Memantau folder (default: `/sdcard/Download`) untuk mendeteksi file baru atau file yang dimodifikasi.
- 🧬 **SHA-256 Hashing dengan Cache:** Menghitung *hash* file untuk verifikasi tanpa membebani baterai (dibatasi ukuran maksimal, default 100MB).
- 🎭 **Double-Extension Trap:** Deteksi file berbahaya yang menyamar (contoh: `tagihan.pdf.apk`).
- 🗄️ **SQLite Persistence:** Semua riwayat koneksi, file, dan *alert* disimpan secara lokal. Dilengkapi fitur *auto-retention* (pembersihan data lama).
- 🔔 **Native Notification:** Kirim *alert* ke *status bar* Android via `Termux:API`.
- 💻 **Subcommands CLI:** Dilengkapi perintah `monitor`, `alerts`, dan `history` yang terintegrasi dengan database.

---

## 📂 Struktur Proyek

```text
android_sentinel/
├── LICENSE
├── requirements.txt
├── README.md
├── allowlist.txt
├── sentinel/
│   ├── __init__.py
│   ├── __main__.py   # CLI flags + subcommands (monitor, alerts, history)
│   ├── config.py     # Konfigurasi + parser allowlist (IP, CIDR, domain, subdomain)
│   ├── db.py         # SQLite persistence + retention cleanup + query helper
│   ├── filescan.py   # Deteksi NEW_FILE / MODIFIED_FILE + cache + batas ukuran
│   ├── network.py    # Parser TCP/TCP6/UDP/UDP6 + reverse DNS + allowlist + baseline
│   └── ui.py         # Render CLI + Notifier
└── tests/
    ├── __init__.py
    ├── test_config.py
    ├── test_db.py
    ├── test_filescan.py
    └── test_network.py

⚙️ Prasyarat (Requirements)

· Aplikasi Termux (Download dari F-Droid, bukan Play Store).
· Aplikasi Termux:API (Untuk fitur notifikasi).
· Python 3.8+ (Tersedia di repositori Termux).

---

🚀 Instalasi

1. Update Termux dan install paket yang dibutuhkan:
   ```bash
   pkg update && pkg upgrade -y
   pkg install python termux-api -y
   ```
2. Beri izin akses penyimpanan Android:
   ```bash
   termux-setup-storage
   ```
3. Clone repositori ini:
   ```bash
   git clone https://github.com/FP-error404/droid-sentinel.git
   cd droid-sentinel
   ```

---

🎮 Penggunaan (Usage)

Droid Sentinel berjalan menggunakan module execution (-m sentinel).

1. Mode Monitor (Default)

Jalankan pemantauan real-time di terminal:

```bash
python -m sentinel
```

Anda juga bisa mengkustomisasi parameter pemantauan:

```bash
python -m sentinel monitor \
  --interval 6 \
  --dir /sdcard/Download \
  --dir /sdcard/Documents \
  --max-hash-size 50 \
  --db-retention 30 \
  --no-notify
```

Opsi CLI Monitor:

Flag Default Deskripsi
--interval 4.0 Jeda antar pemindaian (detik).
--dir /sdcard/Download Folder yang dipantau (bisa diulang).
--max-hash-size 100 Batas ukuran file untuk di-hash (MB).
--db-retention 30 Hapus riwayat database yang lebih lama dari X hari.
--no-notify False Matikan notifikasi Android.
--no-udp False Matikan pemantauan socket UDP.

2. Melihat Riwayat (Subcommands)

Seluruh data monitoring disimpan di SQLite (sentinel.db). Anda bisa melihatnya tanpa harus menjalankan monitor:

```bash
# Lihat 20 alert terbaru (Network/Files)
python -m sentinel alerts --limit 20

# Lihat riwayat koneksi dan file
python -m sentinel history --limit 15
```

---

🛡️ Konfigurasi Allowlist

Agar sistem tidak memunculkan peringatan untuk koneksi yang aman (seperti server Google atau WhatsApp), edit file allowlist.txt di root folder. Format yang didukung:

```text
# --- IP Address Tunggal ---
8.8.8.8
1.1.1.1

# --- CIDR Network ---
104.16.0.0/12

# --- Domain Persis ---
github.com

# --- Wildcard Domain (Subdomain) ---
*.google.com
*.whatsapp.net
```

Setiap IP atau Domain yang ada di sini tidak akan muncul di log maupun notifikasi.

---

🧪 Menjalankan Unit Tests

Proyek ini dilengkapi dengan unit test untuk memastikan logika parsing /proc/net, database, dan file scanner berjalan sempurna. Jalankan perintah ini:

```bash
python -m unittest discover -s tests -v
```

---

📄 Lisensi

Proyek ini dilisensikan di bawah MIT License. Copyright (c) 2026 FajarXdev.

```

***

### 🚀 Langkah Selanjutnya
Setelah lu *copy-paste* README di atas:
1. Simpan (Commit) perubahan di GitHub/Lokal.
2. Jalanin *script git* yang gua kasih di pesan sebelumnya buat nge-push kode `sentinel/` dan folder `tests/` lu.
3. Buka halaman repo GitHub lu, dan lihat hasilnya. Dijamin bakal keliatan kayak *project open-source* yang udah lama dibangun! 🔥

Kalau udah ke-push semua dan repo-nya udah ijo, langsung kabarin gua. Kita gas eksekusi **v0.4 (Deep File Analysis & APK Inspection)**!
