# 🛡️ droid-sentinel

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Android%20%7C%20Termux-green.svg?style=flat-square&logo=android&logoColor=white)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

> **Lightweight CLI security monitor for Android (Termux).** 
> Real-time network traffic analysis (TCP/UDP), file watcher for malicious APKs, and native Android alerts. Built with pure Python.

---

## ✨ Fitur Utama

- 🌐 **Network Monitor:** Memantau koneksi TCP & UDP (IPv4/IPv6) secara *real-time* langsung dari `/proc/net/`.
- 🚨 **Anomaly Detection:** Deteksi koneksi ke port mencurigakan (C2 Server, Backdoor, dll).
- 📁 **File Watcher:** Memantau folder `Download` untuk mendeteksi file APK baru secara otomatis.
- 🧬 **SHA256 Hashing:** Menghitung *hash* file APK dengan *caching* (hemat baterai & RAM).
- 🎭 **Double Extension Trap:** Mendeteksi file berbahaya yang menyamar (contoh: `video.mp4.apk`).
- 🔔 **Native Notification:** Kirim *alert* langsung ke *status bar* Android via `Termux:API`.

## ⚙️ Prasyarat (Requirements)

- Aplikasi [Termux](https://f-droid.org/packages/com.termux/) (Download dari F-Droid, **bukan** Play Store).
- Paket Termux:API.
  ```bash
  pkg install termux-api

  🚀 Instalasi & Penggunaan

1. Clone repositori ini:
   ```bash
   git clone https://github.com/FP-error404/droid-sentinel.git
   cd droid-sentinel
   ```
2. Beri izin eksekusi (opsional):
   ```bash
   chmod +x sentinel.py
   ```
3. Jalankan Sentinel:
   ```bash
   python sentinel.py
   ```

🎛️ Kustomisasi CLI

Kamu bisa mengubah direktori yang dipantau atau interval scanning langsung lewat command line:

```bash
# Scan setiap 10 detik
python sentinel.py --interval 10

# Pantau 2 folder sekaligus
python sentinel.py --dir /sdcard/Download --dir /sdcard/Documents
```

📸 Tampilan CLI

(Tips: Taruh screenshot CLI Termux kamu di sini biar makin keren!)
Contoh: ![Preview](docs/preview.png)

⚠️ Disclaimer

Alat ini dibuat untuk tujuan edukasi dan defensive monitoring pada device milik sendiri. Penulis tidak bertanggung jawab atas penyalahgunaan alat ini untuk memantau perangkat orang lain tanpa izin.
