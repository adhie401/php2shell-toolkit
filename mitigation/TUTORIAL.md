# TUTORIAL: Mengamankan Server dari PHP2Shell (CVE-2026-109618 & CVE-2026-109619)

Panduan langkah-demi-langkah untuk **pemula**. Ikuti urutannya; jangan lompat.
Semua perintah dijalankan di **server Linux** (VM) tempat PHP berjalan, sebagai
pengguna **root** (pakai `sudo`).

---

## ⚠️ BACA DULU (penting agar tidak terjadi kesalahan)

1. **Uji di server STAGING/percobaan dulu**, baru produksi. Jangan langsung ke server utama.
2. **Selalu ada backup** — semua script sudah otomatis mem-backup ke `/var/backups/php2shell-mitigation/`. Tapi pastikan Anda juga punya snapshot VM bila memungkinkan.
3. **Coba mode "DRY RUN" dulu** di setiap script (lihat contoh) — ini hanya *menampilkan rencana*, tidak mengubah apa pun.
4. **Jangan jalankan dua kali tanpa perlu.** Jika ragu, jalankan DRY RUN.
5. Jika sesuatu terasa salah, ada **tombol mundur** (rollback/uninstall) di setiap langkah.
6. Script ini **belum pernah dijalankan di server mana pun** — penulisnya hanya memverifikasi sintaksnya. Uji dengan hati-hati.

---

## Apa bedanya "mitigasi" dan "patch"?

| Istilah | Artinya | Menutup CVE sepenuhnya? |
|--------|---------|--------------------------|
| **Mitigasi** (php.ini + WAF) | Penahan sementara, memperkecil risiko | ❌ Tidak |
| **Patch / Update PHP** | Memperbaiki akar masalah | ✅ Ya |

👉 **Tujuan akhir Anda adalah UPDATE PHP.** Mitigasi hanya untuk menahan sampai update selesai.

---

## Daftar file di folder ini

| File | Fungsi |
|------|--------|
| `apply_mitigation.sh` | Pasang mitigasi php.ini (sementara) |
| `rollback_mitigation.sh` | Lepas mitigasi php.ini |
| `update_php.sh` | **Update PHP ke versi aman (perbaikan utama)** |
| `apply_waf_nginx.sh` | Blok upload berbahaya di **Nginx** |
| `apply_waf_apache.sh` | Blok upload berbahaya di **Apache** |
| `waf_snippets.conf` | Contoh aturan WAF (referensi manual) |
| `MITIGATION_ANALYSIS.md` | Analisis dampak & risiko |
| `TUTORIAL.md` | Dokumen ini |

---

## Persiapan (sekali saja)

1. Salin folder `mitigation` ini ke server (misalnya via `scp` atau `git`).
2. Masuk ke folder & beri izin eksekusi:
   ```bash
   cd mitigation
   chmod +x *.sh
   ```
3. Pastikan Anda root:
   ```bash
   sudo -i   # atau tambahkan "sudo " di depan tiap perintah di bawah
   ```

---

## URUTAN LANGKAH (ikuti dari atas ke bawah)

### Langkah 0 — Cek apakah server sudah terlanjur dibobol
Patch **tidak** menghapus backdoor yang sudah terpasang. Cek dulu (dari komputer mana pun yang ada Python):
```bash
pip install httpx
python triage_scan.py domains.txt --shell-check --out sweep.csv
```
Lihat kolom `shell_hits` di `sweep.csv`. Jika ada temuan → **jangan hanya patch**, jalankan prosedur incident response.

---

### Langkah 1 — Pasang mitigasi sementara (php.ini)
Lihat rencana dulu (tidak mengubah apa pun):
```bash
sudo DRY_RUN=1 FPM_MEMORY_MAX=2G ./apply_mitigation.sh
```
Jika rencananya wajar, terapkan (ganti `2G` sesuai RAM VM Anda — sisakan untuk OS):
```bash
sudo FPM_MEMORY_MAX=2G ./apply_mitigation.sh
```
> `FPM_MEMORY_MAX` membatasi memori PHP di level sistem — **wajib** di VM karena kita mematikan batas memori internal PHP untuk menghindari jalur serang.

Script akan: backup → pasang config → **restart PHP-FPM otomatis** → menampilkan nilai efektif.

---

### Langkah 2 — Pasang WAF (pilih SATU: Nginx ATAU Apache)
Ini lapisan **paling kuat** (memblokir pemicu serangan sebelum sampai ke PHP).

> ⚠️ Tanpa daftar pengecualian, **semua upload file akan diblokir**. Jika aplikasi
> Anda punya halaman upload yang sah (mis. admin, media), daftarkan di `ALLOW_PATHS`.

**Kalau server Anda pakai Nginx:**
```bash
sudo DRY_RUN=1 ./apply_waf_nginx.sh                              # lihat rencana
sudo ALLOW_PATHS="/admin/upload /wp-admin" ./apply_waf_nginx.sh  # terapkan + kecualikan upload sah
```

**Kalau server Anda pakai Apache:**
```bash
sudo DRY_RUN=1 ./apply_waf_apache.sh
sudo ALLOW_PATHS="/admin/upload /wp-admin" ./apply_waf_apache.sh
```

Tidak tahu pakai apa? Cek:
```bash
command -v nginx && echo "ada NGINX"
command -v apache2ctl apachectl && echo "ada APACHE"
```

Kedua script WAF otomatis: backup → tulis aturan → **uji config** (`nginx -t` / `configtest`) → reload. **Jika uji config gagal, perubahan otomatis dibatalkan** sehingga situs tidak down.

---

### Langkah 3 — UPDATE PHP (perbaikan utama)
```bash
sudo DRY_RUN=1 ./update_php.sh      # lihat rencana
sudo ./update_php.sh                # jalankan update + restart otomatis
```
Script mendeteksi distro (apt/dnf/yum/zypper), meng-update **hanya paket PHP**, lalu restart.

Versi aman yang dituju: **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**.

---

### Langkah 4 — VERIFIKASI (jangan dilewati!)
`php -v` di terminal **belum tentu** mewakili versi yang dipakai web. Verifikasi dari web:

1. Buat file sementara di web root, mis. `/var/www/html/cekversi.php`:
   ```php
   <?php echo 'PHP: ' . phpversion();
   ```
2. Buka di browser: `https://domain-anda/cekversi.php`
3. Pastikan versinya **≥** salah satu versi aman di atas.
4. **Hapus file itu** setelah selesai:
   ```bash
   rm /var/www/html/cekversi.php
   ```

Cek juga tool OpenAI untuk konfirmasi:
```bash
node phpcheck.js https://domain-anda
```

---

### Langkah 5 — Setelah aman: lepas mitigasi sementara (opsional)
Kalau PHP sudah ter-update & terverifikasi, mitigasi php.ini boleh dilepas agar
fungsi (upload, dsb.) kembali normal:
```bash
sudo ./rollback_mitigation.sh
```
Untuk melepas WAF:
```bash
sudo ./apply_waf_nginx.sh --uninstall     # jika Nginx
sudo ./apply_waf_apache.sh --uninstall    # jika Apache
```
> Catatan: jangan lepas WAF/mitigasi **sebelum** update PHP terverifikasi, karena
> itu membuka kembali celahnya.

---

## Kalau terjadi masalah (Troubleshooting)

| Gejala | Yang harus dilakukan |
|--------|----------------------|
| Situs error/down setelah WAF | `sudo ./apply_waf_nginx.sh --uninstall` (atau apache), lalu reload |
| Upload berhenti bekerja | Normal bila WAF aktif. Tambahkan path upload ke `ALLOW_PATHS` lalu jalankan ulang |
| "Harus dijalankan sebagai root" | Tambahkan `sudo` di depan perintah |
| "service php*fpm tidak terdeteksi" | Restart PHP/web server Anda manual: `sudo systemctl restart <nama-service>` |
| `nginx -t`/`configtest` gagal | Script sudah auto-rollback; terapkan aturan manual dari `waf_snippets.conf` |
| Memori server penuh setelah mitigasi | Pastikan Langkah 1 memakai `FPM_MEMORY_MAX` yang sesuai |

Semua backup ada di: `/var/backups/php2shell-mitigation/`

---

## Ringkasan super singkat (untuk yang terburu-buru)
```bash
cd mitigation && chmod +x *.sh
python triage_scan.py domains.txt --shell-check            # 0. cek bobol
sudo FPM_MEMORY_MAX=2G ./apply_mitigation.sh               # 1. tahan
sudo ALLOW_PATHS="/admin/upload" ./apply_waf_nginx.sh      # 2. WAF (atau _apache)
sudo ./update_php.sh                                        # 3. patch utama
# 4. verifikasi via phpinfo() di browser  (WAJIB)
sudo ./rollback_mitigation.sh                              # 5. (opsional) setelah aman
```

> Ingat: **update PHP (Langkah 3) adalah satu-satunya perbaikan sejati.** Sisanya penahan.
