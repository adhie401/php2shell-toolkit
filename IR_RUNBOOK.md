# Runbook Incident Response — PHP2Shell (CVE-2026-109618 & CVE-2026-109619)

Panduan operasional tim IR: dari **backup** sampai **patch terverifikasi**, memakai
script di repo ini. Ikuti berurutan. Setiap fase punya **kriteria lanjut (GO)** dan
**cara mundur (ROLLBACK)**.

> Prinsip: **Deteksi kompromi dulu → tahan (mitigasi) → patch → verifikasi → bersihkan mitigasi.**
> Patch menutup celah, TAPI tidak menghapus backdoor yang sudah masuk.

---

## Prasyarat & aturan main
- Jalankan di server sebagai **root** (`sudo -i` atau awali tiap perintah dengan `sudo`).
- **Uji di staging dulu** bila memungkinkan. Lakukan di **jendela perubahan (maintenance window)**.
- Butuh: **Node.js 18+** (untuk `run_bulk.js`), **Python 3 + httpx** (untuk `triage_scan.py`).
- Pegang **daftar aset resmi** (domain/host dalam scope) + **izin tertulis**.
- Catat semua langkah & waktu (untuk laporan IR). Jangan sebarkan temuan ke publik.
- Versi aman target: **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** (atau paket distro yang sudah di-backport).

---

## Peta fase

| Fase | Tujuan | Script utama | Reversibel? |
|------|--------|--------------|-------------|
| 0 | Persiapan & inventaris | — | — |
| 1 | Deteksi rentan + cek kompromi | `triage_scan.py` | read-only |
| 2 | **Backup** | `apply_*` (auto-backup) + snapshot | — |
| 3 | Tahan sementara (mitigasi + WAF) | `apply_mitigation.sh`, `apply_waf_*` | ya |
| 4 | Jika ada shell → Incident Response | — | — |
| 5 | **Patch** (update PHP) | `update_php.sh` | via snapshot |
| 6 | Verifikasi | `phpinfo()`, `triage_scan.py`, `phpcheck.js --local` | — |
| 7 | Lepas mitigasi sementara | `rollback_mitigation.sh`, `apply_waf_* --uninstall` | — |
| 8 | Penutup & pemantauan | — | — |

---

## FASE 0 — Persiapan
```bash
# Siapkan toolkit di jump host / server
git clone https://github.com/adhie401/php2shell-toolkit.git
cd php2shell-toolkit
chmod +x mitigation/*.sh
# Buat daftar domain milik sendiri
cp domains.example.txt domains.txt && nano domains.txt
```
**GO:** daftar aset siap, akses root ada, maintenance window dibuka.

---

## FASE 1 — Deteksi: mana yang rentan & mana yang sudah dibobol
```bash
pip install httpx
python triage_scan.py domains.txt --shell-check --out fase1_triage.csv
```
Baca `fase1_triage.csv`:
- `php2shell_cve = VULNERABLE` → masuk daftar patch.
- `php2shell_cve = UNKNOWN` → versi tersembunyi; konfirmasi nanti di host (`php -v`).
- **`shell_hits` terisi → DUGAAN SUDAH DIBOBOL** → tandai untuk **FASE 4** (jangan cuma patch).

**GO:** daftar host rentan & host terduga-kompromi sudah terpisah.

> Catatan: deteksi jarak-jauh terbatas. Di tiap host, konfirmasi versi yang MELAYANI web
> (bukan hanya CLI) — lihat Fase 6.

---

## FASE 2 — BACKUP (wajib sebelum mengubah apa pun)
```bash
# 1) Snapshot VM (paling penting) — lakukan via hypervisor/cloud console.
# 2) Backup konfigurasi di host:
TS=$(date +%Y%m%d-%H%M%S)
tar czf /root/backup-php-nginx-$TS.tar.gz /etc/php /etc/nginx /etc/apache2 2>/dev/null
ls -lh /root/backup-php-nginx-$TS.tar.gz
```
> Script `apply_mitigation.sh` & `apply_waf_*` juga **otomatis backup** ke
> `/var/backups/php2shell-mitigation/`, tapi **snapshot VM tetap lapisan utama**.

**GO:** snapshot VM sukses + arsip config ada. **Tanpa ini, JANGAN lanjut.**

---

## FASE 3 — Tahan sementara (mitigasi + WAF)
Tujuan: menutup pemicu serangan **sebelum** patch selesai.

**3a. Hardening php.ini + batas memori systemd (VM):**
```bash
cd mitigation
sudo DRY_RUN=1 FPM_MEMORY_MAX=2G ./apply_mitigation.sh    # lihat rencana
sudo FPM_MEMORY_MAX=2G ./apply_mitigation.sh              # terapkan (sesuaikan RAM)
```
**3b. WAF blok multipart (pilih sesuai web server; kecualikan path upload sah):**
```bash
# Nginx:
sudo ALLOW_PATHS="/admin/upload" ./apply_waf_nginx.sh
# atau Apache:
sudo ALLOW_PATHS="/admin/upload" ./apply_waf_apache.sh
```
Uji cepat: upload di path sah tetap jalan; `multipart` ke endpoint lain → **403**.

**GO:** mitigasi aktif, situs masih berfungsi.
**ROLLBACK:** `sudo ./rollback_mitigation.sh` dan `sudo ./apply_waf_nginx.sh --uninstall`
(atau `apply_waf_apache.sh --uninstall`).

---

## FASE 4 — Jika FASE 1 menemukan shell (DUGAAN KOMPROMI)
**Jangan hanya patch.** Jalankan prosedur IR:
1. **Isolasi** host (putus dari jaringan/segmentasi) bila dibenarkan.
2. **Preservasi bukti**: snapshot forensik, simpan log akses/error, daftar file PHP
   yang baru berubah di webroot:
   ```bash
   find /var/www -name '*.php' -mtime -30 -printf '%TY-%Tm-%Td %p\n' | sort
   grep -rEl 'eval\(|base64_decode|system\(|assert\(|shell_exec' /var/www 2>/dev/null
   ```
3. **Bersihkan backdoor** (hapus/karantina), ganti kredensial yang mungkin bocor.
4. Baru lanjut ke patch. Dokumentasikan untuk laporan.

**GO:** backdoor tertangani & bukti tersimpan.

---

## FASE 5 — PATCH (update PHP, perbaikan sebenarnya)
Cek dulu versi yang tersedia dari distro (tanpa instal):
```bash
sudo apt update
apt-cache policy php8.3-cli        # lihat "Candidate:" (sesuaikan branch Anda)
apt-get changelog php8.3-cli | head -40   # pastikan ada entri CVE-2026-109618/619
```
Jalankan update (tetap di branch yang sama, mis. 8.2 → 8.2.x terbaru):
```bash
cd mitigation
sudo DRY_RUN=1 ./update_php.sh     # lihat rencana
sudo ./update_php.sh               # update paket php* + restart FPM otomatis
```
**GO:** update selesai tanpa error, service `active`.
**ROLLBACK:** pulihkan dari **snapshot VM** (Fase 2) bila update menimbulkan regresi.

---

## FASE 6 — VERIFIKASI (jangan dilewati)
`php -v` CLI **tidak** mewakili versi yang dipakai web. Verifikasi dari web:
```bash
echo '<?php echo "PHP ".phpversion();' | sudo tee /var/www/html/_cek.php
curl -s http://localhost/_cek.php            # harus >= versi patched
sudo rm /var/www/html/_cek.php               # hapus setelah cek
```
Konfirmasi di host & ulangi scan portofolio:
```bash
node vendor/php2shell-checker/phpcheck.js --local   # cek versi CLI host
python triage_scan.py domains.txt --out fase6_triage.csv   # bandingkan dgn fase1
```
**Kriteria SUKSES:**
- `phpinfo()`/`_cek.php` menunjukkan versi **≥** patched (atau paket distro ber-backport CVE).
- Status berubah dari `VULNERABLE` → `OK`.
  (Jika distro backport tanpa menaikkan nomor upstream, scanner bisa tetap `VULNERABLE`
  palsu → buktikan via `apt-get changelog` / `dpkg -l` bahwa fix sudah terpasang.)
- Lakukan di **SEMUA** node/vhost/container (fleet & image di-rebuild).

**GO:** semua host terkonfirmasi ter-patch.

---

## FASE 7 — Lepas mitigasi sementara (setelah patch terverifikasi)
```bash
cd mitigation
sudo ./rollback_mitigation.sh                 # kembalikan php.ini + MemoryMax
sudo ./apply_waf_nginx.sh --uninstall         # atau apply_waf_apache.sh --uninstall
```
> Lepas mitigasi **hanya** setelah Fase 6 sukses. Jika patch belum tuntas di semua host,
> biarkan mitigasi tetap aktif sebagai penahan.

---

## FASE 8 — Penutup
- Simpan `fase1_triage.csv` & `fase6_triage.csv` sebagai bukti sebelum/sesudah.
- Tulis laporan IR: lingkup, temuan, tindakan, waktu, host yang di-patch, temuan shell.
- Pantau log beberapa hari; pastikan tak ada akses mencurigakan baru.
- Jadwalkan pemutakhiran rutin & langganan advisори keamanan.

---

## ✅ Checklist ringkas (tempel di tiket IR)
```
[ ] 0  Toolkit siap, daftar aset & izin ada, maintenance window dibuka
[ ] 1  triage_scan --shell-check -> pisahkan: rentan vs terduga-kompromi
[ ] 2  SNAPSHOT VM + arsip /etc/php,/etc/nginx,/etc/apache2   (WAJIB)
[ ] 3  apply_mitigation (FPM_MEMORY_MAX) + apply_waf_* (ALLOW_PATHS)
[ ] 4  (jika ada shell) isolasi, preservasi bukti, bersihkan backdoor
[ ] 5  cek apt-cache policy/changelog -> update_php.sh
[ ] 6  verifikasi via phpinfo() web + rescan di SEMUA node  -> OK
[ ] 7  rollback_mitigation + apply_waf_* --uninstall (setelah OK)
[ ] 8  laporan IR, simpan CSV before/after, pantau log
```
