# Patching PHP2Shell massal dengan Ansible

Otomasi patch **CVE-2026-109618 / CVE-2026-109619** ke banyak server sekaligus,
**bergelombang (rolling)** agar layanan tidak mati serentak. Mengikuti alur
`IR_RUNBOOK.md`: **backup → (mitigasi) → patch → verifikasi**.

## Apa yang dibutuhkan
- 1 **control node** (laptop/jump host) dengan **Ansible** terpasang.
- Akses **SSH** ke semua server + hak **sudo** di sana.
- Server target: Ubuntu/Debian (apt) atau RHEL/Rocky/Alma (dnf).

## Isi folder
| File | Fungsi |
|------|--------|
| `ansible.cfg` | Konfigurasi dasar (inventory, forks, sudo) |
| `inventory.ini.example` | Contoh daftar server (salin → `inventory.ini`) |
| `group_vars/all.yml` | Versi patched, ukuran batch, opsi mitigasi |
| `backup.yml` | Backup `/etc/php`,`/etc/nginx`,`/etc/apache2` |
| `mitigate.yml` | Mitigasi sementara (php.ini + systemd MemoryMax) |
| `patch.yml` | **Patch utama** (rolling + verifikasi) |
| `verify.yml` | Cek status versi seluruh fleet (read-only) |

---

## Langkah demi langkah

### 1) Pasang Ansible di control node
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y ansible
# RHEL/Rocky           : sudo dnf install -y ansible-core
# via pip (universal)  : python3 -m pip install --user ansible
ansible --version
```

### 2) Siapkan inventory
```bash
cd ansible
cp inventory.ini.example inventory.ini
nano inventory.ini          # isi host, ansible_user, key SSH
```

### 3) Uji koneksi ke semua server
```bash
ansible php_servers -m ping
```
Semua host harus `SUCCESS`. (Jika sudo butuh password: tambah `--ask-become-pass`.)

### 4) Sesuaikan variabel (opsional)
Edit `group_vars/all.yml`:
- `patch_batch` — berapa server per gelombang (mis. `"25%"` atau `"5"`).
- `fpm_memory_max` — batas RAM php-fpm (untuk mitigate.yml).
- `allow_paths` — path upload sah (untuk WAF, diterapkan terpisah).

### 5) Dry-run dulu (TANPA mengubah apa pun)
```bash
ansible-playbook patch.yml --check --diff --limit php_staging
```
`--check` = simulasi. Selalu **mulai dari staging** (`--limit php_staging`).

### 6) Backup (wajib)
```bash
ansible-playbook backup.yml
```
> Tetap ambil **snapshot VM** lewat hypervisor/cloud sebagai lapisan utama.

### 7) (Opsional) Mitigasi sementara sambil menunggu patch
```bash
ansible-playbook mitigate.yml --limit php_staging
# WAF multipart diterapkan terpisah (spesifik aplikasi): lihat ../mitigation/apply_waf_*.sh
```

### 8) PATCH — staging dulu, lalu produksi bergelombang
```bash
# a. Staging
ansible-playbook patch.yml --limit php_staging
# b. Verifikasi staging OK
ansible-playbook verify.yml --limit php_staging
# c. Produksi (otomatis per gelombang sesuai patch_batch)
ansible-playbook patch.yml --limit php_prod
```
`patch.yml` tiap host: backup `/etc/php` → `apt/dnf` upgrade paket php (tetap di
branch) → restart php-fpm + reload web server → cek versi & **assert ≥ patched**.

### 9) Verifikasi seluruh fleet
```bash
ansible-playbook verify.yml
```
Lihat kolom `status=OK`. `PERLU CEK` → periksa host itu (lihat catatan backport).

### 10) Lepas mitigasi sementara (setelah semua OK)
```bash
# php.ini + MemoryMax: jalankan rollback manual atau playbook kebalikannya,
# dan WAF: ../mitigation/apply_waf_nginx.sh --uninstall  (di tiap host / via ansible shell)
```

---

## Catatan penting
- **Rolling update**: `serial` di `patch.yml` memastikan hanya sebagian fleet di-restart
  pada satu waktu — sisanya tetap melayani. `max_fail_percentage: 20` menghentikan rollout
  bila terlalu banyak gagal.
- **Backport distro**: Ubuntu/Debian sering memperbaiki CVE tanpa menaikkan nomor upstream,
  sehingga `assert` versi bisa gagal walau sebenarnya aman. Jika itu terjadi: buktikan fix via
  `ansible php_servers -b -a "apt-get changelog phpX.Y-cli"`, lalu set `skip_version_assert: true`.
- **Patch ≠ pembersihan**: jika `triage_scan.py --shell-check` menemukan web shell, jalankan
  Incident Response (lihat `../IR_RUNBOOK.md` Fase 4) — patch tidak menghapus backdoor.
- **Verifikasi web**: `php -v` CLI belum tentu sama dengan yang melayani web; `verify.yml`
  juga membaca header `X-Powered-By`, tapi kepastian penuh via `phpinfo()` dari request web.
