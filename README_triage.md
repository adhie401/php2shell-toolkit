# Triage Scan — penyapuan defensif portofolio domain sendiri

Pemindai **read-only** untuk menyapu daftar domain **milik sendiri**: inventaris
teknologi, deteksi indikasi web shell yang sudah terpasang, dan penandaan endpoint
upload/panel untuk ditinjau manual. Tidak meng-upload, tidak mengeksploitasi, tidak
membuat shell — hanya GET/HEAD.

> Gunakan hanya pada aset yang Anda miliki atau punya izin tertulis untuk diperiksa.

## Install

```bash
pip install httpx
```

## Pakai

```bash
# Inventaris + penandaan path untuk review
python triage_scan.py domains.txt

# Tambah sweep indikasi web shell (compromise detection)
python triage_scan.py domains.txt --shell-check --out hasil.csv --concurrency 20
```

`domains.txt` — satu domain/URL per baris; baris kosong & `#komentar` diabaikan.

## Output

- Ringkasan di layar + daftar domain dengan indikasi shell.
- CSV (`triage_results.csv`) berisi: reachable, status, server, powered_by,
  php_detected, generator/CMS, shell_hits, review_hits.

## Cara baca hasil

- **shell_hits** → PRIORITAS. Verifikasi manual, lalu jalankan prosedur incident
  response. `+SIG` = isi halaman cocok signature shell (sangat kuat).
- **php2shell_cve** → status CVE-2026-109618 / CVE-2026-109619. `VULNERABLE` =
  versi PHP di bawah rilis ber-patch; `UNKNOWN` = versi disembunyikan, cek di host.
- **review_hits** → endpoint upload/panel yang hidup; tinjau validasi upload &
  kontrol akses.
- **generator** usang / **powered_by** versi lama → cek CVE komponen tsb.

## CVE-2026-109618 & CVE-2026-109619 ("PHP2Shell")

RCE kritis di core PHP (rilis 2026-10-21). Deteksi di sini **berbasis versi**, bukan
eksploit — aman untuk aset produksi. Versi ber-patch: **8.5.12 / 8.4.27 / 8.3.36 /
8.2.35**; PHP 8.1 ke bawah EOL (backport terbatas 7.4/8.0/8.1).

Banyak server menyetel `expose_php=Off` sehingga versi tak terlihat dari luar →
kolom akan `UNKNOWN`. Status pasti hanya dari host:

```bash
php -v                 # versi CLI
# versi yang dipakai web server bisa beda; cek paket:
dpkg -l | grep -i php  # Debian/Ubuntu
rpm -qa | grep -i php  # RHEL/CentOS
```

Mitigasi lengkap satu-satunya: **update ke rilis ber-patch**. Pengguna Plesk: ikuti
advisory Plesk. Perlindungan sementara: WAF rule dari vendor (mis. AWS WAF).

## Catatan

Daftar signature & path sengaja dibuat ringkas untuk sweep awal; kembangkan sesuai
stack Anda. Temuan adalah **indikasi**, bukan vonis — selalu verifikasi.
