# Analisis Mitigasi/Patch PHP2Shell (CVE-2026-109618 & CVE-2026-109619)

> Dokumen ini menyertai `apply_mitigation.sh`. Mitigasi config = **stopgap**;
> perbaikan lengkap = **update PHP** ke 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35.

---

## 1. Dampak setelah "patch" diterapkan

### A. Jika memakai MITIGASI CONFIG (script ini)
| Setting | Efek yang diinginkan | Dampak samping ke aplikasi |
|---|---|---|
| `memory_limit = -1` | Menghindari jalur OOM yang memicu CVE-2026-109618 | **Cap memori hilang** — satu script bisa menyedot seluruh RAM host |
| `post_max_size = 8M` | Membatasi body POST | POST/form > 8 MB **gagal** |
| `session.upload_progress.enabled = 0` | Menutup satu jalur CVE-2026-109619 | Progress-bar upload berhenti berfungsi |
| `fatal_error_backtraces = 0` | Mengurangi info saat fatal error | Debug fatal error lebih minim |
| `file_uploads = Off` (opsional) | Mematikan pemicu upload total | **Semua upload file mati** |
| Blok multipart di WAF | Lapisan terkuat | **Semua fitur upload mati** di host/path tsб |
| Restart PHP-FPM | Mengaktifkan config | Downtime singkat / request in-flight terputus |

### B. Jika memakai UPDATE PHP (perbaikan sebenarnya)
- Binari PHP ter-patch; dalam branch sama (mis. 8.3.x → 8.3.36) ini **rilis patch**, kompatibilitas tinggi, risiko regresi rendah.
- Perlu: restart layanan (downtime singkat), opcache ter-reset, kadang ekstensi pihak-ketiga perlu rebuild, image/container perlu di-build ulang.

---

## 2. Risiko & kerugian terhadap environment

1. **`memory_limit = -1` = risiko operasional terbesar.** Menghapus batas memori bisa memicu **kehabisan RAM** dan OOM-killer menewaskan proses lain di host. **Wajib dipasangkan** dengan batas memori **container/cgroup**, bukan `RLIMIT_AS`/`RLIMIT_DATA`.
2. **Kerusakan fungsional.** Blokir multipart & `post_max_size=8M` dapat mematahkan: upload media CMS (WordPress/Magento), form berkas, sebagian API. Perlu pemetaan endpoint upload yang sah.
3. **Mitigasi diterapkan lewat mekanisme salah = sia-sia.** `ini_set()` atau `.user.ini` **terlambat** — tidak melindungi. Harus via `php.ini`/pool FPM/config server (itulah sebab script pakai drop-in conf.d).
4. **Lupa restart worker = config tidak aktif** padahal dikira aman → *false sense of security*.
5. **Verifikasi di tempat salah.** Nilai `php -v`/CLI bisa beda dari SAPI web. Harus dicek via `phpinfo()` dari request web nyata.
6. **Downtime** saat restart FPM/web server pada jam sibuk.
7. **Drift konfigurasi**: drop-in `99-` meng-override; pastikan tidak ada drop-in lain ber-nomor lebih tinggi yang menimpa balik.

---

## 3. Apakah masih bisa ditembus SETELAH patching?

### Setelah MITIGASI CONFIG saja → **YA, masih mungkin.**
- Sumber resmi menyatakan langkah config **tidak menutup kedua CVE sepenuhnya**; `session.upload_progress=0` hanya mengurangi *satu* jalur.
- Blokir multipart menutup pemicu utama, tetapi PoC bervariasi per OS/versi/web server; jalur pemicu non-multipart tidak dapat dipastikan tertutup.
- Aturan WAF dapat di-*bypass* dengan teknik encoding/charset tertentu.
- **Kesimpulan:** config = menurunkan peluang, bukan menutup pintu.

### Setelah UPDATE PHP (perbaikan benar) → kedua CVE ini tertutup, TAPI tetap ada sisa risiko:
1. **Versi yang salah yang ter-patch.** Anda update CLI/SAPI tertentu, tapi web memakai build/soket PHP lain yang belum ter-patch. → **Selalu verifikasi versi yang MELAYANI web via `phpinfo()`**, bukan `php -v`.
2. **Multi-versi PHP terpasang**; virtual host memakai yang lama.
3. **Container/image belum di-build ulang** → PHP lama masih jalan di container aktif.
4. **Fleet di belakang load balancer** → sebagian node belum ter-patch.
5. **KOMPROMI YANG SUDAH TERJADI SEBELUM PATCH TIDAK HILANG.** CVE ini dieksploitasi aktif sejak 21 Okt 2026. Jika server sudah ditanami **web shell/backdoor** sebelum di-patch, patch menutup celah **tetapi implan tetap ada**. → Wajib **compromise assessment** (gunakan `triage_scan.py --shell-check` + prosedur incident response) **sebelum menganggap aman**.
6. **Kerentanan lain** (plugin/CMS/rantai pasok) di luar cakupan dua CVE ini.

### Urutan aman yang disarankan
1. **Compromise sweep dulu** (apakah sudah terlanjur dibobol?).
2. **WAF blokir multipart** (tahan pemicu) → **mitigasi config** → **restart + verifikasi phpinfo()**.
3. **Jadwalkan & lakukan update PHP** ke versi ber-patch (perbaikan final).
4. **Verifikasi ulang** versi yang melayani web di SEMUA node/container.
5. Jika ada temuan kompromi → jalankan **incident response**, jangan hanya patch.

---

### Ringkasan satu kalimat
Mitigasi config membeli waktu tetapi menyisakan risiko dan dapat mematahkan upload;
update PHP menutup kedua CVE tetapi **tidak** menyembuhkan server yang sudah
terlanjur dibobol — karena itu deteksi kompromi harus mendahului rasa aman.
