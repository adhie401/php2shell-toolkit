# PHP2Shell Toolkit (CVE-2026-109618 & CVE-2026-109619)

Perkakas internal untuk **deteksi, triase, dan mitigasi** kerentanan PHP2Shell
(CVE-2026-109618 & CVE-2026-109619) pada portofolio domain/server **milik sendiri**.

> ⚠️ **Gunakan HANYA pada aset yang Anda miliki atau punya izin tertulis untuk memeriksanya.**
> Perkakas ini bersifat defensif (read-only untuk pemindaian; mitigasi di sisi server sendiri).

## Isi

| Berkas | Fungsi |
|--------|--------|
| `triage_scan.py` | Pemindai triase portofolio: deteksi versi PHP rentan + indikasi web shell terpasang |
| `run_bulk.js` | Pengecek massal memakai tool OpenAI `phpcheck.js` (txt → CSV) |
| `demo_version_check.py` | Demo logika deteksi versi (stdlib, tanpa dependency) |
| `domains.example.txt` | Contoh daftar domain (ganti dengan milik sendiri) |
| `README_triage.md` | Dokumentasi detail `triage_scan.py` |
| `mitigation/` | Script mitigasi & patch + `TUTORIAL.md` langkah-demi-langkah |

## Mulai cepat

```bash
# Pemindaian portofolio (butuh Python + httpx)
pip install httpx
python triage_scan.py domains.example.txt --shell-check --out hasil.csv
```

Untuk mitigasi/patch server, baca **`mitigation/TUTORIAL.md`**.

## `run_bulk.js` & tool OpenAI (vendored)

`run_bulk.js` membungkus tool resmi OpenAI `phpcheck.js`. Tool itu **sudah disertakan**
di `vendor/php2shell-checker/` (lihat atribusi di bawah), jadi `run_bulk.js` langsung jalan:

```bash
node run_bulk.js domains.txt --out hasil.csv
# (opsional) pakai salinan phpcheck.js lain:
node run_bulk.js domains.txt --tool /path/lain/phpcheck.js
```

> `triage_scan.py` **berdiri sendiri** dan tidak butuh tool ini.

### Atribusi pihak ketiga
`vendor/php2shell-checker/` berisi [openai/php2shell-checker](https://github.com/openai/php2shell-checker)
(© OpenAI, lisensi **Apache-2.0**, lihat `vendor/php2shell-checker/LICENSE`) — disertakan
tanpa modifikasi untuk kemudahan pemakaian.

## Keamanan & etika

- Pemindaian hanya mengirim request read-only (HEAD/GET baca banner, dan—pada
  `--shell-check`—GET ke path indikator). Tidak ada payload eksploit.
- Temuan adalah **indikasi**, bukan vonis — selalu verifikasi manual.
- Jangan sebarkan hasil pemindaian ke publik.

---
*Repo privat internal. Pindahkan ke publik hanya setelah ditinjau.*
