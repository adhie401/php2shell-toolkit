#!/usr/bin/env bash
# =============================================================================
# update_php.sh - PERBAIKAN SEBENARNYA CVE-2026-109618/109619 (PHP2Shell).
# Update paket PHP ke versi ber-patch (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35),
# sadar-distro. Untuk VM Linux dengan PHP dari paket distro.
#
# Alur:
#   1. Catat versi & daftar paket PHP saat ini (untuk audit/rollback referensi).
#   2. Update HANYA paket PHP (bukan full dist-upgrade) + restart FPM.
#   3. Tampilkan versi baru + pengingat verifikasi.
#
# Jalankan sebagai root. DRY_RUN=1 untuk melihat rencana tanpa mengubah.
# =============================================================================
set -euo pipefail

TS="$(date +%Y%m%d-%H%M%S)"
AUDIT="/var/backups/php2shell-mitigation/update-${TS}.txt"
DRY_RUN="${DRY_RUN:-0}"
log()  { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
run()  { if [ "$DRY_RUN" = "1" ]; then printf '    (dry-run) %s\n' "$*"; else eval "$*"; fi; }

[ "$(id -u)" -eq 0 ] || { warn "Harus root."; exit 1; }
run "mkdir -p '$(dirname "$AUDIT")'"

log "Versi PHP sekarang:"; php -v 2>/dev/null | head -1 || warn "php CLI tak ditemukan"
if [ "$DRY_RUN" != "1" ]; then { echo "== $TS =="; php -v 2>/dev/null | head -1; } >> "$AUDIT"; fi

# --- Deteksi package manager ------------------------------------------------
if   command -v apt-get >/dev/null 2>&1; then PM=apt
elif command -v dnf     >/dev/null 2>&1; then PM=dnf
elif command -v yum     >/dev/null 2>&1; then PM=yum
elif command -v zypper  >/dev/null 2>&1; then PM=zypper
else warn "Package manager tak dikenali. Update PHP manual sesuai distro Anda."; exit 1
fi
log "Package manager: $PM"

# --- Snapshot paket PHP terpasang ------------------------------------------
case "$PM" in
  apt)    PKGS="$(dpkg -l 'php*' 2>/dev/null | awk '/^ii/{print $2}' || true)" ;;
  dnf|yum)PKGS="$(rpm -qa 'php*' 2>/dev/null || true)" ;;
  zypper) PKGS="$(rpm -qa 'php*' 2>/dev/null || true)" ;;
esac
if [ -z "${PKGS// }" ]; then
  warn "Tidak ada paket PHP dari package manager (mungkin PHP dari source/container)."
  warn "update_php.sh ditujukan untuk VM dengan PHP dari paket distro. Hentikan."
  exit 0
fi
if [ "$DRY_RUN" != "1" ]; then printf 'paket PHP sebelum update:\n%s\n' "$PKGS" >> "$AUDIT"; fi
log "Paket PHP terpasang dicatat ke $AUDIT"

# --- Update HANYA paket PHP -------------------------------------------------
case "$PM" in
  apt)
    run "apt-get update"
    # upgrade hanya paket php* yang sudah terpasang
    run "apt-get install --only-upgrade -y \$(dpkg -l 'php*' | awk '/^ii/{print \$2}')" ;;
  dnf)
    run "dnf -y update 'php*'" ;;
  yum)
    run "yum -y update 'php*'" ;;
  zypper)
    run "zypper --non-interactive update 'php*'" ;;
esac

# --- Restart FPM / web server ----------------------------------------------
if command -v systemctl >/dev/null 2>&1; then
  mapfile -t FPM_SVCS < <(systemctl list-unit-files --type=service 2>/dev/null | awk '/php.*fpm/ {print $1}')
  [ "${#FPM_SVCS[@]}" -eq 0 ] && warn "Tidak ada service 'php*fpm' terdeteksi -> jika FPM bernama lain / mod_php, restart web server MANUAL setelah update."
  for s in "${FPM_SVCS[@]}"; do run "systemctl restart '$s' || true"; log "Restart: $s"; done
  run "systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null || true"
fi

log "Versi PHP setelah update:"; php -v 2>/dev/null | head -1 || true
echo
warn "VERIFIKASI WAJIB (patch belum tentu menutup semua jalur sampai dicek):"
warn " 1. Cek versi yang MELAYANI WEB via phpinfo() di TIAP virtual host/node, bukan hanya 'php -v'."
warn " 2. Pastikan versi >= 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (branch 8.1- EOL: pindah branch)."
warn " 3. Build ulang image/redeploy jika PHP juga berjalan di container."
warn " 4. Jalankan compromise sweep (triage_scan.py --shell-check) -> patch TIDAK menghapus backdoor yang sudah ada."
warn " 5. Setelah terverifikasi, mitigasi sementara boleh dilepas: ./rollback_mitigation.sh"
