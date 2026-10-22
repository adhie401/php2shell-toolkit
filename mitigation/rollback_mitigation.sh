#!/usr/bin/env bash
# =============================================================================
# rollback_mitigation.sh
# Membatalkan apply_mitigation.sh: hapus drop-in mitigasi dari semua conf.d,
# lalu restart layanan. Backup php.ini asli tetap tersimpan di /var/backups.
#
# Pakai: sudo ./rollback_mitigation.sh
# =============================================================================
set -euo pipefail

DROPIN_NAME="99-php2shell-mitigation.ini"
log()  { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }

[ "$(id -u)" -eq 0 ] || { warn "Harus dijalankan sebagai root."; exit 1; }

CONF_DIRS=()
for d in /etc/php/*/fpm/conf.d /etc/php/*/apache2/conf.d /etc/php/*/cli/conf.d \
         /etc/php.d /etc/php/conf.d /usr/local/etc/php/conf.d; do
  [ -d "$d" ] && CONF_DIRS+=("$d")
done

removed=0
for d in "${CONF_DIRS[@]}"; do
  if [ -f "$d/$DROPIN_NAME" ]; then
    rm -f "$d/$DROPIN_NAME"
    log "Dihapus: $d/$DROPIN_NAME"
    removed=$((removed+1))
  fi
done
[ "$removed" -eq 0 ] && warn "Tidak ada drop-in mitigasi ditemukan (mungkin sudah dirollback)."

# Hapus juga drop-in systemd MemoryMax (jika dipasang untuk VM)
if command -v systemctl >/dev/null 2>&1; then
  for f in /etc/systemd/system/*php*fpm*.service.d/10-php2shell-memorymax.conf; do
    [ -f "$f" ] && { rm -f "$f"; log "Dihapus: $f"; }
  done
  systemctl daemon-reload 2>/dev/null || true
fi

if command -v systemctl >/dev/null 2>&1; then
  mapfile -t FPM_SVCS < <(systemctl list-unit-files --type=service 2>/dev/null \
      | awk '/php.*fpm/ {print $1}')
  for s in "${FPM_SVCS[@]}"; do systemctl restart "$s" || true; done
  systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null || true
  log "Layanan di-restart/reload."
else
  warn "systemctl tidak ada. Restart PHP-FPM/web server manual."
fi

log "Rollback selesai. Konfigurasi kembali ke nilai semula."
warn "Catatan: dengan rollback ini, mitigasi hilang -> server kembali rentan sampai di-patch."
warn "Backup php.ini asli (bila perlu restore manual) ada di: /var/backups/php2shell-mitigation/"
