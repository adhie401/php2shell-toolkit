#!/usr/bin/env bash
# =============================================================================
# apply_waf_apache.sh - Blok multipart/form-data di APACHE (mitigasi PHP2Shell).
# Mendukung Debian/Ubuntu (apache2) & RHEL/Rocky/Alma (httpd).
# Aman untuk pemula: backup -> tulis config -> `apachectl configtest` -> reload.
# Jika configtest GAGAL, config otomatis dilepas (auto-rollback).
#
# Pakai (sebagai root):
#   sudo ./apply_waf_apache.sh
#   sudo ALLOW_PATHS="/admin/upload /api/files" ./apply_waf_apache.sh
#   sudo DRY_RUN=1 ./apply_waf_apache.sh
#   sudo ./apply_waf_apache.sh --uninstall
#
# PERINGATAN: tanpa ALLOW_PATHS, SEMUA upload file diblokir (403).
# =============================================================================
set -euo pipefail

TS="$(date +%Y%m%d-%H%M%S)"
BK="/var/backups/php2shell-mitigation/waf-apache-${TS}"
DRY_RUN="${DRY_RUN:-0}"
ALLOW_PATHS="${ALLOW_PATHS:-}"

log()  { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
run()  { if [ "$DRY_RUN" = "1" ]; then printf '    (dry-run) %s\n' "$*"; else eval "$*"; fi; }

[ "$(id -u)" -eq 0 ] || { warn "Harus dijalankan sebagai root (sudo)."; exit 1; }

# --- Deteksi flavor Apache -------------------------------------------------
if   command -v apache2ctl >/dev/null 2>&1 && [ -d /etc/apache2 ]; then
  FLAVOR=debian; CTL=apache2ctl; SVC=apache2
  CONF="/etc/apache2/conf-available/php2shell-block.conf"
elif command -v apachectl >/dev/null 2>&1 && [ -d /etc/httpd ]; then
  FLAVOR=rhel; CTL=apachectl; SVC=httpd
  CONF="/etc/httpd/conf.d/php2shell-block.conf"
else
  warn "Apache (apache2/httpd) tidak terdeteksi. Jika pakai Nginx gunakan apply_waf_nginx.sh."
  exit 1
fi
log "Apache terdeteksi: $FLAVOR (service: $SVC)"

uninstall() {
  log "Melepas WAF apache..."
  if [ "$FLAVOR" = debian ]; then
    run "a2disconf php2shell-block 2>/dev/null || true"
  fi
  run "rm -f '$CONF'"
  if [ "$DRY_RUN" = "1" ]; then exit 0; fi
  if $CTL configtest; then systemctl reload "$SVC" || true; log "WAF dilepas & $SVC di-reload."
  else warn "configtest gagal setelah uninstall; periksa manual."; fi
  exit 0
}
[ "${1:-}" = "--uninstall" ] && uninstall

# --- 1. Backup -------------------------------------------------------------
run "mkdir -p '$BK'"
run "cp -a '$(dirname "$CONF")' '$BK/' 2>/dev/null || true"
[ -f "$CONF" ] && run "cp -a '$CONF' '$BK/'"
log "Backup -> $BK"

# --- 2. Susun ekspresi <If> (Apache 2.4): deteksi header request + allowlist
# Catatan: pakai %{HTTP:Content-Type} (header REQUEST). mod_rewrite %{CONTENT_TYPE}
# salah karakter (itu tipe RESPONS) & tidak andal di konteks server.
EXPR='%{HTTP:Content-Type} =~ m#multipart/form-data#i'
if [ -n "$ALLOW_PATHS" ]; then
  alt=""
  for p in $ALLOW_PATHS; do alt="${alt}|${p}"; done
  alt="${alt#|}"
  EXPR="${EXPR} && ! (%{REQUEST_URI} =~ m#^(${alt})#)"
fi

# --- 3. Tulis config -------------------------------------------------------
if [ "$DRY_RUN" = "1" ]; then
  printf '    (dry-run) tulis %s (allow: %s)\n' "$CONF" "${ALLOW_PATHS:-<none>}"
else
  {
    echo "# PHP2Shell mitigation (CVE-2026-109618/109619) - ${TS}"
    echo "# Blokir multipart/form-data (pemicu PHP2Shell) kecuali ALLOW_PATHS."
    echo "<If \"${EXPR}\">"
    echo "    Require all denied"
    echo "</If>"
  } > "$CONF"
  log "Config ditulis: $CONF"
fi

# --- 4. Aktifkan config (Debian) -------------------------------------------
if [ "$FLAVOR" = debian ]; then
  run "a2enconf php2shell-block >/dev/null 2>&1 || true"
fi

# --- 5. Uji config & reload (auto-rollback bila gagal) ---------------------
if [ "$DRY_RUN" = "1" ]; then log "DRY-RUN selesai."; exit 0; fi
if $CTL configtest; then
  systemctl reload "$SVC" || service "$SVC" reload || true
  log "configtest OK. Reload sukses. WAF aktif."
else
  warn "configtest GAGAL -> melepas config..."
  [ "$FLAVOR" = debian ] && a2disconf php2shell-block >/dev/null 2>&1 || true
  rm -f "$CONF"
  $CTL configtest && { systemctl reload "$SVC" || true; }
  warn "Config dilepas. Terapkan manual (lihat waf_snippets.conf)."
  exit 1
fi

log "SELESAI. Uji: upload di path sah harus jalan; multipart ke endpoint lain -> 403."
[ -n "$ALLOW_PATHS" ] || warn "Anda TIDAK menetapkan ALLOW_PATHS -> semua upload diblokir. Jika tak diinginkan, uninstall lalu jalankan ulang dengan ALLOW_PATHS."
