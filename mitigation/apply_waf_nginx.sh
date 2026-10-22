#!/usr/bin/env bash
# =============================================================================
# apply_waf_nginx.sh - Blok multipart/form-data di NGINX (mitigasi PHP2Shell).
# Aman untuk pemula: backup penuh -> tulis config -> `nginx -t` -> reload.
# Jika `nginx -t` GAGAL, config otomatis dikembalikan (auto-rollback).
#
# Pakai (sebagai root):
#   sudo ./apply_waf_nginx.sh                       # blok semua upload multipart
#   sudo ALLOW_PATHS="/admin/upload /api/files" ./apply_waf_nginx.sh   # kecualikan path upload sah
#   sudo DRY_RUN=1 ./apply_waf_nginx.sh             # lihat rencana saja
#   sudo ./apply_waf_nginx.sh --uninstall           # lepas WAF ini
#
# PERINGATAN: tanpa ALLOW_PATHS, SEMUA upload file akan diblokir (403).
# =============================================================================
set -euo pipefail

TS="$(date +%Y%m%d-%H%M%S)"
BK="/var/backups/php2shell-mitigation/waf-nginx-${TS}"
DRY_RUN="${DRY_RUN:-0}"
ALLOW_PATHS="${ALLOW_PATHS:-}"
MAP="/etc/nginx/conf.d/php2shell-map.conf"
SNIP_DIR="/etc/nginx/snippets"
SNIP="${SNIP_DIR}/php2shell-block.conf"

log()  { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
run()  { if [ "$DRY_RUN" = "1" ]; then printf '    (dry-run) %s\n' "$*"; else eval "$*"; fi; }

[ "$(id -u)" -eq 0 ] || { warn "Harus dijalankan sebagai root (sudo)."; exit 1; }
command -v nginx >/dev/null 2>&1 || { warn "nginx tidak ditemukan di server ini."; exit 1; }

uninstall() {
  log "Melepas WAF nginx..."
  run "rm -f '$MAP' '$SNIP'"
  # hapus baris include yang pernah kita tambahkan
  files="$(grep -rl 'php2shell-block.conf' /etc/nginx/sites-enabled /etc/nginx/conf.d 2>/dev/null || true)"
  for f in $files; do run "sed -i '/php2shell-block.conf/d' '$f'"; log "Include dihapus: $f"; done
  if [ "$DRY_RUN" = "1" ]; then exit 0; fi
  if nginx -t; then systemctl reload nginx || true; log "WAF dilepas & nginx di-reload."
  else warn "nginx -t gagal setelah uninstall; periksa manual."; fi
  exit 0
}
[ "${1:-}" = "--uninstall" ] && uninstall

# --- 1. Backup -------------------------------------------------------------
run "mkdir -p '$BK' '$SNIP_DIR'"
run "cp -a /etc/nginx '$BK/nginx'"
log "Backup config nginx -> $BK"

# --- 2. Tulis map (http-level): deteksi multipart + daftar path diizinkan ---
ALLOW_ENTRIES=""
for p in $ALLOW_PATHS; do ALLOW_ENTRIES="${ALLOW_ENTRIES}        \"~*^${p}\" 1;"$'\n'; done
if [ "$DRY_RUN" = "1" ]; then
  printf '    (dry-run) tulis %s (allow: %s)\n' "$MAP" "${ALLOW_PATHS:-<none>}"
else
  {
    echo "# PHP2Shell mitigation (CVE-2026-109618/109619) - ${TS}"
    echo 'map $http_content_type $p2s_is_multipart { default 0; "~*multipart/form-data" 1; }'
    echo 'map $request_uri $p2s_allow {'
    echo '        default 0;'
    printf '%s' "$ALLOW_ENTRIES"
    echo '}'
  } > "$MAP"
  log "Map ditulis: $MAP"
fi

# --- 3. Tulis snippet (dipasang di tiap server{}) --------------------------
if [ "$DRY_RUN" = "1" ]; then
  printf '    (dry-run) tulis %s\n' "$SNIP"
else
  cat > "$SNIP" <<'EOF'
# PHP2Shell mitigation: blokir multipart/form-data kecuali path yang diizinkan.
# p2s_block = "10" berarti (multipart=1 DAN allow=0) -> tolak.
set $p2s_block "${p2s_is_multipart}${p2s_allow}";
if ($p2s_block = "10") { return 403; }
EOF
  log "Snippet ditulis: $SNIP"
fi

# --- 4. Sisipkan include ke server{} pertama tiap file --------------------
targets="$(grep -rlE 'server[[:space:]]*\{' /etc/nginx/sites-enabled /etc/nginx/conf.d 2>/dev/null | grep -v "$MAP" || true)"
if [ -z "$targets" ]; then
  warn "Tidak menemukan blok server{} di sites-enabled/conf.d."
  warn "Tambahkan manual di dalam server{} Anda: include snippets/php2shell-block.conf;"
fi
for f in $targets; do
  grep -q 'php2shell-block.conf' "$f" && { log "Sudah ada include: $f"; continue; }
  if [ "$DRY_RUN" = "1" ]; then printf '    (dry-run) sisipkan include ke %s\n' "$f"
  else
    sed -i '0,/server[[:space:]]*{/s//server {\n    include snippets\/php2shell-block.conf;/' "$f"
    log "Include disisipkan: $f"
  fi
done

# --- 5. Uji config & reload (auto-rollback bila gagal) ---------------------
if [ "$DRY_RUN" = "1" ]; then
  log "DRY-RUN selesai. Tidak ada perubahan nyata."
  exit 0
fi
if nginx -t; then
  systemctl reload nginx || service nginx reload || true
  log "nginx -t OK. Reload sukses. WAF aktif."
else
  warn "nginx -t GAGAL -> mengembalikan konfigurasi dari backup..."
  rm -f "$MAP" "$SNIP"
  cp -a "$BK/nginx/." /etc/nginx/
  nginx -t && { systemctl reload nginx || true; }
  warn "Konfigurasi dikembalikan ke semula. Terapkan manual (lihat waf_snippets.conf)."
  exit 1
fi

log "SELESAI. Uji: upload di path sah harus jalan; multipart ke endpoint lain -> 403."
[ -n "$ALLOW_PATHS" ] || warn "Anda TIDAK menetapkan ALLOW_PATHS -> semua upload diblokir. Jika itu tak diinginkan, uninstall lalu jalankan ulang dengan ALLOW_PATHS."
