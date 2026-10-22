#!/usr/bin/env bash
# =============================================================================
# apply_mitigation.sh
# Mitigasi SEMENTARA CVE-2026-109618 & CVE-2026-109619 (PHP2Shell) via php.ini.
#
# Yang dilakukan:
#   1. BACKUP semua php.ini aktif + drop-in yang ada ke /var/backups/...
#   2. Memasang drop-in 99-php2shell-mitigation.ini di tiap conf.d -> nilai lama
#      DI-OVERRIDE (dinonaktifkan secara efektif), lama tetap tersimpan utuh.
#   3. Restart PHP-FPM / reload web server.
#   4. Verifikasi nilai efektif.
#
# PENTING:
#   - Ini STOPGAP, BUKAN pengganti update PHP. Perbaikan lengkap:
#       apt update && apt install --only-upgrade php*   (Debian/Ubuntu)
#       dnf update php\*                                 (RHEL/Rocky/Alma)
#     ke 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35.
#   - Jalankan sebagai root di SERVER PHP. Uji di staging dulu.
#   - Opsi: DISABLE_UPLOADS=1 -> matikan file_uploads (HANYA jika app tak upload).
#           DRY_RUN=1         -> tampilkan rencana, tidak mengubah apa pun.
# =============================================================================
set -euo pipefail

TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/var/backups/php2shell-mitigation/${TS}"
DROPIN_NAME="99-php2shell-mitigation.ini"
MANIFEST="/var/backups/php2shell-mitigation/${TS}/manifest.txt"
DISABLE_UPLOADS="${DISABLE_UPLOADS:-0}"
DRY_RUN="${DRY_RUN:-0}"

log()  { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
run()  { if [ "$DRY_RUN" = "1" ]; then printf '    (dry-run) %s\n' "$*"; else eval "$*"; fi; }

[ "$(id -u)" -eq 0 ] || { warn "Harus dijalankan sebagai root."; exit 1; }

# --- 1. Temukan direktori conf.d dan php.ini aktif -------------------------
CONF_DIRS=()
for d in /etc/php/*/fpm/conf.d /etc/php/*/apache2/conf.d /etc/php/*/cli/conf.d \
         /etc/php.d /etc/php/conf.d /usr/local/etc/php/conf.d; do
  [ -d "$d" ] && CONF_DIRS+=("$d")
done
INI_FILES=()
for f in /etc/php/*/fpm/php.ini /etc/php/*/apache2/php.ini /etc/php/*/cli/php.ini \
         /etc/php.ini /usr/local/etc/php/php.ini; do
  [ -f "$f" ] && INI_FILES+=("$f")
done

if [ "${#CONF_DIRS[@]}" -eq 0 ]; then
  warn "Tidak menemukan direktori conf.d PHP. Cek lokasi instalasi PHP Anda."
  warn "Petunjuk: jalankan 'php --ini' untuk melihat path, lalu sesuaikan script."
  exit 1
fi

log "conf.d terdeteksi : ${CONF_DIRS[*]}"
log "php.ini terdeteksi: ${INI_FILES[*]:-<tidak ada file utama terpisah>}"
log "Backup ke         : ${BACKUP_DIR}"
[ "$DISABLE_UPLOADS" = "1" ] && log "file_uploads      : AKAN DIMATIKAN (DISABLE_UPLOADS=1)"
[ "$DRY_RUN" = "1" ] && warn "MODE DRY-RUN: tidak ada perubahan yang ditulis."

# --- 2. Backup -------------------------------------------------------------
run "mkdir -p '${BACKUP_DIR}'"
for f in "${INI_FILES[@]}"; do
  run "cp -a '$f' '${BACKUP_DIR}/$(echo "$f" | tr '/' '_')'"
done
# backup drop-in lama yang mungkin bentrok
for d in "${CONF_DIRS[@]}"; do
  if [ -f "$d/$DROPIN_NAME" ]; then
    run "cp -a '$d/$DROPIN_NAME' '${BACKUP_DIR}/PRE_$(echo "$d" | tr '/' '_')_${DROPIN_NAME}'"
  fi
done
log "Backup selesai."

# --- 3. Susun isi drop-in --------------------------------------------------
DROPIN_CONTENT=$(cat <<EOF
; ===========================================================================
; PHP2Shell mitigation (CVE-2026-109618 / CVE-2026-109619)
; Dipasang: ${TS}  oleh apply_mitigation.sh
; STOPGAP - override nilai lama. Rollback: hapus file ini lalu restart.
; ===========================================================================
; CVE-2026-109618 (memory corruption di jalur OOM):
memory_limit = -1
post_max_size = 8M
; CVE-2026-109619 (use-after-free / upload progress):
session.upload_progress.enabled = 0
fatal_error_backtraces = 0
EOF
)
if [ "$DISABLE_UPLOADS" = "1" ]; then
  DROPIN_CONTENT="${DROPIN_CONTENT}"$'\n'"; app tidak butuh upload:"$'\n'"file_uploads = Off"
fi

# --- 4. Tulis drop-in ke tiap conf.d + catat manifest ----------------------
run "mkdir -p '$(dirname "$MANIFEST")'"
for d in "${CONF_DIRS[@]}"; do
  if [ "$DRY_RUN" = "1" ]; then
    printf '    (dry-run) tulis %s/%s\n' "$d" "$DROPIN_NAME"
  else
    printf '%s\n' "$DROPIN_CONTENT" > "$d/$DROPIN_NAME"
    echo "$d/$DROPIN_NAME" >> "$MANIFEST"
    log "Drop-in dipasang: $d/$DROPIN_NAME"
  fi
done
[ "$DRY_RUN" = "1" ] || log "Manifest: $MANIFEST"

# --- 4b. (VM) Batasi memori PHP-FPM di level systemd -----------------------
# Di VM tidak ada cgroup container, jadi memory_limit=-1 bisa menghabiskan RAM
# host. MemoryMax lewat systemd membatasi FPM di level OS (pengganti cgroup).
# Aktif jika FPM_MEMORY_MAX di-set, contoh: FPM_MEMORY_MAX=2G ./apply_mitigation.sh
if [ -n "${FPM_MEMORY_MAX:-}" ] && command -v systemctl >/dev/null 2>&1; then
  mapfile -t _FPM < <(systemctl list-unit-files --type=service 2>/dev/null | awk '/php.*fpm/ {print $1}')
  for s in "${_FPM[@]}"; do
    dropd="/etc/systemd/system/${s}.d"
    run "mkdir -p '$dropd'"
    if [ "$DRY_RUN" = "1" ]; then
      printf '    (dry-run) set MemoryMax=%s untuk %s\n' "$FPM_MEMORY_MAX" "$s"
    else
      printf '[Service]\nMemoryMax=%s\nMemoryHigh=%s\n' "$FPM_MEMORY_MAX" "$FPM_MEMORY_MAX" > "$dropd/10-php2shell-memorymax.conf"
      echo "$dropd/10-php2shell-memorymax.conf" >> "$MANIFEST"
      log "systemd MemoryMax=$FPM_MEMORY_MAX dipasang: $dropd/10-php2shell-memorymax.conf"
    fi
  done
  run "systemctl daemon-reload"
else
  warn "FPM_MEMORY_MAX belum di-set -> memory_limit=-1 TIDAK dibatasi OS."
  warn "Pada VM SANGAT disarankan: ulangi dengan mis. 'sudo FPM_MEMORY_MAX=2G ./apply_mitigation.sh'"
fi

# --- 5. Restart layanan ----------------------------------------------------
if command -v systemctl >/dev/null 2>&1; then
  mapfile -t FPM_SVCS < <(systemctl list-unit-files --type=service 2>/dev/null \
      | awk '/php.*fpm/ {print $1}')
  if [ "${#FPM_SVCS[@]}" -eq 0 ]; then
    warn "Tidak ada service 'php*fpm' terdeteksi. Jika memakai mod_php, reload Apache di bawah sudah cukup; jika FPM bernama lain, restart MANUAL agar config aktif."
  fi
  for s in "${FPM_SVCS[@]}"; do run "systemctl restart '$s' || true"; log "Restart: $s"; done
  run "systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null || true"
  log "Layanan di-restart/reload (jika ada)."
else
  warn "systemctl tidak ada. Restart PHP-FPM/web server secara manual agar aktif."
fi

# --- 6. Verifikasi ---------------------------------------------------------
if command -v php >/dev/null 2>&1; then
  log "Nilai efektif (via CLI - cek juga via phpinfo() di web!):"
  php -r 'foreach (["memory_limit","post_max_size","session.upload_progress.enabled","fatal_error_backtraces","file_uploads"] as $k) printf("    %-34s= %s\n",$k, var_export(ini_get($k),true));' || true
fi

echo
log "SELESAI (mitigasi sementara)."
warn "WAJIB diingat:"
warn " - Nilai CLI bisa beda dari yang dipakai web. Verifikasi lewat phpinfo() dari request web nyata."
warn " - Ini TIDAK menutup CVE sepenuhnya. Jadwalkan update PHP ke versi ber-patch secepatnya."
warn " - Mitigasi WAF (blokir multipart/form-data) = lapisan paling kuat; lihat waf_snippets.conf."
