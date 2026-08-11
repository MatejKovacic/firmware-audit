#!/bin/sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this uninstaller as root." >&2
  exit 1
fi

PURGE=false
ASSUME_YES=false

usage() {
  cat <<'USAGE'
Usage: uninstall.sh [--purge|/purge] [--yes]

Without --purge, Firmware Audit application files and services are removed,
while reports and configuration are preserved for a later reinstall.

--purge, /purge  Also permanently remove reports, configuration and service accounts.
--yes            Do not ask for confirmation.
-h, --help       Show this help.

Distribution packages installed as dependencies are never removed automatically.
USAGE
}

for arg in "$@"; do
  case "$arg" in
    --purge|/purge|-p) PURGE=true ;;
    --yes|-y) ASSUME_YES=true ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

cat <<'EOF_SUMMARY'
Firmware Audit uninstaller

Will remove:
  - Firmware Audit scanner/viewer/uploader application files
  - Firmware Audit systemd services and timers
  - /usr/local/bin/firmware-audit-scan
  - Firmware Audit tmpfiles configuration and runtime directories
EOF_SUMMARY

if [ "$PURGE" = true ]; then
  cat <<'EOF_PURGE'

PURGE mode will also permanently remove:
  - /var/lib/firmware-audit (including all saved JSON reports)
  - /etc/firmware-audit.env
  - /etc/firmware-audit
  - Firmware Audit service users/groups where account-management tools are available
EOF_PURGE
else
  cat <<'EOF_KEEP'

Will preserve:
  - /var/lib/firmware-audit (including saved JSON reports)
  - /etc/firmware-audit.env and /etc/firmware-audit
  - Firmware Audit service users/groups, so preserved data remains ready for reinstall
EOF_KEEP
fi

cat <<'EOF_PACKAGES'

Distribution packages are NOT removed, even if Firmware Audit originally installed them.
They may now be used by other software or by the administrator directly.
EOF_PACKAGES

if [ "$ASSUME_YES" != true ]; then
  printf "\nContinue? [y/N] "
  IFS= read -r answer || answer=
  case "$answer" in
    y|Y|yes|YES|Yes) ;;
    *) echo "Uninstall cancelled."; exit 1 ;;
  esac
fi

SYSTEMD_UNITS='firmware-audit-web.service firmware-audit-uploader.service firmware-audit-scan.service firmware-audit-daily.service firmware-audit-daily.timer firmware-audit-monthly.service firmware-audit-monthly.timer firmware-audit-collect.service firmware-audit-collect.timer firmware-audit-collect.path'

if command -v systemctl >/dev/null 2>&1; then
  # Stop timers and long-running services first, then any scan units.
  for unit in firmware-audit-daily.timer firmware-audit-monthly.timer firmware-audit-web.service firmware-audit-uploader.service firmware-audit-scan.service firmware-audit-daily.service firmware-audit-monthly.service firmware-audit-collect.timer firmware-audit-collect.path firmware-audit-collect.service; do
    systemctl stop "$unit" >/dev/null 2>&1 || true
  done
  # Stop any currently instantiated area scan services.
  systemctl stop 'firmware-audit-scan@*.service' >/dev/null 2>&1 || true
  for unit in firmware-audit-daily.timer firmware-audit-monthly.timer firmware-audit-web.service firmware-audit-uploader.service firmware-audit-collect.timer firmware-audit-collect.path firmware-audit-collect.service; do
    systemctl disable "$unit" >/dev/null 2>&1 || true
  done
fi

for unit in $SYSTEMD_UNITS firmware-audit-scan@.service; do
  rm -f "/etc/systemd/system/$unit"
done
rm -f /etc/systemd/system/timers.target.wants/firmware-audit-daily.timer \
      /etc/systemd/system/timers.target.wants/firmware-audit-monthly.timer \
      /etc/systemd/system/timers.target.wants/firmware-audit-collect.timer \
      /etc/systemd/system/multi-user.target.wants/firmware-audit-web.service \
      /etc/systemd/system/multi-user.target.wants/firmware-audit-uploader.service \
      /etc/systemd/system/multi-user.target.wants/firmware-audit-collect.service \
      /etc/systemd/system/paths.target.wants/firmware-audit-collect.path

rm -f /etc/tmpfiles.d/firmware-audit.conf
rm -f /usr/local/bin/firmware-audit-scan
rm -f /usr/local/libexec/firmware-audit-collect /usr/local/libexec/firmware-audit-request-scan
rm -rf /run/firmware-audit /run/firmware-audit-uploader

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  for unit in $SYSTEMD_UNITS; do
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  done
fi

# Remove application code after services have stopped.  This may include the
# currently executing installed copy of this script; deleting the pathname does
# not invalidate the already-open script file descriptor.
rm -rf /opt/firmware-audit

find_admin_tool() {
  name=$1
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
    return 0
  fi
  for path in "/usr/sbin/$name" "/usr/bin/$name" "/sbin/$name" "/bin/$name"; do
    if [ -x "$path" ]; then
      printf '%s\n' "$path"
      return 0
    fi
  done
  return 1
}

remove_user_if_present() {
  name=$1
  id "$name" >/dev/null 2>&1 || return 0
  if tool=$(find_admin_tool deluser); then
    "$tool" --system "$name" >/dev/null 2>&1 || {
      echo "WARNING: could not remove service user $name." >&2
      return 0
    }
  elif tool=$(find_admin_tool userdel); then
    "$tool" "$name" >/dev/null 2>&1 || {
      echo "WARNING: could not remove service user $name." >&2
      return 0
    }
  else
    echo "WARNING: no deluser/userdel tool is available; preserved service user $name." >&2
  fi
}

remove_group_if_present() {
  name=$1
  getent group "$name" >/dev/null 2>&1 || return 0
  if tool=$(find_admin_tool delgroup); then
    "$tool" --system "$name" >/dev/null 2>&1 || {
      echo "WARNING: could not remove service group $name." >&2
      return 0
    }
  elif tool=$(find_admin_tool groupdel); then
    "$tool" "$name" >/dev/null 2>&1 || {
      echo "WARNING: could not remove service group $name." >&2
      return 0
    }
  else
    echo "WARNING: no delgroup/groupdel tool is available; preserved service group $name." >&2
  fi
}

if [ "$PURGE" = true ]; then
  rm -rf /var/lib/firmware-audit
  rm -f /etc/firmware-audit.env
  rm -rf /etc/firmware-audit

  remove_user_if_present firmware-audit-uploader
  remove_user_if_present firmware-audit
  remove_group_if_present firmware-audit-uploader
  remove_group_if_present firmware-audit
fi

echo
if [ "$PURGE" = true ]; then
  echo "Firmware Audit removed and local Firmware Audit reports/configuration purged."
else
  echo "Firmware Audit removed. Reports and configuration were preserved."
  echo "To remove those later, reinstall/copy uninstall.sh and run it with --purge (or /purge)."
fi
echo "No distribution packages were removed."
