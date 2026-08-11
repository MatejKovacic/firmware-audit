#!/bin/sh
set -eu

# Do not depend on the caller's root PATH.  Minimal Debian installations and
# shells entered through su/sudo may omit /usr/sbin even when account-management
# tools are installed there.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer as root." >&2
  exit 1
fi

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APP_DIR=/opt/firmware-audit
ENV_FILE=/etc/firmware-audit.env

cleanup_obsolete_units() {
  # Stop obsolete triggers before replacing files.  Handle each unit
  # independently so one already-missing legacy unit cannot prevent the
  # remaining timer/service/path units from being stopped and disabled.
  if command -v systemctl >/dev/null 2>&1; then
    for unit in firmware-audit-collect.timer firmware-audit-collect.path firmware-audit-collect.service; do
      systemctl stop "$unit" >/dev/null 2>&1 || true
      systemctl disable "$unit" >/dev/null 2>&1 || true
    done
  fi

  rm -f /etc/systemd/system/firmware-audit-collect.timer \
        /etc/systemd/system/firmware-audit-collect.path \
        /etc/systemd/system/firmware-audit-collect.service
  rm -f /etc/systemd/system/timers.target.wants/firmware-audit-collect.timer \
        /etc/systemd/system/multi-user.target.wants/firmware-audit-collect.service \
        /etc/systemd/system/paths.target.wants/firmware-audit-collect.path
  rm -f /usr/local/libexec/firmware-audit-collect /usr/local/libexec/firmware-audit-request-scan
  rm -f /run/firmware-audit/scan.request /run/firmware-audit/collect.lock

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    for unit in firmware-audit-collect.timer firmware-audit-collect.path firmware-audit-collect.service; do
      systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    done
  fi
}

export DEBIAN_FRONTEND=noninteractive

package_installed() {
  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -qx 'install ok installed'
}

# Firmware Audit must not turn installation into a general OS upgrade.  Ask APT
# only for packages which are genuinely absent.  --no-upgrade additionally
# prevents already-installed packages named by dependency resolution from being
# opportunistically upgraded.  apt-get update is skipped entirely when nothing
# is missing.
REQUIRED_PACKAGES='
python3-flask
gunicorn
python3-gunicorn
fwupd
mokutil
dmidecode
pciutils
usbutils
efibootmgr
tpm2-tools
cryptsetup-bin
kmod
util-linux
systemd
apparmor
cpuid
msr-tools
ipmitool
'
missing_packages=
for package in $REQUIRED_PACKAGES; do
  if ! package_installed "$package"; then
    missing_packages="$missing_packages $package"
  fi
done

coreboot_missing=false
if ! package_installed coreboot-utils; then
  coreboot_missing=true
fi

package_purpose() {
  case "$1" in
    python3-flask) printf '%s' 'Flask runtime for the local dashboard' ;;
    gunicorn) printf '%s' 'Gunicorn executable for the local dashboard' ;;
    python3-gunicorn) printf '%s' 'Gunicorn Python runtime' ;;
    fwupd) printf '%s' 'fwupdmgr firmware/HSI/device evidence' ;;
    mokutil) printf '%s' 'UEFI Secure Boot and MOK evidence' ;;
    dmidecode) printf '%s' 'SMBIOS/DMI firmware and platform evidence' ;;
    pciutils) printf '%s' 'lspci PCI inventory and driver evidence' ;;
    usbutils) printf '%s' 'lsusb USB inventory and topology' ;;
    efibootmgr) printf '%s' 'UEFI boot-entry evidence' ;;
    tpm2-tools) printf '%s' 'TPM properties, PCRs, algorithms and event-log tools' ;;
    cryptsetup-bin) printf '%s' 'encrypted-device mapping/status evidence' ;;
    kmod) printf '%s' 'kernel-module inventory and metadata tools' ;;
    util-linux) printf '%s' 'block, mount and swap inventory tools' ;;
    systemd) printf '%s' 'service management, journal and virtualization detection' ;;
    apparmor) printf '%s' 'aa-status AppArmor state evidence' ;;
    cpuid) printf '%s' 'AMD memory-encryption CPUID evidence' ;;
    msr-tools) printf '%s' 'AMD memory-encryption MSR evidence' ;;
    ipmitool) printf '%s' 'local BMC/IPMI evidence' ;;
    coreboot-utils) printf '%s' 'optional intelmetool Intel ME/CSME evidence' ;;
    *) printf '%s' 'Firmware Audit dependency' ;;
  esac
}

if [ -n "$missing_packages" ] || [ "$coreboot_missing" = true ]; then
  echo
  echo "Firmware Audit found distribution packages that are not currently installed."
  echo "The installer may install the following packages:"
  for package in $missing_packages; do
    printf '  %-20s %s\n' "$package" "$(package_purpose "$package")"
  done
  if [ "$coreboot_missing" = true ]; then
    printf '  %-20s %s\n' "coreboot-utils" "$(package_purpose coreboot-utils)"
    echo "                       (optional; installation continues if you decline it or it is unavailable)"
  fi
  echo
  echo "APT may also need package dependencies. APT will display the complete package"
  echo "transaction and ask for confirmation before any distribution package is installed."
  echo "The installer does not run apt upgrade/full-upgrade and uses --no-upgrade for"
  echo "the requested packages."
  echo
  printf "Continue and let APT resolve these packages? [y/N] "
  IFS= read -r package_answer || package_answer=
  case "$package_answer" in
    y|Y|yes|YES|Yes) ;;
    *)
      echo "Installation cancelled before any Firmware Audit files/services were changed or packages installed."
      exit 1
      ;;
  esac
  echo
fi

# v0.12 replaced the pre-v0.12 collector service/timer/path. Clean those up only
# after package disclosure, so a user who reviews the package list has not yet
# had the existing Firmware Audit installation modified.
cleanup_obsolete_units

if [ -n "$missing_packages" ] || [ "$coreboot_missing" = true ]; then
  echo "Refreshing APT package metadata before dependency resolution..."
  apt-get update
fi

if [ -n "$missing_packages" ]; then
  echo
  echo "APT will now show every package it plans to install/change."
  echo "Confirm the APT prompt to install the required Firmware Audit dependencies."
  # Deliberately do not use -y/--assume-yes: external testers must see and
  # explicitly confirm the complete APT transaction, including dependencies.
  # shellcheck disable=SC2086 -- package names are a controlled internal list.
  apt-get install --no-install-recommends --no-upgrade $missing_packages
else
  echo "All required Firmware Audit packages are already installed; skipping required-package installation."
fi

# intelmetool is an additional, Intel-only evidence source. It is shipped by
# coreboot-utils on Debian/Ubuntu, but the scanner remains usable when that
# optional package is unavailable or when the user declines its APT prompt.
if [ "$coreboot_missing" = true ]; then
  echo
  echo "Optional package coreboot-utils provides intelmetool."
  echo "APT will show its complete dependency transaction and ask separately before installation."
  if ! apt-get install --no-install-recommends --no-upgrade coreboot-utils; then
    echo "WARNING: coreboot-utils was not installed; Intel ME/CSME state may remain Unknown when Linux MEI is unavailable." >&2
  fi
else
  echo "Optional coreboot-utils is already installed."
fi

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

ensure_system_account() {
  name=$1
  description=$2

  if id "$name" >/dev/null 2>&1 && getent group "$name" >/dev/null 2>&1; then
    return 0
  fi

  # systemd-sysusers is the preferred path on supported Debian/Ubuntu systems.
  # It avoids depending on the optional adduser package or on shadow's
  # useradd/groupadd utilities being present in the caller's PATH.
  if sysusers=$(find_admin_tool systemd-sysusers); then
    "$sysusers" --inline "u $name - \"$description\" /nonexistent /usr/sbin/nologin"
    if id "$name" >/dev/null 2>&1 && getent group "$name" >/dev/null 2>&1; then
      return 0
    fi
  fi

  # Compatibility fallback for systems without systemd-sysusers.
  if ! getent group "$name" >/dev/null 2>&1; then
    if tool=$(find_admin_tool addgroup); then
      "$tool" --system "$name"
    elif tool=$(find_admin_tool groupadd); then
      "$tool" --system "$name"
    else
      echo "ERROR: cannot create system group $name: systemd-sysusers, addgroup and groupadd are unavailable." >&2
      exit 1
    fi
  fi

  if ! id "$name" >/dev/null 2>&1; then
    nologin_shell=$(find_admin_tool nologin 2>/dev/null || true)
    [ -n "$nologin_shell" ] || nologin_shell=/usr/sbin/nologin
    if tool=$(find_admin_tool adduser); then
      "$tool" --system --ingroup "$name" --home /nonexistent --no-create-home \
        --shell "$nologin_shell" "$name"
    elif tool=$(find_admin_tool useradd); then
      "$tool" --system --gid "$name" --home-dir /nonexistent --no-create-home \
        --shell "$nologin_shell" "$name"
    else
      echo "ERROR: cannot create system user $name: systemd-sysusers, adduser and useradd are unavailable." >&2
      exit 1
    fi
  fi
}

ensure_system_account firmware-audit "Firmware Audit service"
ensure_system_account firmware-audit-uploader "Firmware Audit uploader"

install -d -o root -g root -m 0755 "$APP_DIR"
install -o root -g root -m 0644 "$SOURCE_DIR/app.py" "$APP_DIR/app.py"
install -o root -g root -m 0644 "$SOURCE_DIR/assessment.py" "$APP_DIR/assessment.py"
install -o root -g root -m 0644 "$SOURCE_DIR/sections.py" "$APP_DIR/sections.py"
install -o root -g root -m 0644 "$SOURCE_DIR/collection_profiles.py" "$APP_DIR/collection_profiles.py"
install -o root -g root -m 0644 "$SOURCE_DIR/report_format.py" "$APP_DIR/report_format.py"
install -o root -g root -m 0755 "$SOURCE_DIR/collector.py" "$APP_DIR/collector.py"
install -o root -g root -m 0755 "$SOURCE_DIR/run_web.py" "$APP_DIR/run_web.py"
install -o root -g root -m 0755 "$SOURCE_DIR/uploader.py" "$APP_DIR/uploader.py"
install -o root -g root -m 0755 "$SOURCE_DIR/uninstall.sh" "$APP_DIR/uninstall.sh"
install -o root -g root -m 0644 "$SOURCE_DIR/README.md" "$APP_DIR/README.md"
install -o root -g root -m 0644 "$SOURCE_DIR/CHANGELOG.md" "$APP_DIR/CHANGELOG.md"
install -o root -g root -m 0644 "$SOURCE_DIR/COLLECTION-CHECKS.md" "$APP_DIR/COLLECTION-CHECKS.md"
install -o root -g root -m 0644 "$SOURCE_DIR/REPORT-FORMAT.md" "$APP_DIR/REPORT-FORMAT.md"
install -o root -g root -m 0644 "$SOURCE_DIR/report-format-v1.schema.json" "$APP_DIR/report-format-v1.schema.json"
install -o root -g root -m 0644 "$SOURCE_DIR/VERSION" "$APP_DIR/VERSION"
rm -rf "$APP_DIR/templates" "$APP_DIR/static"
cp -a "$SOURCE_DIR/templates" "$APP_DIR/templates"
cp -a "$SOURCE_DIR/static" "$APP_DIR/static"
chown -R root:root "$APP_DIR/templates" "$APP_DIR/static"
find "$APP_DIR/templates" "$APP_DIR/static" -type d -exec chmod 0755 {} \;
find "$APP_DIR/templates" "$APP_DIR/static" -type f -exec chmod 0644 {} \;

install -d -o root -g root -m 0755 /usr/local/bin
cat > /usr/local/bin/firmware-audit-scan <<'EOF'
#!/bin/sh
set -eu
exec /usr/bin/python3 /opt/firmware-audit/collector.py --report-dir /var/lib/firmware-audit/reports "$@"
EOF
chmod 0755 /usr/local/bin/firmware-audit-scan
chown root:root /usr/local/bin/firmware-audit-scan
rm -f /usr/local/libexec/firmware-audit-collect

for unit in   firmware-audit-web.service firmware-audit-uploader.service   firmware-audit-scan.service firmware-audit-scan@.service   firmware-audit-daily.service firmware-audit-daily.timer   firmware-audit-monthly.service firmware-audit-monthly.timer
 do
  install -o root -g root -m 0644 "$SOURCE_DIR/systemd/$unit" "/etc/systemd/system/$unit"
 done
install -o root -g root -m 0644 "$SOURCE_DIR/systemd/firmware-audit.tmpfiles" /etc/tmpfiles.d/firmware-audit.conf
systemd-tmpfiles --create /etc/tmpfiles.d/firmware-audit.conf

# The v0.12 viewer intentionally does not load older report formats. Preserve an
# existing pre-v0.12 current snapshot under a different name, then let the new
# initial scan create a v0.12 current.json.
if [ -f /var/lib/firmware-audit/reports/current.json ] && ! grep -q '"name"[[:space:]]*:[[:space:]]*"firmware-audit-report"' /var/lib/firmware-audit/reports/current.json 2>/dev/null; then
  legacy_report="/var/lib/firmware-audit/reports/pre-v0.12-current-$(date +%Y%m%d-%H%M%S).json"
  mv /var/lib/firmware-audit/reports/current.json "$legacy_report"
  echo "Preserved pre-v0.12 current report as $legacy_report"
fi

env_value() {
  key=$1
  sed -n "s/^${key}=//p" "$ENV_FILE" | tail -n 1
}

is_true() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

is_loopback_host() {
  case "$1" in
    127.*|localhost|::1) return 0 ;;
    *) return 1 ;;
  esac
}

replace_env_value() {
  key=$1
  value=$2
  tmp="${ENV_FILE}.tmp.$$"
  awk -v key="$key" -v value="$value" '
    BEGIN { done=0 }
    index($0, key "=") == 1 { print key "=" value; done=1; next }
    { print }
    END { if (!done) print key "=" value }
  ' "$ENV_FILE" > "$tmp"
  chown root:firmware-audit "$tmp"
  chmod 0640 "$tmp"
  mv "$tmp" "$ENV_FILE"
}

remove_env_key() {
  key=$1
  tmp="${ENV_FILE}.tmp.$$"
  awk -v key="$key" 'index($0, key "=") != 1 { print }' "$ENV_FILE" > "$tmp"
  chown root:firmware-audit "$tmp"
  chmod 0640 "$tmp"
  mv "$tmp" "$ENV_FILE"
}

nginx_proxies_to_local_dashboard() {
  port=$1
  [ -d /etc/nginx ] || return 1
  grep -RqsE "proxy_pass[[:space:]]+http://(127\.0\.0\.1|localhost):${port}([/;[:space:]]|$)" /etc/nginx 2>/dev/null
}

validate_or_migrate_web_config() {
  bind_host=$(env_value BIND_HOST)
  bind_port=$(env_value BIND_PORT)
  allow_remote=$(env_value ALLOW_REMOTE_HTTP)
  allow_unauthenticated=$(env_value ALLOW_UNAUTHENTICATED_REMOTE)
  username=$(env_value WEB_USERNAME)
  password_hash=$(env_value WEB_PASSWORD_HASH)

  [ -n "$bind_host" ] || bind_host=127.0.0.1
  [ -n "$bind_port" ] || bind_port=8088

  case "$bind_port" in
    ''|*[!0-9]*)
      echo "ERROR: BIND_PORT must be an integer between 1 and 65535 in $ENV_FILE." >&2
      return 1
      ;;
  esac
  if [ "$bind_port" -lt 1 ] || [ "$bind_port" -gt 65535 ]; then
    echo "ERROR: BIND_PORT must be between 1 and 65535 in $ENV_FILE." >&2
    return 1
  fi

  if { [ -n "$username" ] && [ -z "$password_hash" ]; } || { [ -z "$username" ] && [ -n "$password_hash" ]; }; then
    echo "ERROR: WEB_USERNAME and WEB_PASSWORD_HASH must either both be set or both be empty in $ENV_FILE." >&2
    return 1
  fi

  if ! is_loopback_host "$bind_host" && ! is_true "$allow_remote"; then
    if nginx_proxies_to_local_dashboard "$bind_port"; then
      backup="${ENV_FILE}.before-loopback-$(date +%Y%m%d-%H%M%S)"
      cp -a "$ENV_FILE" "$backup"
      replace_env_value BIND_HOST 127.0.0.1
      echo "Detected nginx proxy to 127.0.0.1:${bind_port}; changed BIND_HOST from $bind_host to 127.0.0.1."
      echo "Previous configuration saved as $backup"
      bind_host=127.0.0.1
    else
      cat >&2 <<EOF
ERROR: $ENV_FILE uses BIND_HOST=$bind_host, but remote plain-HTTP binding is not explicitly allowed.

For the recommended nginx/TLS setup, set:
  BIND_HOST=127.0.0.1

If direct remote HTTP is intentional, explicitly set:
  ALLOW_REMOTE_HTTP=true
and configure WEB_USERNAME/WEB_PASSWORD_HASH, or explicitly acknowledge unauthenticated access.

The web service was not restarted.
EOF
      return 1
    fi
  fi

  if ! is_loopback_host "$bind_host" && [ -z "$username" ] && ! is_true "$allow_unauthenticated"; then
    cat >&2 <<EOF
ERROR: $ENV_FILE permits a non-loopback listener without web authentication.

Configure both WEB_USERNAME and WEB_PASSWORD_HASH, or explicitly set:
  ALLOW_UNAUTHENTICATED_REMOTE=true

The web service was not restarted.
EOF
    return 1
  fi

  return 0
}

if [ ! -f "$ENV_FILE" ]; then
  install -o root -g firmware-audit -m 0640 "$SOURCE_DIR/firmware-audit.env.example" "$ENV_FILE"
else
  echo "Preserving existing $ENV_FILE"
fi

ensure_env_value() {
  key=$1
  value=$2
  if ! grep -q "^${key}=" "$ENV_FILE"; then
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

# Add new v0.12.8 settings to preserved configurations. Manual upload is
# intentionally forced enabled on install/upgrade; no upload occurs until the
# user explicitly clicks Upload report. Other administrator-selected values are
# preserved.
# v0.12.8 policy: manual remote upload is enabled after every install/upgrade.
# This changes an older preserved UPLOAD_ENABLED=false to true.  It does NOT
# trigger an upload; sending a report still requires an explicit dashboard click.
replace_env_value UPLOAD_ENABLED true
ensure_env_value UPLOAD_URL https://audit.telefoncek.si/api/v1/reports
ensure_env_value UPLOAD_SOCKET /run/firmware-audit-uploader/uploader.sock
ensure_env_value UPLOAD_TIMEOUT 30
ensure_env_value CSRF_SECRET_FILE /etc/firmware-audit/csrf.key
# v0.12.8 no longer uses per-machine upload credentials. Remove the obsolete
# setting from preserved configurations so upgrades become immediately usable.
remove_env_key UPLOAD_KEY_FILE
chown root:firmware-audit "$ENV_FILE"
chmod 0640 "$ENV_FILE"

install -d -o root -g root -m 0755 /etc/firmware-audit
if [ ! -f /etc/firmware-audit/csrf.key ]; then
  ( umask 077; /usr/bin/python3 -c 'import secrets; print(secrets.token_hex(32))' > /etc/firmware-audit/csrf.key )
fi
chown root:firmware-audit /etc/firmware-audit/csrf.key
chmod 0640 /etc/firmware-audit/csrf.key

# Older development builds of v0.12.8 used a per-machine bearer token. The
# public receiver now accepts only validated append-only submissions, so the
# token is obsolete. Remove it during upgrade; no administrator provisioning is
# required for the Upload report button.
if [ -e /etc/firmware-audit/upload.key ]; then
  rm -f /etc/firmware-audit/upload.key
  echo "Removed obsolete remote-upload credential."
fi

# Validate preserved settings before touching the running service. Older
# installations commonly used BIND_HOST=0.0.0.0 even when nginx proxied to
# localhost; migrate that safe nginx case automatically.
validate_or_migrate_web_config

systemctl daemon-reload
systemctl enable firmware-audit-uploader.service firmware-audit-web.service
systemctl restart firmware-audit-uploader.service
systemctl restart firmware-audit-web.service
systemctl start --no-block firmware-audit-scan.service

BIND_HOST=$(env_value BIND_HOST)
BIND_PORT=$(env_value BIND_PORT)
[ -n "$BIND_HOST" ] || BIND_HOST=127.0.0.1
[ -n "$BIND_PORT" ] || BIND_PORT=8088

echo
echo "Firmware Audit $(cat "$APP_DIR/VERSION") installed and web service restarted."
echo "Dashboard: http://$BIND_HOST:$BIND_PORT/"
echo "Configuration: $ENV_FILE"
echo "Manual report upload: enabled by default; no credential required; uploads only on an explicit user click"
echo "Current snapshot: /var/lib/firmware-audit/reports/current.json"
echo "Immutable reports: /var/lib/firmware-audit/reports/<report-id>.json"
echo "Initial full scan started in the background; progress is visible in the dashboard."
echo "Optional daily normal scan: systemctl enable --now firmware-audit-daily.timer"
echo "Optional monthly full scan: systemctl enable --now firmware-audit-monthly.timer"
