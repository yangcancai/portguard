#!/usr/bin/env bash
set -Eeuo pipefail

PACKAGE_FILE=""
VERIFY_ACCESS="${VERIFY_ACCESS:-ANY}"
VERIFY_KNOCK_PORT="${VERIFY_KNOCK_PORT:-62201}"
VERIFY_SERVER_HOST="${VERIFY_SERVER_HOST:-verify.example.test}"
VERIFY_SECTION_NAME="${VERIFY_SECTION_NAME:-verify-server}"
VERIFY_ALLOW_IP="${VERIFY_ALLOW_IP:-resolve}"
VERIFY_USER="${VERIFY_USER:-verify-user}"
VERIFY_TIMEOUT="${VERIFY_TIMEOUT:-90}"

usage() {
  cat <<'USAGE'
Install and verify a PortGuard Server package in the current OS image.

Usage:
  scripts/verify-package.sh --package FILE

The verifier installs the local .deb/.rpm, checks first-start key generation,
writes a temporary fwknopd config, checks parser/QR behavior, verifies dynamic
libraries, checks UDP configuration reload and Telegram console handling, and
checks fw-console firewall persistence/rebuild behavior when iptables is usable.
USAGE
}

log() {
  printf '[portguard-package-verify] %s\n' "$*"
}

fail() {
  printf '[portguard-package-verify] ERROR: %s\n' "$*" >&2
  exit 1
}

retry() {
  local attempt
  for attempt in 1 2 3 4 5; do
    if "$@"; then
      return 0
    fi
    if [ "$attempt" = 5 ]; then
      return 1
    fi
    sleep $((attempt * 2))
  done
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --package)
        PACKAGE_FILE="${2:-}"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "unknown option: $1"
        ;;
    esac
  done
}

load_os_release() {
  [ -r /etc/os-release ] || fail "/etc/os-release is missing"
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_VERSION_ID="${VERSION_ID:-}"
  OS_LIKE="${ID_LIKE:-}"
}

configure_centos_vault_repos() {
  if [ "${OS_ID:-}" != "centos" ]; then
    return
  fi

  [ -d /etc/yum.repos.d ] || return

  case "${OS_VERSION_ID%%.*}" in
    7)
      log "configuring CentOS 7 vault repositories"
      sed -i \
        -e 's/^mirrorlist=/#mirrorlist=/' \
        -e 's|^#baseurl=http://mirror.centos.org/centos/$releasever|baseurl=http://vault.centos.org/7.9.2009|' \
        -e 's|^baseurl=http://mirror.centos.org/centos/$releasever|baseurl=http://vault.centos.org/7.9.2009|' \
        /etc/yum.repos.d/CentOS-*.repo
      ;;
    8)
      log "configuring CentOS Stream 8 vault repositories"
      sed -i \
        -e 's/^mirrorlist=/#mirrorlist=/' \
        -e 's|^#baseurl=http://mirror.centos.org/$contentdir/$stream|baseurl=http://vault.centos.org/$contentdir/$stream|' \
        -e 's|^baseurl=http://mirror.centos.org/$contentdir/$stream|baseurl=http://vault.centos.org/$contentdir/$stream|' \
        /etc/yum.repos.d/CentOS-*.repo
      ;;
    *)
      return
      ;;
  esac

  if command -v yum >/dev/null 2>&1; then
    yum clean all >/dev/null 2>&1 || true
  fi
}

os_family() {
  local ids="${OS_ID:-} ${OS_LIKE:-}"
  case "$ids" in
    *debian*|*ubuntu*) printf 'debian\n' ;;
    *rhel*|*fedora*|*centos*|*rocky*) printf 'rhel\n' ;;
    *) fail "unsupported verify OS: ${OS_ID:-unknown}" ;;
  esac
}

install_package() {
  local family="$1"

  case "$family" in
    debian)
      export DEBIAN_FRONTEND=noninteractive
      retry apt-get update -y
      retry apt-get install -y --no-install-recommends ca-certificates iptables
      retry apt-get install -y --no-install-recommends qrencode \
        || log "optional qrencode package is unavailable"
      retry apt-get install -y --no-install-recommends "$PACKAGE_FILE"
      ;;
    rhel)
      local pm="yum"
      if command -v dnf >/dev/null 2>&1; then
        pm="dnf"
      fi
      configure_centos_vault_repos
      retry "$pm" install -y ca-certificates iptables
      retry "$pm" install -y qrencode \
        || log "optional qrencode package is unavailable"
      retry "$pm" install -y "$PACKAGE_FILE"
      ;;
  esac

  if command -v ldconfig >/dev/null 2>&1; then
    ldconfig
  fi
}

assert_file() {
  [ -f "$1" ] || fail "missing file: $1"
}

assert_executable() {
  [ -x "$1" ] || fail "missing executable: $1"
}

expected_version_banner() {
  local family="$1"
  local version release

  case "$family" in
    debian)
      version="$(dpkg-deb -f "$PACKAGE_FILE" Version)"
      release="${version#*+}"
      version="${version%%+*}"
      ;;
    rhel)
      version="$(rpm -qp --queryformat '%{VERSION}' "$PACKAGE_FILE")"
      release="$(rpm -qp --queryformat '%{RELEASE}' "$PACKAGE_FILE")"
      release="${release%%.*}"
      ;;
  esac

  printf 'portguard-server_%s+%s\n' "$version" "$release"
}

verify_version_banner() {
  local family="$1"
  local expected actual

  expected="$(expected_version_banner "$family")"
  actual="$(fwknopd -V)"
  log "checking fwknopd version banner: ${expected}"
  [ "$actual" = "$expected" ] \
    || fail "fwknopd -V returned '${actual}', expected '${expected}'"
}

extract_key_field() {
  local name="$1"
  awk -F':[[:space:]]*' -v n="$name" '$1 == n {print $2; exit}'
}

extract_access_field() {
  local name="$1"
  awk -v n="$name" '$1 == n {print $2; exit}' /etc/fwknop/access.conf
}

verify_first_start_key_initialization() {
  local marker key hmac key_bytes hmac_bytes first_hash second_hash

  marker="__PORTGUARD_GENERATE_ON_FIRST_START__"
  log "checking first-start access key generation"

  [ "$(grep -Ec "^KEY_BASE64[[:space:]]+${marker}$" /etc/fwknop/access.conf)" = "1" ] \
    || fail "packaged access.conf does not contain the KEY_BASE64 first-start placeholder"
  [ "$(grep -Ec "^HMAC_KEY_BASE64[[:space:]]+${marker}$" /etc/fwknop/access.conf)" = "1" ] \
    || fail "packaged access.conf does not contain the HMAC_KEY_BASE64 first-start placeholder"

  fwknopd \
    --exit-parse-config \
    -c /etc/fwknop/fwknopd.conf \
    -a /etc/fwknop/access.conf

  key="$(extract_access_field KEY_BASE64)"
  hmac="$(extract_access_field HMAC_KEY_BASE64)"
  [ -n "$key" ] && [ "$key" != "$marker" ] \
    || fail "first start did not generate KEY_BASE64"
  [ -n "$hmac" ] && [ "$hmac" != "$marker" ] \
    || fail "first start did not generate HMAC_KEY_BASE64"
  printf '%s' "$key" | grep -Eq '^[A-Za-z0-9+/=]+$' \
    || fail "generated KEY_BASE64 is not valid base64 text"
  printf '%s' "$hmac" | grep -Eq '^[A-Za-z0-9+/=]+$' \
    || fail "generated HMAC_KEY_BASE64 is not valid base64 text"
  key_bytes="$(printf '%s' "$key" | base64 --decode 2>/dev/null | wc -c | tr -d '[:space:]')"
  hmac_bytes="$(printf '%s' "$hmac" | base64 --decode 2>/dev/null | wc -c | tr -d '[:space:]')"
  [ "$key_bytes" = "32" ] \
    || fail "generated KEY_BASE64 does not decode to 32 bytes"
  [ "$hmac_bytes" = "64" ] \
    || fail "generated HMAC_KEY_BASE64 does not decode to 64 bytes"
  [ "$(stat -c '%a' /etc/fwknop/access.conf)" = "600" ] \
    || fail "initialized access.conf does not have mode 600"

  first_hash="$(sha256sum /etc/fwknop/access.conf | awk '{print $1}')"
  fwknopd \
    --exit-parse-config \
    -c /etc/fwknop/fwknopd.conf \
    -a /etc/fwknop/access.conf
  second_hash="$(sha256sum /etc/fwknop/access.conf | awk '{print $1}')"
  [ "$first_hash" = "$second_hash" ] \
    || fail "a later start unexpectedly rotated existing access keys"
}

write_verify_config() {
  local key_output key hmac firewall_exe

  key_output="$(fwknopd --key-gen)"
  key="$(printf '%s\n' "$key_output" | extract_key_field KEY_BASE64)"
  hmac="$(printf '%s\n' "$key_output" | extract_key_field HMAC_KEY_BASE64)"
  [ -n "$key" ] || fail "failed to generate KEY_BASE64"
  [ -n "$hmac" ] || fail "failed to generate HMAC_KEY_BASE64"

  firewall_exe="$(command -v iptables || true)"
  [ -n "$firewall_exe" ] || firewall_exe="/usr/sbin/iptables"

  mkdir -p /etc/fwknop /run/fwknop
  cat > /etc/fwknop/fwknopd.conf <<EOF
VERBOSE                     0;
ENABLE_UDP_SERVER           Y;
UDPSERV_PORT                ${VERIFY_KNOCK_PORT};
PCAP_FILTER                 udp port ${VERIFY_KNOCK_PORT};
ENABLE_SPA_PACKET_AGING     Y;
MAX_SPA_PACKET_AGE          120;
FWKNOP_RUN_DIR              /run/fwknop;
FWKNOP_CONF_DIR             /etc/fwknop;
ACCESS_FILE                 access.conf;
FIREWALL_EXE                ${firewall_exe};
SYSLOG_IDENTITY             fwknopd;
SYSLOG_FACILITY             LOG_DAEMON;
PORTGUARD_CLIENT_SERVER     ${VERIFY_SERVER_HOST};
PORTGUARD_SECTION_NAME      ${VERIFY_SECTION_NAME};
PORTGUARD_ALLOW_IP          ${VERIFY_ALLOW_IP};
EOF

  cat > /etc/fwknop/access.conf <<EOF
SOURCE                      ANY
OPEN_PORTS                  ${VERIFY_ACCESS}
KEY_BASE64                  ${key}
HMAC_KEY_BASE64             ${hmac}
REQUIRE_SOURCE_ADDRESS      Y
REQUIRE_USERNAME            ${VERIFY_USER}
FW_ACCESS_TIMEOUT           ${VERIFY_TIMEOUT}
MAX_FW_TIMEOUT              ${VERIFY_TIMEOUT}
EOF

  chmod 600 /etc/fwknop/fwknopd.conf /etc/fwknop/access.conf
}

verify_installed_files() {
  assert_executable /usr/sbin/fwknopd
  assert_file /etc/fwknop/fwknopd.conf
  assert_file /etc/fwknop/access.conf

  if [ -f /lib/systemd/system/fwknopd.service ]; then
    grep -q 'ExecStart=/usr/sbin/fwknopd' /lib/systemd/system/fwknopd.service \
      || fail "systemd unit does not start /usr/sbin/fwknopd"
  elif [ -f /usr/lib/systemd/system/fwknopd.service ]; then
    grep -q 'ExecStart=/usr/sbin/fwknopd' /usr/lib/systemd/system/fwknopd.service \
      || fail "systemd unit does not start /usr/sbin/fwknopd"
  else
    fail "missing systemd unit"
  fi
}

verify_fwknopd() {
  log "checking fwknopd --key-gen"
  fwknopd --key-gen | grep -q '^KEY_BASE64:' \
    || fail "fwknopd --key-gen did not emit KEY_BASE64"

  write_verify_config

  log "checking fwknopd config parser"
  fwknopd \
    --exit-parse-config \
    -c /etc/fwknop/fwknopd.conf \
    -a /etc/fwknop/access.conf

  if command -v qrencode >/dev/null 2>&1; then
    log "checking fwknopd --qr"
    fwknopd \
      --qr \
      -c /etc/fwknop/fwknopd.conf \
      -a /etc/fwknop/access.conf > /tmp/fwknopd-qr.out
    grep -q 'SECTION_NAME:' /tmp/fwknopd-qr.out || fail "fwknopd --qr output is missing SECTION_NAME"
    grep -q "SECTION_NAME:${VERIFY_SECTION_NAME}" /tmp/fwknopd-qr.out || fail "fwknopd --qr output has unexpected SECTION_NAME"
    grep -q "SPA_SERVER:${VERIFY_SERVER_HOST}" /tmp/fwknopd-qr.out || fail "fwknopd --qr output has unexpected SPA_SERVER"
    grep -q "ALLOW_IP:${VERIFY_ALLOW_IP}" /tmp/fwknopd-qr.out || fail "fwknopd --qr output has unexpected ALLOW_IP"
    grep -q "ACCESS:${VERIFY_ACCESS}" /tmp/fwknopd-qr.out || fail "fwknopd --qr output has unexpected ACCESS"
    grep -q 'KEY_BASE64:' /tmp/fwknopd-qr.out || fail "fwknopd --qr output is missing KEY_BASE64"
    grep -q 'HMAC_KEY_BASE64:' /tmp/fwknopd-qr.out || fail "fwknopd --qr output is missing HMAC_KEY_BASE64"
    grep -q "FW_TIMEOUT:${VERIFY_TIMEOUT}" /tmp/fwknopd-qr.out || fail "fwknopd --qr output has unexpected FW_TIMEOUT"
  else
    log "qrencode is unavailable; skipping fwknopd --qr check"
  fi

  if command -v ldd >/dev/null 2>&1; then
    ldd /usr/sbin/fwknopd | tee /tmp/fwknopd-ldd.out
    ! grep -q 'not found' /tmp/fwknopd-ldd.out || fail "fwknopd has missing shared libraries"
  fi
}

verify_telegram_console() {
  local mock_dir token chat_id

  mock_dir="$(mktemp -d /tmp/portguard-tg-mock.XXXXXX)"
  token="123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
  chat_id="-1001234567890"

  cat > "${mock_dir}/curl" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" > /tmp/portguard-tg-curl.args
cat > /tmp/portguard-tg-curl.config
exit 0
EOF
  chmod 0755 "${mock_dir}/curl"

  log "checking fwknopd --fw-console Telegram configuration"
  printf '5\n%s\n%s\n300\ny\ny\n0\n' "$token" "$chat_id" \
    | env PATH="${mock_dir}:${PATH}" fwknopd \
        --fw-console \
        -c /etc/fwknop/fwknopd.conf \
        -a /etc/fwknop/access.conf > /tmp/fwknopd-tg-console.out

  grep -q 'Telegram test notification sent successfully' /tmp/fwknopd-tg-console.out \
    || fail "fw-console Telegram test notification did not succeed"
  grep -q "^PORTGUARD_TG_BOT_TOKEN[[:space:]]*${token};$" /etc/fwknop/fwknopd.conf \
    || fail "fw-console did not persist the Telegram bot token"
  grep -q "^PORTGUARD_TG_CHAT_ID[[:space:]]*${chat_id};$" /etc/fwknop/fwknopd.conf \
    || fail "fw-console did not persist the Telegram chat ID"
  grep -q '^PORTGUARD_TG_NOTIFY_INTERVAL[[:space:]]*300;$' /etc/fwknop/fwknopd.conf \
    || fail "fw-console did not persist the Telegram notification interval"
  [ "$(stat -c '%a' /etc/fwknop/fwknopd.conf)" = "600" ] \
    || fail "fw-console did not keep fwknopd.conf mode 600"

  [ "$(cat /tmp/portguard-tg-curl.args)" = $'--config\n-' ] \
    || fail "Telegram sender passed unexpected curl command-line arguments"
  ! grep -q "$token" /tmp/portguard-tg-curl.args \
    || fail "Telegram bot token leaked into curl command-line arguments"
  grep -q "url = \"https://api.telegram.org/bot${token}/sendMessage\"" \
    /tmp/portguard-tg-curl.config \
    || fail "Telegram sender did not target the Bot API sendMessage method"
  grep -q 'data = "chat_id=-1001234567890&text=PortGuard%20Telegram' \
    /tmp/portguard-tg-curl.config \
    || fail "Telegram sender did not URL-encode the notification payload"

  fwknopd \
    --dump-config \
    -c /etc/fwknop/fwknopd.conf \
    -a /etc/fwknop/access.conf > /tmp/fwknopd-tg-dump.out
  grep -q "PORTGUARD_TG_BOT_TOKEN.*<redacted>" /tmp/fwknopd-tg-dump.out \
    || fail "fwknopd config dump did not redact the Telegram bot token"
  ! grep -q "$token" /tmp/fwknopd-tg-dump.out \
    || fail "fwknopd config dump exposed the Telegram bot token"

  fwknopd \
    --exit-parse-config \
    -c /etc/fwknop/fwknopd.conf \
    -a /etc/fwknop/access.conf

  write_verify_config
}

verify_udp_reload() {
  local daemon_pid recorded_pid

  log "checking UDP server survives fwknopd -R configuration reload"
  rm -f /run/fwknop/fwknopd.pid
  fwknopd \
    --foreground \
    --test \
    -c /etc/fwknop/fwknopd.conf \
    -a /etc/fwknop/access.conf > /tmp/fwknopd-reload.log 2>&1 &
  daemon_pid="$!"
  trap 'kill "$daemon_pid" >/dev/null 2>&1 || true' EXIT

  for _ in 1 2 3 4 5; do
    [ -s /run/fwknop/fwknopd.pid ] && break
    sleep 1
  done
  [ -s /run/fwknop/fwknopd.pid ] \
    || fail "UDP server did not create its PID file"
  kill -0 "$daemon_pid" >/dev/null 2>&1 \
    || fail "UDP server did not stay running before reload"

  fwknopd \
    --restart \
    -c /etc/fwknop/fwknopd.conf \
    -a /etc/fwknop/access.conf > /tmp/fwknopd-restart.out
  grep -q 'Sent restart signal to fwknopd' /tmp/fwknopd-restart.out \
    || fail "fwknopd -R did not send the reload signal"

  for _ in 1 2 3 4 5; do
    grep -q 'Got SIGHUP. Re-reading configs.' /tmp/fwknopd-reload.log \
      && break
    sleep 1
  done
  grep -q 'Got SIGHUP. Re-reading configs.' /tmp/fwknopd-reload.log \
    || fail "UDP server did not process the reload signal"

  for _ in 1 2 3 4 5; do
    [ "$(grep -c 'Kicking off UDP server' /tmp/fwknopd-reload.log || true)" -ge 2 ] \
      && break
    sleep 1
  done
  [ "$(grep -c 'Kicking off UDP server' /tmp/fwknopd-reload.log || true)" -ge 2 ] \
    || fail "UDP server did not resume listening after configuration reload"
  kill -0 "$daemon_pid" >/dev/null 2>&1 \
    || fail "UDP server exited during configuration reload"
  recorded_pid="$(tr -d '[:space:]' < /run/fwknop/fwknopd.pid)"
  [ "$recorded_pid" = "$daemon_pid" ] \
    || fail "UDP server PID changed during configuration reload"

  kill "$daemon_pid"
  wait "$daemon_pid" \
    || fail "UDP server returned an error after SIGTERM"
  ! kill -0 "$daemon_pid" >/dev/null 2>&1 \
    || fail "UDP server did not stop after SIGTERM"
  trap - EXIT
}

iptables_capable() {
  command -v iptables >/dev/null 2>&1 \
    && command -v iptables-save >/dev/null 2>&1 \
    && command -v iptables-restore >/dev/null 2>&1 \
    && iptables -L INPUT -n >/dev/null 2>&1 \
    && iptables-save >/dev/null 2>&1
}

write_non_input_filter_rules() {
  local source="$1"
  local output="$2"

  awk '
    /^# (Generated by|Completed on) / { next }
    $0 == "*filter" { in_filter = 1 }
    in_filter && ($0 ~ /^:INPUT / || $0 ~ /^-A INPUT /) { next }
    { print }
    in_filter && $0 == "COMMIT" { in_filter = 0 }
  ' "$source" > "$output"
}

files_equal() {
  local left="$1"
  local right="$2"

  [ "$(cksum < "$left")" = "$(cksum < "$right")" ]
}

count_matching_rules() {
  local pattern="$1"
  local source="$2"

  awk -v pattern="$pattern" 'BEGIN { count = 0 } $0 ~ pattern { count++ } END { print count }' "$source"
}

verify_fw_console_input_rebuild() {
  local backup prepared after_first after before_non_input after_non_input out chain count

  if ! iptables_capable; then
    log "iptables modification is unavailable; skipping fw-console INPUT rebuild check"
    return 0
  fi

  log "checking fwknopd --fw-console rebuilds only INPUT chain"
  backup="$(mktemp /tmp/portguard-fw-before.XXXXXX)"
  prepared="$(mktemp /tmp/portguard-fw-prepared.XXXXXX)"
  after_first="$(mktemp /tmp/portguard-fw-after-first.XXXXXX)"
  after="$(mktemp /tmp/portguard-fw-after.XXXXXX)"
  before_non_input="$(mktemp /tmp/portguard-fw-before-non-input.XXXXXX)"
  after_non_input="$(mktemp /tmp/portguard-fw-after-non-input.XXXXXX)"
  out="$(mktemp /tmp/portguard-fw-console.XXXXXX)"
  chain="PG_VERIFY_$$"

  iptables-save > "$backup"
  (
    trap 'iptables-restore < "$backup" >/dev/null 2>&1 || true; rm -f "$backup" "$prepared" "$after_first" "$after" "$before_non_input" "$after_non_input" "$out"' EXIT

    iptables -F INPUT
    iptables -P INPUT ACCEPT
    iptables -N "$chain"
    iptables -A "$chain" -j RETURN
    iptables -A FORWARD -j "$chain"
    iptables -N FWKNOP_INPUT 2>/dev/null || true
    iptables -F FWKNOP_INPUT
    iptables -A FWKNOP_INPUT -j RETURN
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A INPUT -p udp --dport "$VERIFY_KNOCK_PORT" -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -j FWKNOP_INPUT
    iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
    iptables -A INPUT -j "$chain"
    iptables-save > "$prepared"

    printf '1\ny\ny\ntcp 22\ndone\n0\n' | timeout 15 fwknopd \
      --fw-console \
      -c /etc/fwknop/fwknopd.conf \
      -a /etc/fwknop/access.conf > "$out"
    iptables-save > "$after_first"

    printf '1\ny\ny\ntcp 22\ndone\n0\n' | timeout 15 fwknopd \
      --fw-console \
      -c /etc/fwknop/fwknopd.conf \
      -a /etc/fwknop/access.conf >> "$out"
    iptables-save > "$after"

    write_non_input_filter_rules "$prepared" "$before_non_input"
    write_non_input_filter_rules "$after" "$after_non_input"
    files_equal "$before_non_input" "$after_non_input" \
      || fail "fw-console initialize changed non-INPUT filter rules"

    ! grep -Eq "^-A INPUT -p tcp( -m tcp)? --dport 2222 -j ACCEPT$" "$after" \
      || fail "fw-console initialize preserved old INPUT tcp/2222 rule"
    ! grep -q "^-A INPUT -j ${chain}$" "$after" \
      || fail "fw-console initialize preserved old INPUT jump rule"
    grep -q "^-A ${chain} -j RETURN$" "$after" \
      || fail "fw-console initialize did not preserve custom chain rules"
    grep -q "^-A FORWARD -j ${chain}$" "$after" \
      || fail "fw-console initialize did not preserve non-INPUT jump rule"
    grep -Eq "^-A INPUT -p udp( -m udp)? --dport ${VERIFY_KNOCK_PORT} -j ACCEPT$" "$after" \
      || fail "fw-console initialize did not add fwknop UDP server port"
    grep -q "^-A INPUT -j FWKNOP_INPUT$" "$after" \
      || fail "fw-console initialize did not keep the FWKNOP_INPUT jump"

    count="$(count_matching_rules "^-A INPUT " "$after")"
    [ "$count" = "6" ] || fail "fw-console initialize left unexpected INPUT rule count"
    count="$(count_matching_rules "^-A INPUT -i lo -j ACCEPT$" "$after")"
    [ "$count" = "1" ] || fail "fw-console initialize left duplicate loopback rules"
    count="$(count_matching_rules "^-A INPUT -p tcp( -m tcp)? --dport 22 -j ACCEPT$" "$after")"
    [ "$count" = "1" ] || fail "fw-console initialize left duplicate tcp/22 rules"
    count="$(count_matching_rules "^-A INPUT -p udp( -m udp)? --dport ${VERIFY_KNOCK_PORT} -j ACCEPT$" "$after")"
    [ "$count" = "1" ] || fail "fw-console initialize left duplicate fwknop UDP server rules"
    count="$(count_matching_rules "^-A INPUT -j FWKNOP_INPUT$" "$after")"
    [ "$count" = "1" ] || fail "fw-console initialize left duplicate FWKNOP_INPUT jumps"
    count="$(count_matching_rules "^-A INPUT .*--state (ESTABLISHED,RELATED|RELATED,ESTABLISHED).* -j ACCEPT$" "$after")"
    [ "$count" = "1" ] || fail "fw-console initialize left duplicate established-state rules"
    count="$(count_matching_rules "^-A INPUT -p icmp -j ACCEPT$" "$after")"
    [ "$count" = "1" ] || fail "fw-console initialize left duplicate icmp rules"

    grep -q 'Firewall INPUT chain initialized successfully' "$out" \
      || fail "fw-console initialize did not report INPUT-only initialization"
  )
}

verify_fw_console_ssh_fallback() {
  local backup prepared after out count

  if ! iptables_capable; then
    log "iptables modification is unavailable; skipping fw-console SSH fallback check"
    return 0
  fi

  log "checking fwknopd --fw-console keeps SSH open on initialize"
  backup="$(mktemp /tmp/portguard-fw-before.XXXXXX)"
  prepared="$(mktemp /tmp/portguard-fw-prepared.XXXXXX)"
  after="$(mktemp /tmp/portguard-fw-after.XXXXXX)"
  out="$(mktemp /tmp/portguard-fw-console.XXXXXX)"

  iptables-save > "$backup"
  (
    trap 'iptables-restore < "$backup" >/dev/null 2>&1 || true; rm -f "$backup" "$prepared" "$after" "$out"' EXIT

    iptables -F INPUT
    iptables -P INPUT ACCEPT
    iptables-save > "$prepared"

    printf '1\ny\nn\n0\n' | SSH_CONNECTION='203.0.113.10 49152 198.51.100.20 2222' timeout 15 fwknopd \
      --fw-console \
      -c /etc/fwknop/fwknopd.conf \
      -a /etc/fwknop/access.conf > "$out"
    iptables-save > "$after"

    grep -q '^:INPUT DROP ' "$after" \
      || fail "fw-console initialize did not change INPUT policy to DROP"
    count="$(count_matching_rules "^-A INPUT -p tcp( -m tcp)? --dport 22 -j ACCEPT$" "$after")"
    [ "$count" = "1" ] || fail "fw-console initialize did not keep tcp/22 open exactly once"
    count="$(count_matching_rules "^-A INPUT -p tcp( -m tcp)? --dport 2222 -j ACCEPT$" "$after")"
    [ "$count" = "1" ] || fail "fw-console initialize did not keep detected SSH tcp/2222 open exactly once"
    grep -Eq "^-A INPUT -p udp( -m udp)? --dport ${VERIFY_KNOCK_PORT} -j ACCEPT$" "$after" \
      || fail "fw-console initialize did not add fwknop UDP server port"
    grep -q 'The SSH fallback port tcp/22 will be kept open to avoid lockout' "$out" \
      || fail "fw-console initialize did not report tcp/22 SSH fallback"
    grep -q 'Detected current SSH server port tcp/2222; it will be kept open' "$out" \
      || fail "fw-console initialize did not report detected SSH server port"
  )
}

verify_fw_console_persistence() {
  local family="$1"

  case "$family" in
    debian)
      log "checking fwknopd --fw-console persists rules to Debian path"
      rm -rf /etc/iptables /etc/sysconfig
      mkdir -p /etc/fwknop /run/fwknop
      printf '3\ntcp\n65535\ny\n0\n' | timeout 10 fwknopd \
        --fw-console \
        -c /etc/fwknop/fwknopd.conf \
        -a /etc/fwknop/access.conf > /tmp/fwknopd-fw-console.out
      grep -q 'Executing: iptables-save > /etc/iptables/rules.v4' /tmp/fwknopd-fw-console.out \
        || fail "fwknopd --fw-console did not save to /etc/iptables/rules.v4 on Debian"
      [ -f /etc/iptables/rules.v4 ] \
        || fail "fwknopd --fw-console did not create /etc/iptables/rules.v4"
      [ ! -e /etc/sysconfig/iptables ] \
        || fail "fwknopd --fw-console unexpectedly wrote /etc/sysconfig/iptables on Debian"
      ;;
    rhel)
      log "checking fwknopd --fw-console persists rules to RHEL path"
      rm -rf /etc/sysconfig
      mkdir -p /etc/fwknop /run/fwknop
      printf '3\ntcp\n65535\ny\n0\n' | timeout 10 fwknopd \
        --fw-console \
        -c /etc/fwknop/fwknopd.conf \
        -a /etc/fwknop/access.conf > /tmp/fwknopd-fw-console.out
      grep -q 'Executing: iptables-save > /etc/sysconfig/iptables' /tmp/fwknopd-fw-console.out \
        || fail "fwknopd --fw-console did not save to /etc/sysconfig/iptables on RHEL"
      [ -f /etc/sysconfig/iptables ] \
        || fail "fwknopd --fw-console did not create /etc/sysconfig/iptables"
      ;;
  esac
}

main() {
  parse_args "$@"
  [ -n "$PACKAGE_FILE" ] || fail "--package is required"
  [ -f "$PACKAGE_FILE" ] || fail "package not found: $PACKAGE_FILE"
  load_os_release

  log "installing ${PACKAGE_FILE} in ${OS_ID}"
  family="$(os_family)"
  install_package "$family"
  verify_installed_files
  verify_version_banner "$family"
  verify_first_start_key_initialization
  verify_fwknopd
  verify_telegram_console
  verify_udp_reload
  verify_fw_console_persistence "$family"
  verify_fw_console_ssh_fallback
  verify_fw_console_input_rebuild
  log "PASS ${PACKAGE_FILE}"
}

main "$@"
