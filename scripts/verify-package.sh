#!/usr/bin/env bash
set -Eeuo pipefail

PACKAGE_FILE=""
VERIFY_ACCESS="${VERIFY_ACCESS:-tcp/22,tcp/443}"
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

The verifier installs the local .deb/.rpm, writes a temporary fwknopd config,
checks parser/QR/key generation behavior, and verifies dynamic libraries.
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

extract_key_field() {
  local name="$1"
  awk -F':[[:space:]]*' -v n="$name" '$1 == n {print $2; exit}'
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
  verify_fwknopd
  verify_fw_console_persistence "$family"
  log "PASS ${PACKAGE_FILE}"
}

main "$@"
