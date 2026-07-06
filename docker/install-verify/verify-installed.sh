#!/usr/bin/env bash
set -Eeuo pipefail

PORTGUARD_INSTALLER="${PORTGUARD_INSTALLER:-/installer/install.sh}"
PORTGUARD_INSTALL_MODE="${PORTGUARD_INSTALL_MODE:-package}"
PORTGUARD_SOURCE_DIR="${PORTGUARD_SOURCE_DIR:-/src}"
VERIFY_SERVER_HOST="${VERIFY_SERVER_HOST:-verify.example.test}"
VERIFY_ACCESS="${VERIFY_ACCESS:-tcp/22,tcp/443}"
VERIFY_KNOCK_PORT="${VERIFY_KNOCK_PORT:-62201}"
VERIFY_USER="${VERIFY_USER:-verify-user}"
VERIFY_TIMEOUT="${VERIFY_TIMEOUT:-90}"

log() {
  printf '[portguard-docker-verify] %s\n' "$*"
}

fail() {
  printf '[portguard-docker-verify] ERROR: %s\n' "$*" >&2
  exit 1
}

assert_file() {
  [ -f "$1" ] || fail "missing file: $1"
}

assert_executable() {
  [ -x "$1" ] || fail "missing executable: $1"
}

assert_payload_field() {
  local field="$1"
  local value
  value="$(tr ' ' '\n' < /tmp/fwknopd-qr.out | awk -F: -v f="$field" '$1 == f {print $2; exit}')"
  [ -n "$value" ] || fail "missing ${field} in fwknopd --qr output"
  printf '%s\n' "$value"
}

service_file() {
  local candidate
  for candidate in \
    /etc/systemd/system/fwknopd.service \
    /usr/lib/systemd/system/fwknopd.service \
    /lib/systemd/system/fwknopd.service
  do
    if [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

install_server() {
  local args=(
    --server "$VERIFY_SERVER_HOST"
    --access "$VERIFY_ACCESS"
    --knock-port "$VERIFY_KNOCK_PORT"
    --protocol udp
    --allow-ip resolve
    --user "$VERIFY_USER"
    --timeout "$VERIFY_TIMEOUT"
    --skip-start
    --no-firewall
  )

  case "$PORTGUARD_INSTALL_MODE" in
    package)
      ;;
    source)
      [ -d "${PORTGUARD_SOURCE_DIR}/server" ] || fail "missing source tree: ${PORTGUARD_SOURCE_DIR}"
      args=(--source-dir "$PORTGUARD_SOURCE_DIR" "${args[@]}")
      ;;
    *)
      fail "unknown install mode: ${PORTGUARD_INSTALL_MODE}"
      ;;
  esac

  bash "$PORTGUARD_INSTALLER" "${args[@]}"
}

log "running installer inside $(cat /etc/os-release | tr '\n' ' ' 2>/dev/null || uname -a)"
log "install mode: ${PORTGUARD_INSTALL_MODE}"

bash -n "$PORTGUARD_INSTALLER"
install_server

assert_executable /usr/sbin/fwknopd
assert_file /etc/fwknop/fwknopd.conf
assert_file /etc/fwknop/access.conf

unit="$(service_file)" || fail "missing fwknopd systemd unit"
grep -q 'ExecStart=.*fwknopd' "$unit" \
  || fail "systemd unit does not start fwknopd: $unit"

grep -q "UDPSERV_PORT[[:space:]]*${VERIFY_KNOCK_PORT}" /etc/fwknop/fwknopd.conf \
  || fail "fwknopd.conf does not contain expected UDP server port"

grep -q "PORTGUARD_CLIENT_SERVER[[:space:]]*${VERIFY_SERVER_HOST}" /etc/fwknop/fwknopd.conf \
  || fail "fwknopd.conf does not contain expected client server"

grep -q "PORTGUARD_ALLOW_IP[[:space:]]*resolve" /etc/fwknop/fwknopd.conf \
  || fail "fwknopd.conf does not contain expected client allow IP"

grep -q "OPEN_PORTS[[:space:]]*${VERIFY_ACCESS}" /etc/fwknop/access.conf \
  || fail "access.conf does not contain expected open ports"

grep -q "REQUIRE_USERNAME[[:space:]]*${VERIFY_USER}" /etc/fwknop/access.conf \
  || fail "access.conf does not contain expected username"

log "checking fwknopd --qr"
fwknopd \
  --qr \
  -c /etc/fwknop/fwknopd.conf \
  -a /etc/fwknop/access.conf > /tmp/fwknopd-qr.out

section_name="$(assert_payload_field SECTION_NAME)"
server_proto="$(assert_payload_field SPA_SERVER_PROTO)"
server_port="$(assert_payload_field SPA_SERVER_PORT)"
allow_ip="$(assert_payload_field ALLOW_IP)"
access="$(assert_payload_field ACCESS)"
server_host="$(assert_payload_field SPA_SERVER)"
key_base64="$(assert_payload_field KEY_BASE64)"
hmac_key_base64="$(assert_payload_field HMAC_KEY_BASE64)"
use_hmac="$(assert_payload_field USE_HMAC)"
spoof_user="$(assert_payload_field SPOOF_USER)"
fw_timeout="$(assert_payload_field FW_TIMEOUT)"

[ -n "$section_name" ] || fail "SECTION_NAME is empty"
[ "$server_proto" = "udp" ] || fail "unexpected SPA_SERVER_PROTO: $server_proto"
[ "$server_port" = "$VERIFY_KNOCK_PORT" ] || fail "unexpected SPA_SERVER_PORT: $server_port"
[ "$allow_ip" = "resolve" ] || fail "unexpected ALLOW_IP: $allow_ip"
[ "$access" = "$VERIFY_ACCESS" ] || fail "unexpected ACCESS: $access"
[ "$server_host" = "$VERIFY_SERVER_HOST" ] || fail "unexpected SPA_SERVER: $server_host"
[ "$use_hmac" = "Y" ] || fail "unexpected USE_HMAC: $use_hmac"
[ "$spoof_user" = "$VERIFY_USER" ] || fail "unexpected SPOOF_USER: $spoof_user"
[ "$fw_timeout" = "$VERIFY_TIMEOUT" ] || fail "unexpected FW_TIMEOUT: $fw_timeout"

printf '%s' "$key_base64" | grep -Eq '^[A-Za-z0-9+/=]+$' \
  || fail "KEY_BASE64 does not look like base64"
printf '%s' "$hmac_key_base64" | grep -Eq '^[A-Za-z0-9+/=]+$' \
  || fail "HMAC_KEY_BASE64 does not look like base64"

log "checking fwknopd --key-gen"
fwknopd --key-gen | grep -q '^KEY_BASE64:' \
  || fail "fwknopd --key-gen did not emit KEY_BASE64"

log "checking fwknopd config parser"
fwknopd \
  --exit-parse-config \
  -c /etc/fwknop/fwknopd.conf \
  -a /etc/fwknop/access.conf

if command -v ldd >/dev/null 2>&1; then
  ldd /usr/sbin/fwknopd | tee /tmp/fwknopd-ldd.out
  ! grep -q 'not found' /tmp/fwknopd-ldd.out || fail "fwknopd has missing shared libraries"
fi

log "PASS $(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '\"' 2>/dev/null || uname -s)"
