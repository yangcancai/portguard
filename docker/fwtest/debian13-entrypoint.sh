#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_MODE="${PORTGUARD_FWTEST_INSTALL_MODE:-local}"
PACKAGE_FILE="${PORTGUARD_FWTEST_PACKAGE:-/pkg/portguard-server.deb}"
INSTALL_URL="${PORTGUARD_FWTEST_INSTALL_URL:-https://portguard.net/install.sh}"
TEST_PORT="${PORTGUARD_FWTEST_PORT:-7700}"
KNOCK_PORT="${PORTGUARD_FWTEST_KNOCK_PORT:-62201}"
HOST_TEST_PORT="${PORTGUARD_FWTEST_HOST_PORT:-17700}"
HOST_SSH_PORT="${PORTGUARD_FWTEST_HOST_SSH_PORT:-22222}"
HOST_KNOCK_PORT="${PORTGUARD_FWTEST_HOST_KNOCK_PORT:-62201}"
SECTION_NAME="${PORTGUARD_FWTEST_SECTION_NAME:-docker-debian13-fwtest}"
CLIENT_NS_NAME="${PORTGUARD_FWTEST_CLIENT_NS:-pgfwclient}"
SERVER_TEST_IP="${PORTGUARD_FWTEST_SERVER_IP:-10.77.0.1}"
CLIENT_TEST_IP="${PORTGUARD_FWTEST_CLIENT_IP:-10.77.0.2}"
EXIT_AFTER_READY="${PORTGUARD_FWTEST_EXIT_AFTER_READY:-0}"
SHELL_AFTER_READY="${PORTGUARD_FWTEST_SHELL_AFTER_READY:-1}"
OPEN_TEST_PORT_ON_INIT="${PORTGUARD_FWTEST_OPEN_TEST_PORT_ON_INIT:-0}"
AUTO_KNOCK="${PORTGUARD_FWTEST_AUTO_KNOCK:-0}"
TELEGRAM_MOCK="${PORTGUARD_FWTEST_TELEGRAM_MOCK:-0}"
TELEGRAM_TOKEN="123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
TELEGRAM_CHAT_ID="-1001234567890"

log() {
  printf '[portguard-fwtest] %s\n' "$*"
}

die() {
  printf '[portguard-fwtest] ERROR: %s\n' "$*" >&2
  exit 1
}

extract_key_field() {
  local name="$1"
  awk -F':[[:space:]]*' -v n="$name" '$1 == n {print $2; exit}'
}

assert_rule() {
  local pattern="$1"
  local message="$2"

  grep -Eq "$pattern" /tmp/iptables-after-fw-console.rules \
    || die "$message"
}

install_runtime_dependencies() {
  export DEBIAN_FRONTEND=noninteractive

  log "installing Debian runtime dependencies"
  apt-get update
  apt-get install -y --no-install-recommends \
    bash ca-certificates curl fwknop-client iptables iproute2 \
    netcat-openbsd procps qrencode
}

stage_fwknop_client() {
  local fwknop_bin

  fwknop_bin="$(command -v fwknop || true)"
  [ -n "$fwknop_bin" ] || die "fwknop client was not installed"

  log "staging fwknop client for manual SPA tests"
  mkdir -p /usr/local/lib/portguard-fwtest
  cp "$fwknop_bin" /usr/local/lib/portguard-fwtest/fwknop

  cat > /usr/local/bin/fwknop <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
exec /usr/local/lib/portguard-fwtest/fwknop "$@"
EOF
  chmod +x /usr/local/bin/fwknop /usr/local/lib/portguard-fwtest/fwknop
}

install_portguard() {
  case "$INSTALL_MODE" in
    local)
      [ -f "$PACKAGE_FILE" ] || die "local package not found: $PACKAGE_FILE"
      log "installing local PortGuard package: $PACKAGE_FILE"
      apt-get install -y --no-install-recommends "$PACKAGE_FILE"
      ;;
    official)
      log "installing PortGuard through official installer: $INSTALL_URL"
      curl -fsSL "$INSTALL_URL" -o /tmp/portguard-install.sh
      bash /tmp/portguard-install.sh \
        || log "official installer returned non-zero; continuing if fwknopd is installed"
      ;;
    *)
      die "unknown install mode: $INSTALL_MODE"
      ;;
  esac

  [ -x /usr/sbin/fwknopd ] || die "fwknopd was not installed"
  command -v fwknop >/dev/null 2>&1 || die "staged fwknop client is missing"
  fwknop --version >/tmp/fwknop-client-version.out
}

write_test_config() {
  local key_output key hmac firewall_exe

  log "writing test fwknopd configuration"
  key_output="$(/usr/sbin/fwknopd --key-gen)"
  key="$(printf '%s\n' "$key_output" | extract_key_field KEY_BASE64)"
  hmac="$(printf '%s\n' "$key_output" | extract_key_field HMAC_KEY_BASE64)"
  [ -n "$key" ] || die "failed to generate KEY_BASE64"
  [ -n "$hmac" ] || die "failed to generate HMAC_KEY_BASE64"

  firewall_exe="$(command -v iptables || true)"
  [ -n "$firewall_exe" ] || firewall_exe="/usr/sbin/iptables"
  printf '%s\n' "$CLIENT_TEST_IP" > /tmp/portguard-fwtest-allow-ip

  mkdir -p /etc/fwknop /run/fwknop
  cat > /etc/fwknop/fwknopd.conf <<EOF
VERBOSE                     0;
ENABLE_UDP_SERVER           Y;
UDPSERV_PORT                ${KNOCK_PORT};
PCAP_FILTER                 udp port ${KNOCK_PORT};
ENABLE_SPA_PACKET_AGING     Y;
MAX_SPA_PACKET_AGE          120;
FWKNOP_RUN_DIR              /run/fwknop;
FWKNOP_CONF_DIR             /etc/fwknop;
ACCESS_FILE                 access.conf;
FIREWALL_EXE                ${firewall_exe};
SYSLOG_IDENTITY             fwknopd;
SYSLOG_FACILITY             LOG_DAEMON;
PORTGUARD_CLIENT_SERVER     ${SERVER_TEST_IP};
PORTGUARD_SECTION_NAME      ${SECTION_NAME};
PORTGUARD_ALLOW_IP          ${CLIENT_TEST_IP};
EOF

  cat > /etc/fwknop/access.conf <<EOF
SOURCE                      ANY
OPEN_PORTS                  ANY
KEY_BASE64                  ${key}
HMAC_KEY_BASE64             ${hmac}
REQUIRE_SOURCE_ADDRESS      N
REQUIRE_USERNAME            portguard
FW_ACCESS_TIMEOUT           60
MAX_FW_TIMEOUT              60
EOF

  grep -v '^OPEN_PORTS[[:space:]]' /etc/fwknop/access.conf \
    > /etc/fwknop/access-deny-any.conf

  cat > /root/.fwknoprc <<EOF
[${SECTION_NAME}]
SPA_SERVER                  ${SERVER_TEST_IP}
SPA_SERVER_PORT             ${KNOCK_PORT}
SPA_SERVER_PROTO            udp
ALLOW_IP                    ${CLIENT_TEST_IP}
ACCESS                      ANY
KEY_BASE64                  ${key}
HMAC_KEY_BASE64             ${hmac}
USE_HMAC                    Y
SPOOF_USER                  portguard
FW_TIMEOUT                  60
EOF

  chmod 600 /etc/fwknop/fwknopd.conf /etc/fwknop/access.conf \
    /etc/fwknop/access-deny-any.conf /root/.fwknoprc
  /usr/sbin/fwknopd \
    --exit-parse-config \
    -c /etc/fwknop/fwknopd.conf \
    -a /etc/fwknop/access.conf
}

write_telegram_mock() {
  if [ "$TELEGRAM_MOCK" != "1" ]; then
    return
  fi

  log "writing Telegram curl mock"
  mkdir -p /usr/local/lib/portguard-fwtest/mock-bin
  cat > /usr/local/lib/portguard-fwtest/mock-bin/curl <<'EOF'
#!/bin/sh
printf '%s\n' "$@" > /tmp/portguard-fwtest-tg.args
cat > /tmp/portguard-fwtest-tg.request
exit 0
EOF
  chmod 0755 /usr/local/lib/portguard-fwtest/mock-bin/curl
}

write_fwknopd_wrapper() {
  log "writing fwknopd convenience wrapper"

  cat > /usr/local/bin/fwknopd <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

fwknopd_bin="/usr/sbin/fwknopd"
needs_config=1
skip_next=0

for arg in "$@"; do
  if [ "$skip_next" = "1" ]; then
    skip_next=0
    continue
  fi

  case "$arg" in
    -c|-a|--config|--config-file|--access-file|--access-folder)
      needs_config=0
      skip_next=1
      ;;
    -c*|-a*|--config=*|--config-file=*|--access-file=*|--access-folder=*)
      needs_config=0
      ;;
    --key-gen|--version|-h|--help)
      needs_config=0
      ;;
  esac
done

if [ "$needs_config" = "1" ]; then
  exec "$fwknopd_bin" "$@" -c /etc/fwknop/fwknopd.conf -a /etc/fwknop/access.conf
fi

exec "$fwknopd_bin" "$@"
EOF
  chmod +x /usr/local/bin/fwknopd

  fwknopd -Q >/tmp/fwknopd-qr.out
}

write_manual_helpers() {
  log "writing manual test helpers"

  cat > /usr/local/bin/pg-fwtest-rules <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
echo "==== INPUT ===="
iptables -L INPUT -n --line-numbers
echo
echo "==== FWKNOP_INPUT ===="
iptables -L FWKNOP_INPUT -n --line-numbers 2>/dev/null || true
EOF

  cat > /usr/local/bin/pg-fwtest-status <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
echo "==== fwknopd status ===="
fwknopd --status || true
echo
echo "==== listeners ===="
ss -lntup | grep -E "(:22|:${PORTGUARD_FWTEST_PORT:-7700}|:${PORTGUARD_FWTEST_KNOCK_PORT:-62201})" || true
echo
pg-fwtest-rules
EOF

  cat > /usr/local/bin/pg-fwtest-probe <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
ip netns exec ${CLIENT_NS_NAME} nc -vz -w 2 ${SERVER_TEST_IP} ${TEST_PORT}
EOF

  cat > /usr/local/bin/pg-fwtest-knock <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
ip netns exec ${CLIENT_NS_NAME} fwknop --rc-file /root/.fwknoprc -n ${SECTION_NAME} --verbose
sleep 1
echo
fwknopd --fw-list || true
echo
pg-fwtest-rules
EOF

  cat > /usr/local/bin/pg-fwtest-check <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
echo "==== before knock: tcp service should be blocked ===="
if pg-fwtest-probe; then
  echo "ERROR: test TCP service is reachable before SPA knock" >&2
  exit 1
fi
echo "blocked as expected"
echo
echo "==== sending knock ===="
pg-fwtest-knock
echo
echo "==== after knock: tcp service should be reachable ===="
pg-fwtest-probe
EOF

  chmod +x /usr/local/bin/pg-fwtest-rules \
    /usr/local/bin/pg-fwtest-status \
    /usr/local/bin/pg-fwtest-probe \
    /usr/local/bin/pg-fwtest-knock \
    /usr/local/bin/pg-fwtest-check
}

start_test_listeners() {
  log "starting TCP listeners on 22 and ${TEST_PORT}"
  nc -lk -p 22 >/tmp/nc22.log 2>&1 &
  nc -lk -p "$TEST_PORT" >"/tmp/nc${TEST_PORT}.log" 2>&1 &
  sleep 1

  ss -lntp | grep -E "(:22|:${TEST_PORT})" \
    || die "test TCP listeners did not start"
}

create_client_namespace() {
  log "creating test client network namespace ${CLIENT_NS_NAME}"
  ip netns delete "$CLIENT_NS_NAME" >/dev/null 2>&1 || true
  ip link delete pgfw-vsrv >/dev/null 2>&1 || true

  ip netns add "$CLIENT_NS_NAME"
  ip link add pgfw-vsrv type veth peer name pgfw-vcli
  ip addr add "${SERVER_TEST_IP}/24" dev pgfw-vsrv
  ip link set pgfw-vsrv up
  ip link set pgfw-vcli netns "$CLIENT_NS_NAME"
  ip netns exec "$CLIENT_NS_NAME" ip addr add "${CLIENT_TEST_IP}/24" dev pgfw-vcli
  ip netns exec "$CLIENT_NS_NAME" ip link set lo up
  ip netns exec "$CLIENT_NS_NAME" ip link set pgfw-vcli up
}

initialize_firewall() {
  log "resetting INPUT chain to simulate a host that relied on policy ACCEPT"
  iptables -F INPUT
  iptables -P INPUT ACCEPT

  log "running fwknopd --fw-console firewall initialization"
  if [ "$OPEN_TEST_PORT_ON_INIT" = "1" ]; then
    printf '1\ny\ny\ntcp %s\ndone\n0\n' "$TEST_PORT" | /usr/sbin/fwknopd \
      --fw-console \
      -c /etc/fwknop/fwknopd.conf \
      -a /etc/fwknop/access.conf
  else
    printf '1\ny\ny\ntcp 22\ndone\n0\n' | /usr/sbin/fwknopd \
      --fw-console \
      -c /etc/fwknop/fwknopd.conf \
      -a /etc/fwknop/access.conf
  fi

  iptables-save > /tmp/iptables-after-fw-console.rules
}

verify_firewall() {
  log "verifying firewall rules"

  assert_rule '^:INPUT DROP ' \
    "INPUT policy was not changed to DROP"
  assert_rule '^-A INPUT -p tcp( -m tcp)? --dport 22 -j ACCEPT$' \
    "tcp/22 is not explicitly open after fw-console initialization"
  assert_rule "^-A INPUT -p udp( -m udp)? --dport ${KNOCK_PORT} -j ACCEPT$" \
    "udp/${KNOCK_PORT} is not explicitly open after fw-console initialization"

  if [ "$OPEN_TEST_PORT_ON_INIT" = "1" ]; then
    assert_rule "^-A INPUT -p tcp( -m tcp)? --dport ${TEST_PORT} -j ACCEPT$" \
      "tcp/${TEST_PORT} is not explicitly open after fw-console initialization"
  elif grep -Eq "^-A INPUT -p tcp( -m tcp)? --dport ${TEST_PORT} -j ACCEPT$" \
      /tmp/iptables-after-fw-console.rules; then
    die "tcp/${TEST_PORT} is already open before SPA knock"
  fi
}

start_fwknopd() {
  local access_file="${1:-/etc/fwknop/access.conf}"
  local log_file="${2:-/tmp/fwknopd.log}"
  local daemon_path="$PATH"

  if [ "$TELEGRAM_MOCK" = "1" ]; then
    daemon_path="/usr/local/lib/portguard-fwtest/mock-bin:${daemon_path}"
  fi

  log "starting fwknopd in UDP server mode with ${access_file}"
  PATH="$daemon_path" /usr/sbin/fwknopd \
    -f \
    -c /etc/fwknop/fwknopd.conf \
    -a "$access_file" > "$log_file" 2>&1 &
  echo "$!" > /run/fwknop/fwknopd-fwtest.pid
  sleep 1

  if ! kill -0 "$(cat /run/fwknop/fwknopd-fwtest.pid)" >/dev/null 2>&1; then
    cat "$log_file" >&2 || true
    die "fwknopd did not stay running"
  fi
}

configure_telegram_for_running_daemon() {
  local pid

  if [ "$TELEGRAM_MOCK" != "1" ]; then
    return
  fi

  log "configuring Telegram after fwknopd has started"
  printf '5\n%s\n%s\n0\ny\nn\n0\n' \
    "$TELEGRAM_TOKEN" "$TELEGRAM_CHAT_ID" \
    | PATH="/usr/local/lib/portguard-fwtest/mock-bin:$PATH" \
      /usr/sbin/fwknopd \
        --fw-console \
        -c /etc/fwknop/fwknopd.conf \
        -a /etc/fwknop/access.conf \
        > /tmp/portguard-fwtest-tg-console.out

  grep -q 'Running fwknopd reloaded the Telegram configuration' \
    /tmp/portguard-fwtest-tg-console.out \
    || die "Telegram console configuration did not reload the running daemon"
  grep -Eq '^PORTGUARD_TG_BOT_TOKEN[[:space:]]+'"${TELEGRAM_TOKEN}"';$' \
    /etc/fwknop/fwknopd.conf \
    || die "Telegram bot token was not saved"
  grep -Eq '^PORTGUARD_TG_CHAT_ID[[:space:]]+'"${TELEGRAM_CHAT_ID}"';$' \
    /etc/fwknop/fwknopd.conf \
    || die "Telegram chat ID was not saved"
  grep -Eq '^PORTGUARD_TG_NOTIFY_INTERVAL[[:space:]]+0;$' \
    /etc/fwknop/fwknopd.conf \
    || die "Telegram notification interval was not saved"

  for _ in 1 2 3 4 5; do
    grep -q 'Got SIGHUP. Re-reading configs.' /tmp/fwknopd.log && break
    sleep 1
  done
  if grep -q 'Got SIGHUP. Re-reading configs.' /tmp/fwknopd.log; then
    log "fwknopd processed the Telegram configuration reload"
  else
    log "SIGHUP reload was not emitted to the foreground log; verifying through the next SPA notification"
  fi

  pid="$(cat /run/fwknop/fwknopd-fwtest.pid)"
  kill -0 "$pid" >/dev/null 2>&1 \
    || die "fwknopd stopped after reloading the Telegram configuration"
  rm -f /tmp/portguard-fwtest-tg.args /tmp/portguard-fwtest-tg.request
}

stop_fwknopd() {
  local pid

  pid="$(cat /run/fwknop/fwknopd-fwtest.pid 2>/dev/null || true)"
  if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid"
    wait "$pid" 2>/dev/null || true
  fi
}

verify_any_requires_explicit_authorization() {
  if [ "$AUTO_KNOCK" != "1" ]; then
    return
  fi

  log "checking that ACCESS ANY is denied without OPEN_PORTS ANY"
  start_fwknopd /etc/fwknop/access-deny-any.conf /tmp/fwknopd-deny-any.log
  pg-fwtest-knock
  if iptables-save | grep -Eq "^-A FWKNOP_INPUT .*${CLIENT_TEST_IP}/32.* -j ACCEPT"; then
    die "ACCESS ANY created a firewall rule without explicit OPEN_PORTS ANY authorization"
  fi
  stop_fwknopd
}

auto_knock_if_requested() {
  if [ "$AUTO_KNOCK" != "1" ]; then
    return
  fi

  log "checking that tcp/${TEST_PORT} is blocked before SPA knock"
  if pg-fwtest-probe; then
    die "tcp/${TEST_PORT} is reachable before SPA knock"
  fi

  log "sending automatic SPA knock"
  pg-fwtest-knock
  any_rule="$(iptables-save | grep -E "^-A FWKNOP_INPUT .*${CLIENT_TEST_IP}/32.* -j ACCEPT" | head -n 1 || true)"
  [ -n "$any_rule" ] \
    || die "ACCESS ANY did not add a source-only rule to FWKNOP_INPUT"
  if printf '%s\n' "$any_rule" | grep -Eq -- ' (-p|--dport) '; then
    die "ACCESS ANY rule unexpectedly restricts protocol or destination port: ${any_rule}"
  fi
  pg-fwtest-probe \
    || die "tcp/${TEST_PORT} is not reachable after ACCESS ANY knock"

  if [ "$TELEGRAM_MOCK" = "1" ]; then
    for _ in 1 2 3 4 5; do
      [ -s /tmp/portguard-fwtest-tg.request ] && break
      sleep 1
    done
    if [ ! -s /tmp/portguard-fwtest-tg.request ]; then
      cat /tmp/portguard-fwtest-tg-console.out >&2 || true
      cat /tmp/fwknopd.log >&2 || true
      die "successful SPA knock did not trigger a Telegram notification"
    fi
    [ "$(cat /tmp/portguard-fwtest-tg.args)" = $'--config\n-' ] \
      || die "Telegram bot token was exposed in curl arguments"
    grep -q 'text=PortGuard%20access%20granted' /tmp/portguard-fwtest-tg.request \
      || die "Telegram notification is missing the access-granted event"
    grep -q 'Source%20IP%3A%2010.77.0.2' /tmp/portguard-fwtest-tg.request \
      || die "Telegram notification is missing the allowed source IP"
    grep -q 'Access%3A%20ANY' /tmp/portguard-fwtest-tg.request \
      || die "Telegram notification is missing the requested access"
    grep -q 'Expires%20at%3A%20' /tmp/portguard-fwtest-tg.request \
      || die "Telegram notification is missing the expiration time"
    log "Telegram notification triggered after successful SPA rule creation"
  fi
}

print_status() {
  echo
  echo "==== INPUT rules ===="
  iptables -L INPUT -n --line-numbers

  echo
  echo "==== listeners ===="
  ss -lntup | grep -E "(:22|:${TEST_PORT}|:${KNOCK_PORT})" || true

  echo
  echo "Container ready."
  echo "Manual SPA test inside this container:"
  echo "  1. Before knock, this should fail or time out:"
  echo "     pg-fwtest-probe"
  echo "  2. Send the SPA packet:"
  echo "     pg-fwtest-knock"
  echo "  3. After knock, this should succeed:"
  echo "     pg-fwtest-probe"
  echo "  Or run the full manual check:"
  echo "     pg-fwtest-check"
  echo
  echo "Container helper commands:"
  echo "  pg-fwtest-status"
  echo "  pg-fwtest-rules"
  echo "  pg-fwtest-probe"
  echo "  pg-fwtest-knock"
  echo "  pg-fwtest-check"
  echo "  fwknopd -Q"
  echo "  fwknopd --fw-console"
  echo
  echo "Test client namespace: ${CLIENT_NS_NAME} (${CLIENT_TEST_IP} -> ${SERVER_TEST_IP})"
  echo "Host SSH fallback port mapping: nc -vz 127.0.0.1 ${HOST_SSH_PORT}"
  echo "Host TCP test port mapping: ${HOST_TEST_PORT}/tcp -> ${TEST_PORT}/tcp"
  echo "Host UDP knock port mapping: ${HOST_KNOCK_PORT}/udp -> ${KNOCK_PORT}/udp"
  echo "fwknop client rc: /root/.fwknoprc"
  echo "SPA allow IP used for firewall rule: $(cat /tmp/portguard-fwtest-allow-ip)"
  echo "fwknopd log: /tmp/fwknopd.log"
}

main() {
  install_runtime_dependencies
  stage_fwknop_client
  install_portguard
  write_test_config
  write_telegram_mock
  write_fwknopd_wrapper
  write_manual_helpers
  start_test_listeners
  create_client_namespace
  initialize_firewall
  verify_firewall
  verify_any_requires_explicit_authorization
  start_fwknopd
  configure_telegram_for_running_daemon
  auto_knock_if_requested
  print_status
  if [ "$EXIT_AFTER_READY" = "1" ]; then
    return
  fi
  if [ "$SHELL_AFTER_READY" = "1" ]; then
    exec bash -l
  fi
  sleep infinity
}

main "$@"
