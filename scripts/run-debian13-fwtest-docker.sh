#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"

IMAGE="${PORTGUARD_FWTEST_IMAGE:-debian:13}"
PLATFORM="${PORTGUARD_DOCKER_PLATFORM:-linux/amd64}"
CONTAINER_NAME="${PORTGUARD_FWTEST_NAME:-portguard-debian13-fwtest}"
INSTALL_MODE="${PORTGUARD_FWTEST_INSTALL_MODE:-local}"
TEST_PORT="${PORTGUARD_FWTEST_PORT:-7700}"
HOST_TEST_PORT="${PORTGUARD_FWTEST_HOST_PORT:-17700}"
HOST_SSH_PORT="${PORTGUARD_FWTEST_HOST_SSH_PORT:-22222}"
KNOCK_PORT="${PORTGUARD_FWTEST_KNOCK_PORT:-62201}"
HOST_KNOCK_PORT="${PORTGUARD_FWTEST_HOST_KNOCK_PORT:-62201}"
DIST_DIR="${PORTGUARD_FWTEST_DIST_DIR:-}"
PACKAGE_FILE="${PORTGUARD_FWTEST_PACKAGE:-}"
EXIT_AFTER_READY="${PORTGUARD_FWTEST_EXIT_AFTER_READY:-0}"
SHELL_AFTER_READY="${PORTGUARD_FWTEST_SHELL_AFTER_READY:-1}"
OPEN_TEST_PORT_ON_INIT="${PORTGUARD_FWTEST_OPEN_TEST_PORT_ON_INIT:-0}"
AUTO_KNOCK="${PORTGUARD_FWTEST_AUTO_KNOCK:-0}"
TELEGRAM_MOCK="${PORTGUARD_FWTEST_TELEGRAM_MOCK:-0}"
PULL_IMAGE=1
REPLACE_CONTAINER=1

ENTRYPOINT="${REPO_ROOT}/docker/fwtest/debian13-entrypoint.sh"

usage() {
  cat <<'USAGE'
Run a Debian 13 Docker firewall test container for PortGuard Server.

Usage:
  scripts/run-debian13-fwtest-docker.sh [options]

Options:
  --local-package       Build and install a local Debian 13 package. Default.
  --official            Install with https://portguard.net/install.sh instead.
  --package FILE        Install an existing local .deb package instead of building.
  --dist DIR            Output directory for a locally built package.
  --name NAME           Docker container name. Default: portguard-debian13-fwtest.
  --test-port PORT      Container TCP service port. Default: 7700.
  --host-test-port PORT Host port mapped to the test service. Default: 17700.
  --host-ssh-port PORT  Host port mapped to container tcp/22. Default: 22222.
  --knock-port PORT     Container UDP SPA listener port. Default: 62201.
  --host-knock-port PORT
                        Host UDP port mapped to the SPA listener. Default: 62201.
  --platform VALUE      Docker platform. Default: linux/amd64.
  --image IMAGE         Docker image. Default: debian:13.
  --no-pull            Do not docker pull the image first.
  --no-replace         Do not remove an existing test container with the same name.
  --exit-after-ready   Exit after setup and firewall verification instead of sleeping.
  --no-shell           Keep the container alive instead of entering bash.
  --open-test-port-on-init
                       Open the test TCP port during fw-console initialization.
  --auto-knock         Send one SPA knock automatically after fwknopd starts.
  -h, --help           Show this help.

The default local-package mode tests the current source tree, so it can validate
firewall changes before they are released. The container resets only its own
Docker network namespace; it does not change the host firewall.

After setup, the script enters a shell in the container. Use pg-fwtest-knock to
send a manual SPA packet and temporarily open the test TCP port.
USAGE
}

log() {
  printf '[run-debian13-fwtest] %s\n' "$*"
}

die() {
  printf '[run-debian13-fwtest] ERROR: %s\n' "$*" >&2
  exit 1
}

abs_path() {
  local p="$1"
  if [ -d "$p" ]; then
    (cd "$p" && pwd -P)
  else
    (cd "$(dirname "$p")" && printf '%s/%s\n' "$(pwd -P)" "$(basename "$p")")
  fi
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --local-package)
        INSTALL_MODE="local"
        shift
        ;;
      --official)
        INSTALL_MODE="official"
        shift
        ;;
      --package)
        INSTALL_MODE="local"
        PACKAGE_FILE="${2:-}"
        shift 2
        ;;
      --dist)
        DIST_DIR="${2:-}"
        shift 2
        ;;
      --name)
        CONTAINER_NAME="${2:-}"
        shift 2
        ;;
      --test-port)
        TEST_PORT="${2:-}"
        shift 2
        ;;
      --host-test-port)
        HOST_TEST_PORT="${2:-}"
        shift 2
        ;;
      --host-ssh-port)
        HOST_SSH_PORT="${2:-}"
        shift 2
        ;;
      --knock-port)
        KNOCK_PORT="${2:-}"
        shift 2
        ;;
      --host-knock-port)
        HOST_KNOCK_PORT="${2:-}"
        shift 2
        ;;
      --platform)
        PLATFORM="${2:-}"
        shift 2
        ;;
      --image)
        IMAGE="${2:-}"
        shift 2
        ;;
      --no-pull)
        PULL_IMAGE=0
        shift
        ;;
      --no-replace)
        REPLACE_CONTAINER=0
        shift
        ;;
      --exit-after-ready)
        EXIT_AFTER_READY=1
        shift
        ;;
      --no-shell)
        SHELL_AFTER_READY=0
        shift
        ;;
      --open-test-port-on-init)
        OPEN_TEST_PORT_ON_INIT=1
        shift
        ;;
      --auto-knock)
        AUTO_KNOCK=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown option: $1"
        ;;
    esac
  done
}

validate_port() {
  local name="$1" value="$2"

  case "$value" in
    ''|*[!0-9]*) die "${name} must be a numeric port: ${value}" ;;
  esac
  [ "$value" -ge 1 ] && [ "$value" -le 65535 ] \
    || die "${name} must be 1-65535: ${value}"
}

validate_inputs() {
  command -v docker >/dev/null 2>&1 || die "docker command not found"
  [ -f "$ENTRYPOINT" ] || die "entrypoint not found: $ENTRYPOINT"

  case "$INSTALL_MODE" in
    local|official) ;;
    *) die "unknown install mode: $INSTALL_MODE" ;;
  esac

  validate_port "--test-port" "$TEST_PORT"
  validate_port "--host-test-port" "$HOST_TEST_PORT"
  validate_port "--host-ssh-port" "$HOST_SSH_PORT"
  validate_port "--knock-port" "$KNOCK_PORT"
  validate_port "--host-knock-port" "$HOST_KNOCK_PORT"

  if [ -n "$PACKAGE_FILE" ]; then
    PACKAGE_FILE="$(abs_path "$PACKAGE_FILE")"
    [ -f "$PACKAGE_FILE" ] || die "package not found: $PACKAGE_FILE"
  fi
}

pull_image() {
  local args=()

  if [ "$PULL_IMAGE" != "1" ]; then
    return
  fi

  if [ -n "$PLATFORM" ]; then
    args=(--platform "$PLATFORM")
  fi

  log "pulling ${IMAGE}"
  docker pull "${args[@]}" "$IMAGE"
}

build_local_package() {
  local args=() release

  if [ "$INSTALL_MODE" != "local" ] || [ -n "$PACKAGE_FILE" ]; then
    return
  fi

  if [ -z "$DIST_DIR" ]; then
    DIST_DIR="/tmp/portguard-fwtest-debian13-$(date +%Y%m%d%H%M%S)"
  else
    DIST_DIR="$(abs_path "$DIST_DIR")"
  fi
  mkdir -p "$DIST_DIR"

  if [ -n "$PLATFORM" ]; then
    args=(--platform "$PLATFORM")
  fi

  release="fwtest$(date +%Y%m%d%H%M%S)"
  log "building local Debian 13 package into ${DIST_DIR}"
  docker run --rm \
    "${args[@]}" \
    -e PORTGUARD_PACKAGE_RELEASE="$release" \
    -v "${REPO_ROOT}:/src:ro" \
    -v "${DIST_DIR}:/dist" \
    "$IMAGE" \
    bash /src/scripts/build-package.sh \
      --source /src \
      --output /dist \
      --distro debian13

  PACKAGE_FILE="$(find "$DIST_DIR" -maxdepth 1 -type f -name '*.deb' | sort | tail -n 1)"
  [ -n "$PACKAGE_FILE" ] || die "local package build did not produce a .deb"
  log "built package: ${PACKAGE_FILE}"
}

remove_existing_container() {
  if [ "$REPLACE_CONTAINER" != "1" ]; then
    return
  fi

  if docker ps -a --format '{{.Names}}' | grep -Fxq "$CONTAINER_NAME"; then
    log "removing existing test container: ${CONTAINER_NAME}"
    docker rm -f "$CONTAINER_NAME" >/dev/null
  fi
}

run_container() {
  local args=() tty_args=() package_mount=() package_env=()

  if [ -n "$PLATFORM" ]; then
    args=(--platform "$PLATFORM")
  fi

  if [ -t 0 ] && [ -t 1 ]; then
    tty_args=(-it)
  else
    tty_args=(-i)
  fi

  if [ "$INSTALL_MODE" = "local" ]; then
    package_mount=(-v "${PACKAGE_FILE}:/pkg/portguard-server.deb:ro")
    package_env=(-e PORTGUARD_FWTEST_PACKAGE=/pkg/portguard-server.deb)
  fi

  log "starting ${CONTAINER_NAME}"
  docker run --rm \
    "${tty_args[@]}" \
    --name "$CONTAINER_NAME" \
    --privileged \
    "${args[@]}" \
    -p "${HOST_SSH_PORT}:22" \
    -p "${HOST_TEST_PORT}:${TEST_PORT}" \
    -p "${HOST_KNOCK_PORT}:${KNOCK_PORT}/udp" \
    -e PORTGUARD_FWTEST_INSTALL_MODE="$INSTALL_MODE" \
    -e PORTGUARD_FWTEST_PORT="$TEST_PORT" \
    -e PORTGUARD_FWTEST_HOST_PORT="$HOST_TEST_PORT" \
    -e PORTGUARD_FWTEST_KNOCK_PORT="$KNOCK_PORT" \
    -e PORTGUARD_FWTEST_HOST_KNOCK_PORT="$HOST_KNOCK_PORT" \
    -e PORTGUARD_FWTEST_HOST_SSH_PORT="$HOST_SSH_PORT" \
    -e PORTGUARD_FWTEST_EXIT_AFTER_READY="$EXIT_AFTER_READY" \
    -e PORTGUARD_FWTEST_SHELL_AFTER_READY="$SHELL_AFTER_READY" \
    -e PORTGUARD_FWTEST_OPEN_TEST_PORT_ON_INIT="$OPEN_TEST_PORT_ON_INIT" \
    -e PORTGUARD_FWTEST_AUTO_KNOCK="$AUTO_KNOCK" \
    -e PORTGUARD_FWTEST_TELEGRAM_MOCK="$TELEGRAM_MOCK" \
    "${package_env[@]}" \
    -v "${ENTRYPOINT}:/fwtest/debian13-entrypoint.sh:ro" \
    "${package_mount[@]}" \
    "$IMAGE" \
    bash /fwtest/debian13-entrypoint.sh
}

main() {
  parse_args "$@"
  validate_inputs
  pull_image
  build_local_package
  remove_existing_container
  run_container
}

main "$@"
