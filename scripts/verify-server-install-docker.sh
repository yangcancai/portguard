#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"

SERVER_SRC="${PORTGUARD_SERVER_SRC:-${REPO_ROOT}}"
INSTALLER="${PORTGUARD_INSTALLER:-}"
VERIFY_SCRIPT="${REPO_ROOT}/docker/install-verify/verify-installed.sh"
PLATFORM="${PORTGUARD_DOCKER_PLATFORM:-}"
INSTALL_MODE="${PORTGUARD_INSTALL_MODE:-package}"
PULL_IMAGES=1
IMAGES=()

usage() {
  cat <<'USAGE'
Verify PortGuard Server installation in Docker images.

Usage:
  scripts/verify-server-install-docker.sh [options]

Options:
  --image IMAGE        Add one Docker image to verify. May be repeated.
  --all               Verify the extended image matrix.
  --installer FILE    Installer script to run in the container.
  --source-install    Verify installer source-build mode instead of release packages.
  --server-src DIR    Local portguard source tree for --source-install. Default: repo root.
  --platform VALUE    Docker platform, for example linux/amd64.
  --no-pull           Do not docker pull images before running.
  -h, --help          Show this help.

Default images:
  debian:12 ubuntu:24.04 rockylinux:9 quay.io/centos/centos:stream9

The default mode verifies prebuilt package installation through install.sh and
the GitHub release manifest. Use --source-install to exercise local source builds.
USAGE
}

log() {
  printf '[verify-server-install-docker] %s\n' "$*"
}

die() {
  printf '[verify-server-install-docker] ERROR: %s\n' "$*" >&2
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

add_default_images() {
  if [ "${#IMAGES[@]}" -eq 0 ]; then
    IMAGES=(debian:12 ubuntu:24.04 rockylinux:9 quay.io/centos/centos:stream9)
  fi
}

add_all_images() {
  IMAGES=(
    debian:12
    debian:13
    ubuntu:22.04
    ubuntu:24.04
    rockylinux:8
    rockylinux:9
    quay.io/centos/centos:7
    quay.io/centos/centos:stream8
    quay.io/centos/centos:stream9
  )
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --image)
        IMAGES+=("${2:-}")
        shift 2
        ;;
      --all)
        add_all_images
        shift
        ;;
      --installer)
        INSTALLER="${2:-}"
        shift 2
        ;;
      --source-install)
        INSTALL_MODE="source"
        shift
        ;;
      --server-src)
        SERVER_SRC="${2:-}"
        shift 2
        ;;
      --platform)
        PLATFORM="${2:-}"
        shift 2
        ;;
      --no-pull)
        PULL_IMAGES=0
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

resolve_installer() {
  local candidate

  if [ -n "$INSTALLER" ]; then
    INSTALLER="$(abs_path "$INSTALLER")"
    return
  fi

  for candidate in \
    "${REPO_ROOT}/install.sh" \
    "${REPO_ROOT}/priv/static/install.sh" \
    "${REPO_ROOT}/../../elixir/fwknop_site/priv/static/install.sh"
  do
    if [ -f "$candidate" ]; then
      INSTALLER="$(abs_path "$candidate")"
      return
    fi
  done

  die "installer not found; pass --installer /path/to/install.sh"
}

validate_inputs() {
  command -v docker >/dev/null 2>&1 || die "docker command not found"
  [ -f "$INSTALLER" ] || die "installer not found: $INSTALLER"
  [ -f "$VERIFY_SCRIPT" ] || die "verify script not found: $VERIFY_SCRIPT"

  case "$INSTALL_MODE" in
    package) ;;
    source)
      SERVER_SRC="$(abs_path "$SERVER_SRC")"
      [ -d "${SERVER_SRC}/server" ] || die "server source is invalid: $SERVER_SRC"
      ;;
    *) die "unknown install mode: $INSTALL_MODE" ;;
  esac
}

image_to_name() {
  printf '%s' "$1" | tr '/:@' '---' | tr -cd 'A-Za-z0-9_.-'
}

run_image() {
  local image="$1"
  local name platform_args=() source_mount=() source_env=()
  name="portguard-install-verify-$(image_to_name "$image")-$$"

  if [ -n "$PLATFORM" ]; then
    platform_args=(--platform "$PLATFORM")
  fi

  if [ "$INSTALL_MODE" = "source" ]; then
    source_mount=(-v "${SERVER_SRC}:/src:ro")
    source_env=(-e PORTGUARD_SOURCE_DIR=/src)
  fi

  if [ "$PULL_IMAGES" = "1" ]; then
    log "pulling ${image}"
    docker pull "${platform_args[@]}" "$image"
  fi

  log "verifying ${image} (${INSTALL_MODE})"
  docker run \
    --rm \
    --name "$name" \
    "${platform_args[@]}" \
    -e PORTGUARD_INSTALLER=/installer/install.sh \
    -e PORTGUARD_INSTALL_MODE="$INSTALL_MODE" \
    -e PORTGUARD_PACKAGE_MANIFEST_URL="${PORTGUARD_PACKAGE_MANIFEST_URL:-}" \
    -e PORTGUARD_ENABLE_EPEL_FOR_QR="${PORTGUARD_ENABLE_EPEL_FOR_QR:-1}" \
    "${source_env[@]}" \
    -v "${INSTALLER}:/installer/install.sh:ro" \
    -v "${VERIFY_SCRIPT}:/verify/verify-installed.sh:ro" \
    "${source_mount[@]}" \
    "$image" \
    bash /verify/verify-installed.sh
}

main() {
  parse_args "$@"
  add_default_images
  resolve_installer
  validate_inputs

  log "repo root: ${REPO_ROOT}"
  log "installer: ${INSTALLER}"
  log "install mode: ${INSTALL_MODE}"
  if [ "$INSTALL_MODE" = "source" ]; then
    log "server source: ${SERVER_SRC}"
  fi
  if [ -n "$PLATFORM" ]; then
    log "docker platform: ${PLATFORM}"
  fi

  local failures=0 passed=0 image
  for image in "${IMAGES[@]}"; do
    if run_image "$image"; then
      passed=$((passed + 1))
      log "PASS ${image}"
    else
      failures=$((failures + 1))
      log "FAIL ${image}"
    fi
  done

  log "summary: ${passed} passed, ${failures} failed"
  [ "$failures" -eq 0 ]
}

main "$@"
