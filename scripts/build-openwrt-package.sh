#!/usr/bin/env bash
set -Eeuo pipefail

PACKAGE_NAME="portguard-server"
SOURCE_DIR=""
OUTPUT_DIR=""
PACKAGE_VERSION=""
PACKAGE_RELEASE="${PORTGUARD_PACKAGE_RELEASE:-pg1}"
SDK_ARCH="${OPENWRT_SDK_ARCH:-x86-64-24.10.7}"
SDK_IMAGE="${OPENWRT_SDK_IMAGE:-}"
SDK_PLATFORM="${OPENWRT_SDK_PLATFORM:-linux/amd64}"
DISTRO=""
INSIDE_SDK=0

usage() {
  cat <<'USAGE'
Build a PortGuard Server OpenWrt package with the official OpenWrt SDK image.

Usage:
  scripts/build-openwrt-package.sh [options]

Options:
  --source DIR          Source tree. Default: repository root.
  --output DIR          Output directory. Default: SOURCE/dist.
  --version VERSION     Package version. Default: parsed from configure.ac.
  --release RELEASE     Package release suffix. Default: PORTGUARD_PACKAGE_RELEASE or pg1.
  --sdk-arch ARCH       OpenWrt SDK tag arch, for example x86-64-24.10.7.
  --sdk-image IMAGE     Full SDK image. Default: openwrt/sdk:SDK_ARCH.
  --distro ID           Output distro label, for example openwrt2410-x86-64.
  --inside-sdk          Run inside an OpenWrt SDK container.
  -h, --help            Show this help.
USAGE
}

log() {
  printf '[portguard-openwrt] %s\n' "$*"
}

die() {
  printf '[portguard-openwrt] ERROR: %s\n' "$*" >&2
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

script_dir() {
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P
}

repo_root() {
  cd "$(script_dir)/.." && pwd -P
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --source)
        SOURCE_DIR="${2:-}"
        shift 2
        ;;
      --output)
        OUTPUT_DIR="${2:-}"
        shift 2
        ;;
      --version)
        PACKAGE_VERSION="${2:-}"
        shift 2
        ;;
      --release)
        PACKAGE_RELEASE="${2:-}"
        shift 2
        ;;
      --sdk-arch)
        SDK_ARCH="${2:-}"
        shift 2
        ;;
      --sdk-image)
        SDK_IMAGE="${2:-}"
        shift 2
        ;;
      --distro)
        DISTRO="${2:-}"
        shift 2
        ;;
      --inside-sdk)
        INSIDE_SDK=1
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

parse_version() {
  sed -n 's/^m4_define(my_version,[[:space:]]*\[\([^]]*\)\]).*/\1/p' "${SOURCE_DIR}/configure.ac" | head -n 1
}

normalize_release() {
  local release="$1"
  case "$release" in
    "v${PACKAGE_VERSION}") release="pg1" ;;
    "v${PACKAGE_VERSION}-"*) release="${release#v${PACKAGE_VERSION}-}" ;;
    "v${PACKAGE_VERSION}+"*) release="${release#v${PACKAGE_VERSION}+}" ;;
    "${PACKAGE_VERSION}-"*) release="${release#${PACKAGE_VERSION}-}" ;;
    "${PACKAGE_VERSION}+"*) release="${release#${PACKAGE_VERSION}+}" ;;
  esac
  release="$(printf '%s' "$release" | tr -c 'A-Za-z0-9+._' '_')"
  release="${release%_}"
  [ -n "$release" ] || release="pg1"
  printf '%s' "$release"
}

default_distro() {
  local sdk="$1"
  local target="$sdk"
  local version=""

  case "$sdk" in
    *-[0-9][0-9].[0-9][0-9]*)
      version="${sdk##*-}"
      target="${sdk%-${version}}"
      version="${version%.*}"
      version="$(printf '%s' "$version" | tr -d '.')"
      printf 'openwrt%s-%s' "$version" "$target"
      ;;
    *)
      printf 'openwrt-%s' "$target"
      ;;
  esac
}

run_container() {
  local tmp_dist

  [ -n "$SDK_IMAGE" ] || SDK_IMAGE="openwrt/sdk:${SDK_ARCH}"
  log "using SDK image ${SDK_IMAGE}"

  tmp_dist="$(mktemp -d "${TMPDIR:-/tmp}/portguard-openwrt-dist.XXXXXX")"
  chmod 0777 "$tmp_dist"

  (
    trap 'rm -rf "$tmp_dist"' EXIT

    docker pull --platform "$SDK_PLATFORM" "$SDK_IMAGE"
    docker run --rm \
      --platform "$SDK_PLATFORM" \
      -e PORTGUARD_PACKAGE_RELEASE="$PACKAGE_RELEASE" \
      -v "${SOURCE_DIR}:/src:ro" \
      -v "${tmp_dist}:/dist" \
      "$SDK_IMAGE" \
      bash /src/scripts/build-openwrt-package.sh \
        --inside-sdk \
        --source /src \
        --output /dist \
        --version "$PACKAGE_VERSION" \
        --release "$PACKAGE_RELEASE" \
        --sdk-arch "$SDK_ARCH" \
        --distro "$DISTRO"

    copy_host_packages "$tmp_dist"
  )
}

copy_host_packages() {
  local dist_dir="$1"
  local package copied=0

  while IFS= read -r package; do
    [ -n "$package" ] || continue
    cp "$package" "${OUTPUT_DIR}/$(basename "$package")"
    log "wrote ${OUTPUT_DIR}/$(basename "$package")"
    copied=1
  done < <(find "$dist_dir" -maxdepth 1 -type f -name '*.ipk' | sort)

  [ "$copied" = "1" ] || die "OpenWrt SDK did not export any .ipk packages"
}

copy_openwrt_package() {
  local package arch out_file copied=0

  while IFS= read -r package; do
    [ -n "$package" ] || continue
    arch="$(
      tar -xOzf "$package" ./control.tar.gz 2>/dev/null \
        | tar -xzO ./control 2>/dev/null \
        | awk -F': *' '$1 == "Architecture" { print $2; exit }'
    )"
    if [ -z "$arch" ]; then
      local base rest
      base="$(basename "$package")"
      rest="${base#${PACKAGE_NAME}_${PACKAGE_VERSION}-}"
      rest="${rest%.ipk}"
      arch="${rest#*_}"
    fi
    [ -n "$arch" ] || die "could not determine OpenWrt package architecture for ${package}"
    out_file="${PACKAGE_NAME}_${PACKAGE_VERSION}-${PACKAGE_RELEASE}_${DISTRO}_${arch}.ipk"
    cp "$package" "${OUTPUT_DIR}/${out_file}"
    log "wrote ${OUTPUT_DIR}/${out_file}"
    copied=1
  done < <(find bin/packages -type f -name "${PACKAGE_NAME}_*.ipk" | sort)

  [ "$copied" = "1" ] || die "OpenWrt SDK did not produce ${PACKAGE_NAME}_*.ipk"
}

build_inside_sdk() {
  [ -f rules.mk ] || die "this command must run from an OpenWrt SDK root"
  [ -d "${SOURCE_DIR}/extras/openwrt/package/${PACKAGE_NAME}" ] || die "missing OpenWrt package definition"

  rm -rf "package/${PACKAGE_NAME}"
  cp -a "${SOURCE_DIR}/extras/openwrt/package/${PACKAGE_NAME}" "package/${PACKAGE_NAME}"

  make defconfig
  make "package/${PACKAGE_NAME}/clean" V=s || true
  log "building ${PACKAGE_NAME} ${PACKAGE_VERSION}-${PACKAGE_RELEASE} for ${DISTRO}"
  make "package/${PACKAGE_NAME}/compile" V="${V:-s}" \
    PORTGUARD_SOURCE_DIR="$SOURCE_DIR" \
    PORTGUARD_PACKAGE_VERSION="$PACKAGE_VERSION" \
    PORTGUARD_PACKAGE_RELEASE="$PACKAGE_RELEASE"

  copy_openwrt_package
}

main() {
  parse_args "$@"
  [ -n "$SOURCE_DIR" ] || SOURCE_DIR="$(repo_root)"
  SOURCE_DIR="$(abs_path "$SOURCE_DIR")"
  [ -d "${SOURCE_DIR}/server" ] || die "invalid source tree: ${SOURCE_DIR}"

  [ -n "$OUTPUT_DIR" ] || OUTPUT_DIR="${SOURCE_DIR}/dist"
  mkdir -p "$OUTPUT_DIR"
  OUTPUT_DIR="$(abs_path "$OUTPUT_DIR")"

  [ -n "$PACKAGE_VERSION" ] || PACKAGE_VERSION="$(parse_version)"
  [ -n "$PACKAGE_VERSION" ] || die "could not parse version from configure.ac"
  PACKAGE_RELEASE="$(normalize_release "$PACKAGE_RELEASE")"
  [ -n "$SDK_ARCH" ] || die "--sdk-arch is required"
  [ -n "$DISTRO" ] || DISTRO="$(default_distro "$SDK_ARCH")"

  if [ "$INSIDE_SDK" = "1" ]; then
    build_inside_sdk
  else
    run_container
  fi
}

main "$@"
