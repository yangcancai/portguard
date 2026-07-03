#!/usr/bin/env bash
set -Eeuo pipefail

DIST_DIR=""
BASE_URL=""

usage() {
  cat <<'USAGE'
Generate release manifests for PortGuard Server packages.

Usage:
  scripts/generate-release-manifest.sh --dist DIR [--base-url URL]

Outputs:
  manifest.json
  manifest.tsv
  checksums.txt
USAGE
}

die() {
  printf '[portguard-manifest] ERROR: %s\n' "$*" >&2
  exit 1
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --dist)
        DIST_DIR="${2:-}"
        shift 2
        ;;
      --base-url)
        BASE_URL="${2:-}"
        shift 2
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

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "sha256sum or shasum is required"
  fi
}

distro_os_version() {
  local distro="$1"
  case "$distro" in
    debian*)
      printf 'debian\t%s' "${distro#debian}"
      ;;
    ubuntu*)
      local raw="${distro#ubuntu}"
      if [ "${#raw}" = "4" ]; then
        printf 'ubuntu\t%s.%s' "${raw%??}" "${raw#??}"
      else
        printf 'ubuntu\t%s' "$raw"
      fi
      ;;
    rocky*)
      printf 'rocky\t%s' "${distro#rocky}"
      ;;
    centos*)
      printf 'centos\t%s' "${distro#centos}"
      ;;
    *)
      printf '%s\t' "$distro"
      ;;
  esac
}

parse_package() {
  local file="$1"
  local base rest pkg_version distro arch format os_version os version

  base="$(basename "$file")"
  case "$base" in
    portguard-server_*.deb)
      rest="${base#portguard-server_}"
      rest="${rest%.deb}"
      pkg_version="${rest%%_*}"
      rest="${rest#*_}"
      distro="${rest%%_*}"
      arch="${rest#*_}"
      format="deb"
      ;;
    portguard-server-*.rpm)
      rest="${base#portguard-server-}"
      rest="${rest%.rpm}"
      pkg_version="${rest%%-*}"
      rest="${rest#*-}"
      rest="${rest#*.}"
      distro="${rest%%.*}"
      arch="${rest#*.}"
      format="rpm"
      ;;
    *)
      return 1
      ;;
  esac

  os_version="$(distro_os_version "$distro")"
  os="${os_version%%	*}"
  version="${os_version#*	}"
  printf '%s\t%s\t%s\t%s\t%s\t%s' "$os" "$version" "$arch" "$format" "$base" "$pkg_version"
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

main() {
  parse_args "$@"
  [ -n "$DIST_DIR" ] || die "--dist is required"
  [ -d "$DIST_DIR" ] || die "dist directory not found: $DIST_DIR"
  BASE_URL="${BASE_URL%/}"

  local checksums="${DIST_DIR}/checksums.txt"
  local tsv="${DIST_DIR}/manifest.tsv"
  local json="${DIST_DIR}/manifest.json"
  local tmp_packages
  tmp_packages="$(mktemp)"

  find "$DIST_DIR" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.rpm' \) | sort > "$tmp_packages"
  [ -s "$tmp_packages" ] || die "no .deb or .rpm packages found in $DIST_DIR"

  : > "$checksums"
  : > "$tsv"
  printf '# os\tversion\tarch\tformat\tfile\tsha256\turl\n' > "$tsv"

  printf '{\n' > "$json"
  printf '  "schema": 1,\n' >> "$json"
  printf '  "generated_at": "%s",\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$json"
  printf '  "packages": [\n' >> "$json"

  local first=1 package meta os version arch format file pkg_version sha url
  while IFS= read -r package; do
    file="$(basename "$package")"
    sha="$(sha256_file "$package")"
    printf '%s  %s\n' "$sha" "$file" >> "$checksums"

    meta="$(parse_package "$package")" || continue
    os="$(printf '%s' "$meta" | awk -F '\t' '{print $1}')"
    version="$(printf '%s' "$meta" | awk -F '\t' '{print $2}')"
    arch="$(printf '%s' "$meta" | awk -F '\t' '{print $3}')"
    format="$(printf '%s' "$meta" | awk -F '\t' '{print $4}')"
    pkg_version="$(printf '%s' "$meta" | awk -F '\t' '{print $6}')"

    url=""
    if [ -n "$BASE_URL" ]; then
      url="${BASE_URL}/${file}"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$os" "$version" "$arch" "$format" "$file" "$sha" "$url" >> "$tsv"

    if [ "$first" = "0" ]; then
      printf ',\n' >> "$json"
    fi
    first=0
    printf '    {"os":"%s","version":"%s","arch":"%s","format":"%s","file":"%s","package_version":"%s","sha256":"%s","url":"%s"}' \
      "$(json_escape "$os")" \
      "$(json_escape "$version")" \
      "$(json_escape "$arch")" \
      "$(json_escape "$format")" \
      "$(json_escape "$file")" \
      "$(json_escape "$pkg_version")" \
      "$(json_escape "$sha")" \
      "$(json_escape "$url")" >> "$json"
  done < "$tmp_packages"

  printf '\n  ]\n}\n' >> "$json"
  rm -f "$tmp_packages"

  printf '[portguard-manifest] wrote %s\n' "$checksums"
  printf '[portguard-manifest] wrote %s\n' "$tsv"
  printf '[portguard-manifest] wrote %s\n' "$json"
}

main "$@"
