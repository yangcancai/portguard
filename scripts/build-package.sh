#!/usr/bin/env bash
set -Eeuo pipefail

PACKAGE_NAME="portguard-server"
PACKAGE_RELEASE="${PORTGUARD_PACKAGE_RELEASE:-pg1}"
SOURCE_DIR=""
OUTPUT_DIR=""
PACKAGE_VERSION=""
DISTRO=""
SKIP_DEPS=0

usage() {
  cat <<'USAGE'
Build a PortGuard Server binary package from the current source tree.

Usage:
  scripts/build-package.sh [options]

Options:
  --source DIR          Source tree. Default: repository root.
  --output DIR          Output directory. Default: SOURCE/dist.
  --version VERSION     Package version. Default: parsed from configure.ac.
  --release RELEASE     Package release suffix. Default: pg1.
  --distro ID           Distro label for filename, for example debian12.
  --skip-deps           Do not install build dependencies.
  -h, --help            Show this help.

The script intentionally builds from a copied source tree so CI can mount the
repository read-only.
USAGE
}

log() {
  printf '[portguard-package] %s\n' "$*"
}

die() {
  printf '[portguard-package] ERROR: %s\n' "$*" >&2
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
      --distro)
        DISTRO="${2:-}"
        shift 2
        ;;
      --skip-deps)
        SKIP_DEPS=1
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

load_os_release() {
  [ -r /etc/os-release ] || die "/etc/os-release is missing"
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_VERSION_ID="${VERSION_ID:-}"
  OS_LIKE="${ID_LIKE:-}"
}

os_family() {
  local ids="${OS_ID:-} ${OS_LIKE:-}"
  case "$ids" in
    *debian*|*ubuntu*) printf 'debian\n' ;;
    *rhel*|*fedora*|*centos*|*rocky*) printf 'rhel\n' ;;
    *) die "unsupported build OS: ${OS_ID:-unknown}" ;;
  esac
}

default_distro() {
  local version
  version="$(printf '%s' "${OS_VERSION_ID:-}" | tr -d '.')"
  printf '%s%s' "${OS_ID:-linux}" "$version"
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

deb_arch() {
  if command -v dpkg >/dev/null 2>&1; then
    dpkg --print-architecture
    return
  fi

  case "$(uname -m)" in
    x86_64) printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *) uname -m ;;
  esac
}

rpm_arch() {
  if command -v rpm >/dev/null 2>&1; then
    rpm --eval '%{_arch}'
    return
  fi

  uname -m
}

install_build_deps_debian() {
  export DEBIAN_FRONTEND=noninteractive
  retry apt-get update -y
  retry apt-get install -y --no-install-recommends \
    bash ca-certificates tar gzip coreutils findutils sed grep gawk \
    make gcc libc6-dev autoconf automake libtool pkg-config \
    texinfo iptables dpkg-dev
}

install_build_deps_rhel() {
  local pm="yum"
  if command -v dnf >/dev/null 2>&1; then
    pm="dnf"
  fi

  retry "$pm" install -y \
    bash ca-certificates tar gzip coreutils findutils sed grep gawk \
    make gcc autoconf automake libtool pkgconfig \
    texinfo iptables rpm-build
}

install_build_deps() {
  if [ "$SKIP_DEPS" = "1" ]; then
    log "dependency installation skipped"
    return
  fi

  case "$(os_family)" in
    debian) install_build_deps_debian ;;
    rhel) install_build_deps_rhel ;;
  esac
}

prepare_source_tree() {
  if [ -f doc/Makefile.am ] && grep -q '^AUTOMAKE_OPTIONS[[:space:]]*=[[:space:]]*info-in-builddir' doc/Makefile.am; then
    log "patching doc/Makefile.am for older automake compatibility"
    sed -i.bak 's/^AUTOMAKE_OPTIONS[[:space:]]*=[[:space:]]*info-in-builddir/#&/' doc/Makefile.am
  fi
}

copy_source_tree() {
  local dst="$1"
  mkdir -p "$dst"
  tar \
    --exclude='.git' \
    --exclude='autom4te.cache' \
    --exclude='*.o' \
    --exclude='*.lo' \
    --exclude='.libs' \
    --exclude='dist' \
    -C "$SOURCE_DIR" -cf - . | tar -C "$dst" -xf -
}

build_install_root() {
  local build_src="$1"
  local install_root="$2"
  local family="$3"
  local arch="$4"
  local iptables_bin libdir jobs unit_dir

  iptables_bin="$(command -v iptables || true)"
  [ -n "$iptables_bin" ] || iptables_bin="/usr/sbin/iptables"

  libdir="/usr/lib"
  if [ "$family" = "rhel" ]; then
    case "$arch" in
      x86_64|aarch64|ppc64le|s390x) libdir="/usr/lib64" ;;
    esac
  fi

  log "building fwknopd ${PACKAGE_VERSION} for ${DISTRO} (${arch})"
  (
    cd "$build_src"
    prepare_source_tree
    bash ./autogen.sh
    ./configure \
      --prefix=/usr \
      --sysconfdir=/etc \
      --localstatedir=/run \
      --libdir="$libdir" \
      --disable-client \
      --enable-udp-server \
      --without-gpgme \
      --with-iptables="$iptables_bin" \
      --with-firewalld=no
    jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '2')"
    make -j "$jobs"
    make install DESTDIR="$install_root"

    unit_dir="/lib/systemd/system"
    if [ "$family" = "rhel" ]; then
      unit_dir="/usr/lib/systemd/system"
    fi
    install -D -m 0644 extras/systemd/fwknopd.service "${install_root}${unit_dir}/fwknopd.service"
  )

  prune_install_root "$install_root"
}

prune_install_root() {
  local install_root="$1"

  rm -rf "${install_root}/usr/include" "${install_root}/usr/share/info"
  find "${install_root}/usr" -type f \( -name '*.a' -o -name '*.la' \) -delete 2>/dev/null || true
  find "${install_root}/usr" -type f \( -name '*.o' -o -name '*.lo' \) -delete 2>/dev/null || true

  if [ -d "${install_root}/etc/fwknop" ]; then
    chmod 700 "${install_root}/etc/fwknop"
    chmod 600 "${install_root}/etc/fwknop/"*.conf 2>/dev/null || true
  fi
}

write_deb_maintainer_scripts() {
  local debian_dir="$1"

  cat > "${debian_dir}/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v ldconfig >/dev/null 2>&1; then
    ldconfig
fi
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF

  cat > "${debian_dir}/postrm" <<'EOF'
#!/bin/sh
set -e
if command -v ldconfig >/dev/null 2>&1; then
    ldconfig
fi
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF

  chmod 0755 "${debian_dir}/postinst" "${debian_dir}/postrm"
}

package_deb() {
  local install_root="$1"
  local arch="$2"
  local debian_dir deb_version package_file

  deb_version="${PACKAGE_VERSION}+${PACKAGE_RELEASE}"
  package_file="${PACKAGE_NAME}_${deb_version}_${DISTRO}_${arch}.deb"
  debian_dir="${install_root}/DEBIAN"
  mkdir -p "$debian_dir"

  cat > "${debian_dir}/control" <<EOF
Package: ${PACKAGE_NAME}
Version: ${deb_version}
Section: net
Priority: optional
Architecture: ${arch}
Maintainer: PortGuard Maintainers <support@portguard.net>
Depends: libc6 (>= 2.17), iptables
Recommends: qrencode
Conflicts: fwknop-server, libfko, libfko3
Replaces: fwknop-server, libfko, libfko3
Description: PortGuard Single Packet Authorization server
 PortGuard Server packages fwknopd for easy SPA deployment. Runtime
 configuration and client import payloads are generated by install.sh.
EOF

  cat > "${debian_dir}/conffiles" <<'EOF'
/etc/fwknop/fwknopd.conf
/etc/fwknop/access.conf
EOF

  write_deb_maintainer_scripts "$debian_dir"
  dpkg-deb --build --root-owner-group "$install_root" "${OUTPUT_DIR}/${package_file}"
  log "wrote ${OUTPUT_DIR}/${package_file}"
}

write_rpm_file_list() {
  local install_root="$1"
  local file_list="$2"

  : > "$file_list"
  while IFS= read -r path; do
    local rel="/${path#${install_root}/}"
    case "$rel" in
      /etc/fwknop/fwknopd.conf|/etc/fwknop/access.conf) ;;
      *) printf '%s\n' "$rel" >> "$file_list" ;;
    esac
  done < <(find "$install_root" \( -type f -o -type l \) | sort)
}

package_rpm() {
  local install_root="$1"
  local arch="$2"
  local rpm_top spec_file file_list built_rpm out_file

  rpm_top="$(mktemp -d /tmp/portguard-rpmbuild.XXXXXX)"
  mkdir -p "${rpm_top}/"{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
  spec_file="${rpm_top}/SPECS/${PACKAGE_NAME}.spec"
  file_list="${rpm_top}/files.list"
  write_rpm_file_list "$install_root" "$file_list"

  cat > "$spec_file" <<EOF
Name: ${PACKAGE_NAME}
Version: ${PACKAGE_VERSION}
Release: ${PACKAGE_RELEASE}.${DISTRO}%{?dist}
Summary: PortGuard Single Packet Authorization server
License: GPL-2.0-or-later
URL: https://portguard.net/
Requires: iptables
Conflicts: fwknop-server, libfko

%description
PortGuard Server packages fwknopd for easy SPA deployment. Runtime
configuration and client import payloads are generated by install.sh.

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a ${install_root}/. %{buildroot}/

%post
/sbin/ldconfig || true
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

%postun
/sbin/ldconfig || true
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

%files -f ${file_list}
%defattr(-,root,root,-)
%dir %attr(0700,root,root) /etc/fwknop
%config(noreplace) %attr(0600,root,root) /etc/fwknop/fwknopd.conf
%config(noreplace) %attr(0600,root,root) /etc/fwknop/access.conf
EOF

  rpmbuild \
    --define "_topdir ${rpm_top}" \
    --define "_build_id_links none" \
    --define "debug_package %{nil}" \
    -bb "$spec_file"

  built_rpm="$(find "${rpm_top}/RPMS" -type f -name '*.rpm' | sort | head -n 1)"
  [ -n "$built_rpm" ] || die "rpmbuild did not produce an rpm"
  out_file="${PACKAGE_NAME}-${PACKAGE_VERSION}-${PACKAGE_RELEASE}.${DISTRO}.${arch}.rpm"
  cp "$built_rpm" "${OUTPUT_DIR}/${out_file}"
  log "wrote ${OUTPUT_DIR}/${out_file}"
}

main() {
  parse_args "$@"
  [ -n "$SOURCE_DIR" ] || SOURCE_DIR="$(repo_root)"
  SOURCE_DIR="$(abs_path "$SOURCE_DIR")"
  [ -d "${SOURCE_DIR}/server" ] || die "invalid source tree: ${SOURCE_DIR}"

  [ -n "$OUTPUT_DIR" ] || OUTPUT_DIR="${SOURCE_DIR}/dist"
  mkdir -p "$OUTPUT_DIR"
  OUTPUT_DIR="$(abs_path "$OUTPUT_DIR")"

  load_os_release
  [ -n "$PACKAGE_VERSION" ] || PACKAGE_VERSION="$(parse_version)"
  [ -n "$PACKAGE_VERSION" ] || die "could not parse version from configure.ac"
  PACKAGE_RELEASE="$(normalize_release "$PACKAGE_RELEASE")"
  [ -n "$DISTRO" ] || DISTRO="$(default_distro)"

  install_build_deps

  local family arch build_root build_src install_root
  family="$(os_family)"
  if [ "$family" = "debian" ]; then
    arch="$(deb_arch)"
  else
    arch="$(rpm_arch)"
  fi

  build_root="$(mktemp -d /tmp/portguard-package.XXXXXX)"
  build_src="${build_root}/src"
  install_root="${build_root}/root"
  mkdir -p "$install_root"

  copy_source_tree "$build_src"
  build_install_root "$build_src" "$install_root" "$family" "$arch"

  if [ "$family" = "debian" ]; then
    package_deb "$install_root" "$arch"
  else
    package_rpm "$install_root" "$arch"
  fi
}

main "$@"
