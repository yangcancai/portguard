include $(TOPDIR)/rules.mk

PKG_NAME:=portguard-server
PKG_VERSION:=$(if $(PORTGUARD_PACKAGE_VERSION),$(PORTGUARD_PACKAGE_VERSION),2.6.11)
PKG_RELEASE:=$(if $(PORTGUARD_PACKAGE_RELEASE),$(PORTGUARD_PACKAGE_RELEASE),pg1)

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_FIXUP:=autoreconf
PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/portguard-server
  SECTION:=net
  CATEGORY:=Network
  TITLE:=PortGuard Single Packet Authorization server
  URL:=https://portguard.net/
  MAINTAINER:=PortGuard Maintainers <support@portguard.net>
  CONFLICTS:=fwknop fwknopd
  DEPENDS:=+iptables +curl +ca-bundle
endef

define Package/portguard-server/description
 PortGuard Server packages fwknopd for OpenWrt routers. It runs in UDP
 server mode and includes libfko in the same package for simple deployment.
 It expects an iptables-compatible firewall command such as iptables-nft to
 already be installed on the router.
endef

define Package/portguard-server/conffiles
/etc/fwknop/fwknopd.conf
/etc/fwknop/access.conf
endef

CONFIGURE_ARGS += \
	--sysconfdir=/etc \
	--localstatedir=/var/run \
	--disable-client \
	--enable-udp-server \
	--without-gpgme \
	--with-iptables=/usr/sbin/iptables \
	--with-firewalld=no \
	--with-portguard-release=$(PKG_RELEASE)

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	(cd $(PORTGUARD_SOURCE_DIR); tar \
		--exclude=.git \
		--exclude=autom4te.cache \
		--exclude='*.o' \
		--exclude='*.lo' \
		--exclude=.libs \
		--exclude=dist \
		-cf - .) | tar -C $(PKG_BUILD_DIR) -xf -
	if [ -f $(PKG_BUILD_DIR)/Makefile.am ]; then \
		awk '\
			function flush() { if (have_pending) { print pending; have_pending = 0 } } \
			BEGIN { in_subdirs = 0; pending = ""; have_pending = 0 } \
			/^SUBDIRS[[:space:]]*=/ { in_subdirs = 1 } \
			in_subdirs && /^[[:space:]]*doc[[:space:]]*$$$$/ { \
				if (have_pending) { \
					sub(/[[:space:]]*\\[[:space:]]*$$$$/, "", pending); \
					print pending; \
					have_pending = 0; \
				} \
				next; \
			} \
			{ flush(); pending = $$$$0; have_pending = 1 } \
			in_subdirs && /^[[:space:]]*$$$$/ { in_subdirs = 0 } \
			END { flush() }' \
			$(PKG_BUILD_DIR)/Makefile.am > $(PKG_BUILD_DIR)/Makefile.am.tmp; \
		mv $(PKG_BUILD_DIR)/Makefile.am.tmp $(PKG_BUILD_DIR)/Makefile.am; \
	fi
	if [ -f $(PKG_BUILD_DIR)/doc/Makefile.am ]; then \
		$(SED) 's/^AUTOMAKE_OPTIONS[[:space:]]*=[[:space:]]*info-in-builddir/#&/' \
			$(PKG_BUILD_DIR)/doc/Makefile.am; \
	fi
endef

define Package/portguard-server/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/fwknopd $(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libfko.so* $(1)/usr/lib/

	$(INSTALL_DIR) $(1)/etc/fwknop
	$(INSTALL_CONF) $(PKG_INSTALL_DIR)/etc/fwknop/fwknopd.conf $(1)/etc/fwknop/
	$(INSTALL_CONF) $(PKG_INSTALL_DIR)/etc/fwknop/access.conf $(1)/etc/fwknop/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/portguard.init $(1)/etc/init.d/fwknopd
endef

define Package/portguard-server/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
if ! command -v iptables >/dev/null 2>&1; then
	echo "portguard-server: install iptables-nft or another /usr/sbin/iptables provider before opening ports."
fi
exit 0
endef

$(eval $(call BuildPackage,portguard-server))
