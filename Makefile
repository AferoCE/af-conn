#  connectivity : WAN Daemon Subsystem
#  Copyright (c) 2014-2016 Afero, Inc. All rights reserved.

include $(TOPDIR)/rules.mk

PKG_NAME:=connectivity
PKG_VERSION:=1.0
PKG_RELEASE:=1

USE_SOURCE_DIR:=$(CURDIR)/pkg

PKG_BUILD_PARALLEL:=1
PKG_FIXUP:=autoreconf
PKG_INSTALL:=1
PKG_USE_MIPS16:=0

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/connectivity
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Kiban connectivity manager
  DEPENDS:=+libevent2 +libpthread +libpcap +librt +af-ipc +attrd +af-util +freed
  URL:=http://www.kibanlabs.com/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		all install
endef

define Package/connectivity/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/wand $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/atcmd $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/connmgr $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/wifistad $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/include/wifista_shared_types.h $(STAGING_DIR)/usr/include
	$(CP) -rp $(CURDIR)/pkg/files/* $(1)
endef

define Build/Clean
	$(RM) -rf $(CURDIR)/pkg/src/.deps/* $(CURDIR)/pkg/src/connd/.deps/* $(CURDIR)/pkg/src/atcmd/.deps/*
	$(RM) -rf $(CURDIR)/pkg/src/wand/.deps/*
	$(RM) -rf $(CURDIR)/pkg/src/wifistad/.deps/*
	$(RM) -rf $(CURDIR)/pkg/src/*.o $(CURDIR)/pkg/src/*.lo $(CURDIR)/pkg/src/wand/.deps/*
	$(RM) -rf $(CURDIR)/pkg/src/linux/*.o $(CURDIR)/pkg/src/.libs/*
	$(RM) -rf $(CURDIR)/pkg/src/wand/*.o $(CURDIR)/pkg/src/connd/*.o
	$(RM) -rf $(CURDIR)/pkg/src/wifistad/*.o
	$(RM) -rf $(CURDIR)/pkg/autom4te.cache/*
	$(RM) -rf $(CURDIR)/pkg/ipkg-install/*
	$(RM) -rf $(CURDIR)/pkg/ipkg-ar71xx/$(PKG_NAME)/*
	$(RM) -rf $(CURDIR)/pkg/libtool $(CURDIR)/pkg/config.*
	$(RM) -rf $(CURDIR)/pkg/.quilt_checked  $(CURDIR)/pkg/.prepared $(CURDIR)/pkg/.configured_ $(CURDIR)/pkg/.built
	$(RM) -rf $(CURDIR)/pkg/COPYING $(CURDIR)/pkg/NEWS
	$(RM) -rf $(CURDIR)/pkg/src/Makefile $(CURDIR)/pkg/src/Makefile.in $(CURDIR)/pkg/Makefile $(CURDIR)/pkg/Makefile.in
	$(RM) -rf $(CURDIR)/pkg/src/connd/Makefile $(CURDIR)/pkg/src/connd/Makefile.in
	$(RM) -rf $(CURDIR)/pkg/src/atcmd/Makefile $(CURDIR)/pkg/src/atcmd/Makefile.in
	$(RM) -rf $(CURDIR)/pkg/src/wifistad/Makefile $(CURDIR)/pkg/src/wifistad/Makefile.in
	$(RM) -f $(CURDIR)/pkg/src/wand/wand
	$(RM) -f $(CURDIR)/pkg/src/wifistad/wifistad

	$(RM) -rf $(CURDIR)/pkg/aclocal.m4 $(CURDIR)/pkg/ChangeLog  $(CURDIR)/pkg/ABOUT-NLS $(CURDIR)/pkg/AUTHORS $(CURDIR)/pkg/configure
	$(RM) -rf $(CURDIR)/pkg/.source_dir $(CURDIR)/pkg/stamp-h1
	$(RM) -rf $(CURDIR)/pkg/src/connd/connmgr $(CURDIR)/pkg/src/atcmd/atcmd-atcmd.o $(CURDIR)/pkg/src/atcmd/atcmd

	$(RM) -rf $(STAGING_DIR)/pkginfo/$(PKG_NAME).*
	$(RM) -rf $(1)/usr/bin/connmgr $(1)/usr/bin/atcmd
	$(RM) -rf $(1)/usr/lib/libevent-2.0.so.5 $(1)/usr/lib/libevent_pthreads-2.0.so.5 $(1)/usr/bin/switch_route_to.sh
	$(RM) -rf $(1)/etc/init.d/wand $(1)/etc/init.d/cmservice $(1)/usr/bin/wancontrol $(1)/usr/bin/wannetwork
	$(RM) -rf $(1)/etc/config/afero_whitelist.txt $(1) /etc/config/create_afero_whitelist.sh $(1)/etc/config/firewall.bento $(1)/etc/firewall.user.bento

endef

$(eval $(call BuildPackage,connectivity))
