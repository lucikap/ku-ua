include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-ku-ua
PKG_VERSION:=1.2.4
PKG_RELEASE:=1


include $(INCLUDE_DIR)/package.mk

define Package/luci-app-ku-ua
	SECTION:=luci
	CATEGORY:=LuCI
	SUBMENU:=3. Applications
	TITLE:=KU-UA for luci
endef

define Package/luci-app-ku-ua/description
	<- NULL ->
endef
define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/luci-app-ku-ua/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller/
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi/
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/cbi/
	$(INSTALL_DIR) $(1)/etc/config/
	$(INSTALL_DIR) $(1)/etc/init.d/
	
	$(INSTALL_BIN) ./controller/* $(1)/usr/lib/lua/luci/controller/
	$(INSTALL_BIN) ./model/* $(1)/usr/lib/lua/luci/model/cbi/
	$(INSTALL_CONF) ./etc/config/ku-ua.config $(1)/etc/config/ku-ua
	$(INSTALL_BIN) ./etc/init.d/ku-ua.init $(1)/etc/init.d/ku-ua
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
