#
# Copyright (C) 2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ku-ua
PKG_RELEASE:=4.7

include $(INCLUDE_DIR)/package.mk

define KernelPackage/ku-ua
  SUBMENU:=Other modules
  TITLE:=O_-
  FILES:=$(PKG_BUILD_DIR)/ku-ua.ko
  AUTOLOAD:=$(call AutoLoad,99,ku-ua)
endef

include $(INCLUDE_DIR)/kernel-defaults.mk

define Build/Compile
	$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" modules CFLAGS_MODULE="-std=gnu99 -O2"
endef

$(eval $(call KernelPackage,ku-ua))
