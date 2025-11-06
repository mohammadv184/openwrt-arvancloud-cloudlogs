# Copyright (c) Mohammad Abbasi <mohammad.v184@gmail.com> - All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

include $(TOPDIR)/rules.mk

PKG_NAME:=arvancloud-cloudlogs
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Mohammad Abbasi <mohammad.v184@gmail.com>
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_URL:=https://github.com/mohammadv184/openwrt-arvancloud-cloudlogs

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/arvancloud-cloudlogs
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Forward OpenWrt logd entries to ArvanCloud CloudLogs
  URL:=https://github.com/mohammadv184/openwrt-arvancloud-cloudlogs
  MAINTAINER:=Mohammad Abbasi <mohammad.v184@gmail.com>
  DEPENDS:=+libubus +libubox +libcurl
endef

define Package/arvancloud-cloudlogs/description
A small daemon that subscribes to logd via ubus and forwards logs to ArvanCloud CloudLogs service.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(Build/Patch)
endef


TARGET_CFLAGS += -Wall -Wextra -O2

TARGET_LDFLAGS += -lubus -lubox -lcurl

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/arvancloud-cloudlogs/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/arvancloud-cloudlogs $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/arvancloud-cloudlogs.init $(1)/etc/init.d/arvancloud-cloudlogs
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/arvancloud-cloudlogs.conf $(1)/etc/config/arvancloud-cloudlogs
endef

$(eval $(call BuildPackage,arvancloud-cloudlogs))
