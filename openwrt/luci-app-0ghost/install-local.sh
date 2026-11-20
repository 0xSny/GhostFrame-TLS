#!/bin/sh
set -eu

BASE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

echo "[KestrelBox] Installing binary & OpenWrt procd/LuCI files..."
mkdir -p /etc/kbox /usr/bin /etc/init.d /etc/hotplug.d/iface /etc/hotplug.d/firewall /usr/share/luci/menu.d /usr/share/rpcd/acl.d /www/luci-static/resources/view/kbox

# Lossless migration from legacy 0Ghost installation if present
if [ -x /etc/init.d/0ghost ]; then
	/etc/init.d/0ghost stop >/dev/null 2>&1 || true
	/etc/init.d/0ghost disable >/dev/null 2>&1 || true
fi
if [ ! -f /etc/kbox/config.json ] && [ -f /etc/0ghost/config.json ]; then
	cp -f /etc/0ghost/config.json /etc/kbox/config.json
	echo "[KestrelBox] Migrated /etc/0ghost/config.json -> /etc/kbox/config.json"
fi
if [ ! -f /etc/kbox/cn_ipv4.txt ] && [ -f /etc/0ghost/cn_ipv4.txt ]; then
	cp -f /etc/0ghost/cn_ipv4.txt /etc/kbox/cn_ipv4.txt
fi
rm -f /etc/init.d/0ghost /etc/hotplug.d/iface/99-0ghost /etc/hotplug.d/firewall/99-0ghost \
	/usr/share/luci/menu.d/luci-app-0ghost.json /usr/share/rpcd/acl.d/luci-app-0ghost.json
rm -rf /www/luci-static/resources/view/0ghost

cp -f "$BASE_DIR/usr/bin/kbox" /usr/bin/kbox
chmod 0755 /usr/bin/kbox
cp -f "$BASE_DIR/etc/init.d/kbox" /etc/init.d/kbox
chmod 0755 /etc/init.d/kbox
if [ -f "$BASE_DIR/etc/hotplug.d/iface/99-kbox" ]; then
	cp -f "$BASE_DIR/etc/hotplug.d/iface/99-kbox" /etc/hotplug.d/iface/99-kbox
	chmod 0755 /etc/hotplug.d/iface/99-kbox
	sed -i 's/\r$//' /etc/hotplug.d/iface/99-kbox
fi
if [ -f "$BASE_DIR/etc/hotplug.d/firewall/99-kbox" ]; then
	cp -f "$BASE_DIR/etc/hotplug.d/firewall/99-kbox" /etc/hotplug.d/firewall/99-kbox
	chmod 0755 /etc/hotplug.d/firewall/99-kbox
	sed -i 's/\r$//' /etc/hotplug.d/firewall/99-kbox
fi
cp -f "$BASE_DIR/usr/share/luci/menu.d/luci-app-kbox.json" /usr/share/luci/menu.d/luci-app-kbox.json
chmod 0644 /usr/share/luci/menu.d/luci-app-kbox.json
cp -f "$BASE_DIR/usr/share/rpcd/acl.d/luci-app-kbox.json" /usr/share/rpcd/acl.d/luci-app-kbox.json
chmod 0644 /usr/share/rpcd/acl.d/luci-app-kbox.json
cp -f "$BASE_DIR/www/luci-static/resources/view/kbox/index.js" /www/luci-static/resources/view/kbox/index.js
chmod 0644 /www/luci-static/resources/view/kbox/index.js

# Optional non-blocking installation of nft_tproxy + nft_socket kernel modules if missing.
if command -v opkg >/dev/null 2>&1 && [ ! -d /sys/module/nft_tproxy ]; then
	(opkg update >/dev/null 2>&1 && opkg install kmod-nft-tproxy kmod-nft-socket >/dev/null 2>&1) || true
fi

# Strip any accidental CRLF line endings on shell scripts
sed -i 's/\r$//' /etc/init.d/kbox

# Register uhttpd reverse-proxy prefix /kbox -> http://127.0.0.1:19080 (and clean legacy /0ghost=)
if command -v uci >/dev/null 2>&1 && uci -q get uhttpd.main >/dev/null; then
	uhttpd_changed=0
	if uci -q get uhttpd.main.proxy_prefix | grep -q '/0ghost='; then
		uci del_list uhttpd.main.proxy_prefix='/0ghost=http://127.0.0.1:19080' >/dev/null 2>&1 || true
		uhttpd_changed=1
	fi
	if ! uci -q get uhttpd.main.proxy_prefix | grep -q '/kbox='; then
		uci add_list uhttpd.main.proxy_prefix='/kbox=http://127.0.0.1:19080'
		uhttpd_changed=1
	fi
	if [ "$uhttpd_changed" = "1" ]; then
		uci commit uhttpd
		/etc/init.d/uhttpd reload >/dev/null 2>&1 || /etc/init.d/uhttpd restart >/dev/null 2>&1 || true
	fi
fi

# Refresh LuCI menu/ACL cache cleanly
rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache/*
/etc/init.d/rpcd restart >/dev/null 2>&1 || true

/etc/init.d/kbox enable
/etc/init.d/kbox restart

echo "[KestrelBox] Installation complete. Service status: $(/etc/init.d/kbox status || true)"
