#!/bin/sh
set -eu

BASE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

echo "[0Ghost] Installing binary & OpenWrt procd/LuCI files..."
mkdir -p /etc/0ghost /usr/bin /etc/init.d /etc/hotplug.d/iface /etc/hotplug.d/firewall /usr/share/luci/menu.d /usr/share/rpcd/acl.d /www/luci-static/resources/view/0ghost

cp -f "$BASE_DIR/usr/bin/0ghost" /usr/bin/0ghost
chmod 0755 /usr/bin/0ghost
cp -f "$BASE_DIR/etc/init.d/0ghost" /etc/init.d/0ghost
chmod 0755 /etc/init.d/0ghost
if [ -f "$BASE_DIR/etc/hotplug.d/iface/99-0ghost" ]; then
	cp -f "$BASE_DIR/etc/hotplug.d/iface/99-0ghost" /etc/hotplug.d/iface/99-0ghost
	chmod 0755 /etc/hotplug.d/iface/99-0ghost
	sed -i 's/\r$//' /etc/hotplug.d/iface/99-0ghost
fi
if [ -f "$BASE_DIR/etc/hotplug.d/firewall/99-0ghost" ]; then
	cp -f "$BASE_DIR/etc/hotplug.d/firewall/99-0ghost" /etc/hotplug.d/firewall/99-0ghost
	chmod 0755 /etc/hotplug.d/firewall/99-0ghost
	sed -i 's/\r$//' /etc/hotplug.d/firewall/99-0ghost
fi
cp -f "$BASE_DIR/usr/share/luci/menu.d/luci-app-0ghost.json" /usr/share/luci/menu.d/luci-app-0ghost.json
chmod 0644 /usr/share/luci/menu.d/luci-app-0ghost.json
cp -f "$BASE_DIR/usr/share/rpcd/acl.d/luci-app-0ghost.json" /usr/share/rpcd/acl.d/luci-app-0ghost.json
chmod 0644 /usr/share/rpcd/acl.d/luci-app-0ghost.json
cp -f "$BASE_DIR/www/luci-static/resources/view/0ghost/index.js" /www/luci-static/resources/view/0ghost/index.js
chmod 0644 /www/luci-static/resources/view/0ghost/index.js

# Optional non-blocking installation of nft_tproxy + nft_socket kernel modules if missing.
if command -v opkg >/dev/null 2>&1 && [ ! -d /sys/module/nft_tproxy ]; then
	(opkg update >/dev/null 2>&1 && opkg install kmod-nft-tproxy kmod-nft-socket >/dev/null 2>&1) || true
fi

# Strip any accidental CRLF line endings on shell scripts
sed -i 's/\r$//' /etc/init.d/0ghost

# Register uhttpd reverse-proxy prefix /0ghost -> http://127.0.0.1:19080 (idempotent)
if command -v uci >/dev/null 2>&1 && uci -q get uhttpd.main >/dev/null; then
	if ! uci -q get uhttpd.main.proxy_prefix | grep -q '/0ghost='; then
		uci add_list uhttpd.main.proxy_prefix='/0ghost=http://127.0.0.1:19080'
		uci commit uhttpd
		/etc/init.d/uhttpd reload >/dev/null 2>&1 || /etc/init.d/uhttpd restart >/dev/null 2>&1 || true
	fi
fi

# Refresh LuCI menu/ACL cache cleanly
rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache/*
/etc/init.d/rpcd restart >/dev/null 2>&1 || true

/etc/init.d/0ghost enable
/etc/init.d/0ghost restart

echo "[0Ghost] Installation complete. Service status: $(/etc/init.d/0ghost status || true)"
