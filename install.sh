#!/usr/bin/env bash
set -euo pipefail

# GhostFrame-TLS (GFT) v3.2 Installer (Server + Phicomm N1 / OpenWrt / Linux Client)
REPO="Spittingjiu/GhostFrame-TLS"
ROLE="server"
UNATTENDED=0
LISTEN_PORT=443
HOP_RANGE=""
SNI_OVERRIDE=""
CLIENT_LINK=""
SOCKS_ADDR="127.0.0.1:10808"
LOW_MEM=0
MIRROR_PREFIX=""
TARGET_VER="latest"

log()  { printf "\033[1;36m[GFT]\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m[✓]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
die()  { printf "\033[1;31m[×]\033[0m %s\n" "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
GhostFrame-TLS (GFT) v3.2 Installer

Usage:
  install.sh [options]

Options:
  --role <server|client>   Install server + `gft` TUI or `gft-core` client daemon (default: server)
  --unattended             Non-interactive server deployment
  --port <1-65535>         Server main TLS/QUIC listen port (default: 443)
  --hop <min-max>          Server UDP port hopping range (e.g. 20000-30000)
  --sni <domain>           Override auto-selected non-CDN camouflage SNI
  --link <gft3://...>      Client gft3:// URI for --role client
  --socks <addr:port>      Client SOCKS5 listen address (default: 127.0.0.1:10808)
  --low-mem                Enable low-memory router mode (<35MB RSS, ideal for N1/S905D)
  --mirror <url-prefix>    Optional download mirror prefix for GitHub URLs
  --version <tag>          Release tag to install (default: latest)
  -h, --help               Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)       ROLE="$2"; shift 2 ;;
    --unattended) UNATTENDED=1; shift ;;
    --port)       LISTEN_PORT="$2"; shift 2 ;;
    --hop)        HOP_RANGE="$2"; shift 2 ;;
    --sni)        SNI_OVERRIDE="$2"; shift 2 ;;
    --link)       CLIENT_LINK="$2"; shift 2 ;;
    --socks)      SOCKS_ADDR="$2"; shift 2 ;;
    --low-mem)    LOW_MEM=1; shift ;;
    --mirror)     MIRROR_PREFIX="$2"; shift 2 ;;
    --version)    TARGET_VER="$2"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *)            die "Unknown option: $1" ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "Please run install.sh as root (sudo)."

# 1. Architecture & Init System Detection
RAW_ARCH="$(uname -m)"
case "$RAW_ARCH" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "Unsupported CPU architecture: $RAW_ARCH (supported: x86_64/amd64, aarch64/arm64)" ;;
esac

INIT_SYS="unknown"
if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  INIT_SYS="systemd"
elif [[ -f /etc/openwrt_release ]] || command -v procd >/dev/null 2>&1 || [[ -x /sbin/procd ]]; then
  INIT_SYS="procd"
fi
log "Detected arch=${ARCH}, init=${INIT_SYS}, role=${ROLE}"

ensure_tools() {
  for bin in curl tar sha256sum; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq curl tar coreutils ca-certificates
        break
      elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q curl tar coreutils ca-certificates
        break
      elif command -v opkg >/dev/null 2>&1; then
        opkg update && opkg install curl ca-bundle coreutils-sha256sum || true
        break
      fi
    fi
  done
}
ensure_tools

# 2. NTP Clock Calibration (prevents 30s stego time-bucket auth failures)
sync_ntp_clock() {
  local remote_date remote_ts local_ts drift
  remote_date="$(curl -fsSI --max-time 4 https://cloudflare.com 2>/dev/null | grep -i '^date:' | head -n1 | cut -d' ' -f2- | tr -d '\r' || true)"
  if [[ -z "$remote_date" ]]; then
    remote_date="$(curl -fsSI --max-time 4 https://www.baidu.com 2>/dev/null | grep -i '^date:' | head -n1 | cut -d' ' -f2- | tr -d '\r' || true)"
  fi
  if [[ -n "$remote_date" ]]; then
    remote_ts="$(date -d "$remote_date" +%s 2>/dev/null || echo 0)"
    local_ts="$(date +%s)"
    if [[ "$remote_ts" -gt 0 ]]; then
      drift=$(( local_ts - remote_ts ))
      drift=${drift#-}
      if [[ "$drift" -gt 15 ]]; then
        warn "System clock drift is ${drift}s (>15s); synchronizing NTP clock..."
        if command -v timedatectl >/dev/null 2>&1; then
          timedatectl set-ntp true >/dev/null 2>&1 || true
        fi
        if command -v chronyc >/dev/null 2>&1; then
          chronyc makestep >/dev/null 2>&1 || true
        elif command -v ntpd >/dev/null 2>&1; then
          ntpd -q -n -p pool.ntp.org >/dev/null 2>&1 || true
        fi
      else
        ok "Clock check passed (drift ${drift}s <= 15s)"
      fi
    fi
  fi
}
sync_ntp_clock

# 3. Kernel BBR + 25MB QUIC UDP Buffers (/etc/sysctl.d/99-gft-apex.conf)
apply_sysctl_tuning() {
  if [[ -d /etc/sysctl.d ]]; then
    cat > /etc/sysctl.d/99-gft-apex.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
EOF
    sysctl --system >/dev/null 2>&1 || true
    ok "Applied BBR + fq and 25MB QUIC UDP buffers (/etc/sysctl.d/99-gft-apex.conf)"
  fi
}

# 4. Release Binary Fetch & Strict SHA-256 Verification
dl_url() {
  local raw="$1"
  if [[ -n "$MIRROR_PREFIX" ]]; then
    printf "%s%s" "${MIRROR_PREFIX%/}/" "$raw"
  else
    printf "%s" "$raw"
  fi
}

download_verified_asset() {
  local asset_name="$1"
  local dest_path="$2"
  local base_url tmp_dir

  if [[ "$TARGET_VER" == "latest" ]]; then
    base_url="https://github.com/${REPO}/releases/latest/download"
  else
    base_url="https://github.com/${REPO}/releases/download/${TARGET_VER}"
  fi

  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' RETURN

  local sum_url bin_url expected got
  sum_url="$(dl_url "${base_url}/checksums.txt")"
  bin_url="$(dl_url "${base_url}/${asset_name}")"

  log "Downloading ${asset_name} (${TARGET_VER})..."
  if ! curl -fsSL --retry 2 -o "${tmp_dir}/checksums.txt" "$sum_url"; then
    die "Failed to fetch checksums.txt from ${sum_url}. Verify network connectivity or build from source with 'go build ./cmd/gft-server'."
  fi
  if ! curl -fsSL --retry 2 -o "${tmp_dir}/${asset_name}" "$bin_url"; then
    die "Failed to download ${asset_name} from ${bin_url}."
  fi

  expected="$(awk -v f="$asset_name" '{ gsub(/^\.\//, "", $2); if ($2 == f) { print tolower($1); exit } }' "${tmp_dir}/checksums.txt")"
  [[ -n "$expected" ]] || die "checksums.txt has no entry for ${asset_name}"
  got="$(sha256sum "${tmp_dir}/${asset_name}" | awk '{print tolower($1)}')"
  [[ "$got" == "$expected" ]] || die "SHA-256 mismatch for ${asset_name}: expected=${expected} got=${got}"
  ok "SHA-256 verified for ${asset_name}"

  mkdir -p "$(dirname "$dest_path")"
  mv -f "${tmp_dir}/${asset_name}" "$dest_path"
  chmod 0755 "$dest_path"
}

# 5. Port Conflict Check (never force-kill existing web services!)
check_port_and_guide() {
  local fallback_mode="mirror"
  local fallback_target=""
  if command -v ss >/dev/null 2>&1; then
    local busy
    busy="$(ss -tulpn 2>/dev/null | grep -E ":${LISTEN_PORT}[[:space:]]" | grep -v "gft-server" || true)"
    if [[ -n "$busy" ]]; then
      warn "Port ${LISTEN_PORT} is already in use by another process:"
      printf "%s\n" "$busy"
      if [[ "$UNATTENDED" -eq 1 ]]; then
        die "Port ${LISTEN_PORT} conflict in --unattended mode; pass --port <alt> to avoid disrupting existing services."
      fi
      printf "\nChoose how to proceed without stopping your existing service:\n"
      printf "  [1] Switch GhostFrame listen port to an alternate port (e.g. 8443) and coexist\n"
      printf "  [2] Abort installation manually\n"
      read -r -p "Select [1/2]: " choice
      case "$choice" in
        1)
          read -r -p "Enter alternate listen port [1024-65535, default 8443]: " altp
          LISTEN_PORT="${altp:-8443}"
          read -r -p "Optional local website reverse_proxy URL (blank keeps transparent SNI mirror): " rurl
          if [[ -n "$rurl" ]]; then
            fallback_mode="reverse_proxy"
            fallback_target="$rurl"
          fi
          ;;
        *) die "Aborted cleanly without modifying existing services on port ${LISTEN_PORT}." ;;
      esac
    fi
  fi
  CHOSEN_FALLBACK_MODE="$fallback_mode"
  CHOSEN_FALLBACK_TARGET="$fallback_target"
}

apply_hop_firewall() {
  local range="$1"
  local dst="$2"
  [[ -n "$range" ]] || return 0
  local lo="${range%-*}"
  local hi="${range#*-}"
  if command -v nft >/dev/null 2>&1; then
    nft delete table inet gft_hop >/dev/null 2>&1 || true
    nft -f - <<EOF
add table inet gft_hop
add chain inet gft_hop prerouting { type nat hook prerouting priority dstnat; policy accept; }
add rule inet gft_hop prerouting udp dport ${lo}-${hi} redirect to :${dst}
EOF
    ok "Configured isolated nftables table inet gft_hop (UDP ${lo}-${hi} -> :${dst})"
  elif command -v iptables >/dev/null 2>&1; then
    iptables -t nat -N GFT_HOP >/dev/null 2>&1 || true
    iptables -t nat -F GFT_HOP
    iptables -t nat -C PREROUTING -j GFT_HOP >/dev/null 2>&1 || iptables -t nat -A PREROUTING -j GFT_HOP
    iptables -t nat -A GFT_HOP -p udp --dport "${lo}:${hi}" -j REDIRECT --to-ports "${dst}"
    ok "Configured isolated iptables chain GFT_HOP (UDP ${lo}:${hi} -> :${dst})"
  fi
}

install_server() {
  [[ "$INIT_SYS" == "systemd" ]] || die "Server role currently requires systemd (detected: $INIT_SYS)."
  check_port_and_guide
  apply_sysctl_tuning

  download_verified_asset "gft-server-linux-${ARCH}" "/opt/ghostframe/gft-server"
  ln -sf /opt/ghostframe/gft-server /usr/local/bin/gft

  if ! id -u gft >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -M gft || useradd -r -s /bin/false -M gft
  fi
  mkdir -p /etc/gft /var/lib/gft

  local init_args=(init --conf-dir /etc/gft --state-dir /var/lib/gft --listen ":${LISTEN_PORT}")
  if [[ -n "$SNI_OVERRIDE" ]]; then
    init_args+=(--sni "$SNI_OVERRIDE")
  else
    init_args+=(--auto-sni)
  fi
  if [[ -n "$HOP_RANGE" ]]; then
    init_args+=(--hop-range "$HOP_RANGE")
  fi
  if [[ -n "$CHOSEN_FALLBACK_MODE" ]]; then
    init_args+=(--fallback-mode "$CHOSEN_FALLBACK_MODE")
  fi
  if [[ -n "$CHOSEN_FALLBACK_TARGET" ]]; then
    init_args+=(--fallback-target "$CHOSEN_FALLBACK_TARGET")
  fi

  log "Initializing server credentials & running non-CDN origin probe..."
  /opt/ghostframe/gft-server "${init_args[@]}" >/dev/null
  chown -R gft:gft /etc/gft /var/lib/gft
  chmod 0750 /etc/gft /var/lib/gft

  cat > /etc/systemd/system/ghostframe.service <<'EOF'
[Unit]
Description=GhostFrame-TLS (GFT) v3.2 Apex Dual-Stack Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=gft
Group=gft
ExecStart=/opt/ghostframe/gft-server run -config /etc/gft/server.json
Restart=always
RestartSec=2s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  apply_hop_firewall "$HOP_RANGE" "$LISTEN_PORT"

  systemctl daemon-reload
  systemctl enable ghostframe >/dev/null 2>&1
  systemctl restart ghostframe
  sleep 1.5
  systemctl is-active --quiet ghostframe || die "ghostframe failed to start; inspect: journalctl -u ghostframe -n 30"

  echo ""
  /opt/ghostframe/gft-server show-card -config /etc/gft/server.json
  ok "Installation complete! Type 'gft' anytime to open the interactive control center."
}

install_client() {
  [[ -n "$CLIENT_LINK" ]] || die "--role client requires --link \"gft3://...\""
  download_verified_asset "gft-core-linux-${ARCH}" "/usr/local/bin/gft-core"
  mkdir -p /etc/gft

  local extra_flags="-no-sysproxy"
  if [[ "$LOW_MEM" -eq 1 ]]; then
    extra_flags="${extra_flags} -low-mem"
  fi

  if [[ "$INIT_SYS" == "systemd" ]]; then
    cat > /etc/systemd/system/gft-core.service <<EOF
[Unit]
Description=GhostFrame-TLS (GFT) v3.2 Headless Core Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gft-core ${extra_flags} -socks "${SOCKS_ADDR}" -link "${CLIENT_LINK}"
Restart=always
RestartSec=3s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable gft-core >/dev/null 2>&1
    systemctl restart gft-core
    ok "gft-core systemd service installed and started (SOCKS5: ${SOCKS_ADDR})"
  elif [[ "$INIT_SYS" == "procd" ]]; then
    cat > /etc/init.d/gft-core <<EOF
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1

start_service() {
  procd_open_instance
  procd_set_param command /usr/local/bin/gft-core ${extra_flags} -socks "${SOCKS_ADDR}" -link "${CLIENT_LINK}"
  procd_set_param respawn 3600 5 5
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_close_instance
}
EOF
    chmod 0755 /etc/init.d/gft-core
    /etc/init.d/gft-core enable
    /etc/init.d/gft-core restart
    ok "gft-core OpenWrt procd service installed and started (SOCKS5: ${SOCKS_ADDR})"
  else
    warn "Neither systemd nor procd detected; run manually:"
    printf "/usr/local/bin/gft-core %s -socks %q -link %q\n" "$extra_flags" "$SOCKS_ADDR" "$CLIENT_LINK"
  fi
}

case "$ROLE" in
  server) install_server ;;
  client) install_client ;;
  *) die "Invalid --role: ${ROLE} (must be 'server' or 'client')" ;;
esac
