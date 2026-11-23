#!/usr/bin/env bash
set -euo pipefail

# Kestrel (Kestrel-RTC) v4.2.0 Installer (Server + Phicomm N1 / OpenWrt / Linux Client)
REPO="Spittingjiu/Ghost"
ROLE="server"
UNATTENDED=0
LISTEN_PORT=443
DEFAULT_HOP_RANGE="40000-65000"
HOP_RANGE=""
HOP_EXPLICIT=0
SNI_OVERRIDE=""
CLIENT_LINK=""
SOCKS_ADDR="127.0.0.1:10808"
LOW_MEM=0
MIRROR_PREFIX=""
TARGET_VER="latest"

log()  { printf "\033[1;36m[KSL]\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m[✓]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
die()  { printf "\033[1;31m[×]\033[0m %s\n" "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Kestrel (Kestrel-RTC) v4.2.0 Installer

Usage:
  install.sh [options]

Options:
  --role <server|client>   Install server + `ksl` TUI or `kestrel-core` client daemon (default: server)
  --unattended             Non-interactive server deployment
  --port <1-65535>         Server main TCP/RTC listen port (default: 443)
  --hop <min-max|none>     Server UDP port hopping range (default: 40000-65000; pass 'none' to disable)
  --sni <domain>           Override auto-selected non-CDN camouflage SNI
  --link <ksl4://...>      Client ksl4:// URI (or legacy gft3://) for --role client
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
    --hop)        if [[ "${2:-}" == "none" || "${2:-}" == "off" ]]; then HOP_RANGE=""; else HOP_RANGE="$2"; fi; HOP_EXPLICIT=1; shift 2 ;;
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

# 3. Kernel BBR + 32MB Kestrel-RTC UDP Buffers (/etc/sysctl.d/99-ksl-rtc.conf)
apply_sysctl_tuning() {
  if [[ -d /etc/sysctl.d ]]; then
    cat > /etc/sysctl.d/99-ksl-rtc.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_autocorking = 0
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 8388608
net.core.wmem_default = 8388608
net.ipv4.udp_rmem_min = 65536
net.ipv4.udp_wmem_min = 65536
net.core.netdev_max_backlog = 16384
EOF
    sysctl --system >/dev/null 2>&1 || true
    ok "Applied BBR + fq and 32MB Kestrel-RTC UDP buffers (/etc/sysctl.d/99-ksl-rtc.conf)"
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
  trap 'rm -rf "${tmp_dir:-}"' RETURN

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
    busy="$(ss -tulpn 2>/dev/null | grep -E ":${LISTEN_PORT}[[:space:]]" | grep -vE "kestrel-server|gft-server" || true)"
    if [[ -n "$busy" ]]; then
      warn "Port ${LISTEN_PORT} is already in use by another process:"
      printf "%s\n" "$busy"
      if [[ "$UNATTENDED" -eq 1 ]]; then
        die "Port ${LISTEN_PORT} conflict in --unattended mode; pass --port <alt> to avoid disrupting existing services."
      fi
      printf "\nChoose how to proceed without stopping your existing service:\n"
      printf "  [1] Switch Kestrel listen port to an alternate port (e.g. 8443) and coexist\n"
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
  local exempt_ports=()
  if command -v ss >/dev/null 2>&1; then
    while IFS= read -r p; do
      [[ -n "$p" ]] || continue
      if (( p >= lo && p <= hi && p != dst )); then
        exempt_ports+=("$p")
      fi
    done < <(ss -ulnp 2>/dev/null | grep -vE 'kestrel-server|gft-server' | awk 'NR>1 {print $4}' | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p' | sort -nu)
  fi

  if command -v nft >/dev/null 2>&1; then
    nft delete table inet gft_hop >/dev/null 2>&1 || true
    nft delete table inet ksl_hop >/dev/null 2>&1 || true
    {
      echo "add table inet ksl_hop"
      echo "add chain inet ksl_hop prerouting { type nat hook prerouting priority dstnat; policy accept; }"
      if (( ${#exempt_ports[@]} > 0 )); then
        local port_set
        port_set=$(IFS=,; echo "${exempt_ports[*]}")
        echo "add rule inet ksl_hop prerouting udp dport { ${port_set} } return"
        ok "Preserved co-hosted UDP ports (${port_set}) with nft RETURN exemption"
      fi
      echo "add rule inet ksl_hop prerouting udp dport ${lo}-${hi} redirect to :${dst}"
    } | nft -f -
    ok "Configured isolated nftables table inet ksl_hop (UDP ${lo}-${hi} -> :${dst})"
  elif command -v iptables >/dev/null 2>&1; then
    iptables -t nat -D PREROUTING -j GFT_HOP >/dev/null 2>&1 || true
    iptables -t nat -D PREROUTING -p udp -j GFT_HOP >/dev/null 2>&1 || true
    iptables -t nat -D PREROUTING -j KSL_HOP >/dev/null 2>&1 || true
    iptables -t nat -N KSL_HOP >/dev/null 2>&1 || true
    iptables -t nat -F KSL_HOP
    iptables -t nat -C PREROUTING -p udp -j KSL_HOP >/dev/null 2>&1 || iptables -t nat -A PREROUTING -p udp -j KSL_HOP
    if (( ${#exempt_ports[@]} > 0 )); then
      local i=0 chunk=""
      for p in "${exempt_ports[@]}"; do
        chunk="${chunk:+${chunk},}${p}"
        i=$((i + 1))
        if (( i % 15 == 0 )); then
          iptables -t nat -A KSL_HOP -p udp -m multiport --dports "${chunk}" -j RETURN
          chunk=""
        fi
      done
      if [[ -n "$chunk" ]]; then
        iptables -t nat -A KSL_HOP -p udp -m multiport --dports "${chunk}" -j RETURN
      fi
      ok "Preserved co-hosted UDP ports (${exempt_ports[*]}) with iptables RETURN exemption"
    fi
    iptables -t nat -A KSL_HOP -p udp --dport "${lo}:${hi}" -j REDIRECT --to-ports "${dst}"
    if command -v netfilter-persistent >/dev/null 2>&1; then
      netfilter-persistent save >/dev/null 2>&1 || true
    fi
    ok "Configured isolated iptables chain KSL_HOP (UDP ${lo}:${hi} -> :${dst})"
  fi
}

install_server() {
  [[ "$INIT_SYS" == "systemd" ]] || die "Server role currently requires systemd (detected: $INIT_SYS)."
  apply_sysctl_tuning

  download_verified_asset "kestrel-server-linux-${ARCH}" "/opt/kestrel/kestrel-server"
  ln -sf /opt/kestrel/kestrel-server /usr/local/bin/ksl
  ln -sf /opt/kestrel/kestrel-server /usr/local/bin/gft

  if ! id -u gft >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -M gft || useradd -r -s /bin/false -M gft
  fi
  mkdir -p /etc/kestrel /var/lib/kestrel

  # Lossless migration from legacy GhostFrame (/etc/gft) if present
  if [[ ! -f /etc/kestrel/server.json ]] && [[ -f /etc/gft/server.json ]]; then
    cp -an /etc/gft/. /etc/kestrel/ 2>/dev/null || cp -a /etc/gft/server.json /etc/kestrel/server.json
    if [[ -d /var/lib/gft ]]; then
      cp -an /var/lib/gft/. /var/lib/kestrel/ 2>/dev/null || true
    fi
    log "Migrated existing node configuration /etc/gft -> /etc/kestrel"
  fi
  if [[ -f /etc/kestrel/server.json ]]; then
    # Ensure cert.pem/key.pem are also present under /etc/kestrel if server.json was migrated earlier
    if [[ -f /etc/gft/cert.pem ]] && [[ ! -f /etc/kestrel/cert.pem ]]; then
      cp -a /etc/gft/cert.pem /etc/kestrel/cert.pem
    fi
    if [[ -f /etc/gft/key.pem ]] && [[ ! -f /etc/kestrel/key.pem ]]; then
      cp -a /etc/gft/key.pem /etc/kestrel/key.pem
    fi
    sed -i -e 's|"/etc/gft/|"/etc/kestrel/|g' -e 's|"/var/lib/gft"|"/var/lib/kestrel"|g' -e 's|"/var/lib/gft/|"/var/lib/kestrel/|g' /etc/kestrel/server.json
  fi

  if [[ -f /etc/kestrel/server.json ]]; then
    log "Preserving existing /etc/kestrel/server.json (lossless binary upgrade)."
    if [[ "$HOP_EXPLICIT" -eq 0 ]]; then
      local existing_hop
      existing_hop="$(sed -n 's/.*"hop_range"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /etc/kestrel/server.json | head -n1 || true)"
      if [[ -n "$existing_hop" ]]; then
        HOP_RANGE="$existing_hop"
        log "Preserving existing UDP hop range from server.json: ${HOP_RANGE}"
      fi
    fi
    local existing_port
    existing_port="$(sed -n 's/.*"listen"[[:space:]]*:[[:space:]]*":\([0-9][0-9]*\)".*/\1/p' /etc/kestrel/server.json | head -n1 || true)"
    if [[ -n "$existing_port" ]]; then
      LISTEN_PORT="$existing_port"
    fi
  else
    check_port_and_guide
    if [[ "$HOP_EXPLICIT" -eq 0 ]]; then
      HOP_RANGE="$DEFAULT_HOP_RANGE"
      log "Enabling default UDP port hopping range: ${HOP_RANGE}"
    fi
    local init_args=(init --conf-dir /etc/kestrel --state-dir /var/lib/kestrel --listen ":${LISTEN_PORT}")
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
    /opt/kestrel/kestrel-server "${init_args[@]}" >/dev/null
  fi

  chown -R gft:gft /etc/kestrel /var/lib/kestrel
  chmod 0750 /etc/kestrel /var/lib/kestrel
  if [[ -f /etc/kestrel/key.pem ]]; then chmod 0600 /etc/kestrel/key.pem; fi

  # Unconditionally stop legacy ghostframe service/process before binding port
  systemctl stop ghostframe >/dev/null 2>&1 || true
  systemctl disable ghostframe >/dev/null 2>&1 || true
  pkill -x gft-server >/dev/null 2>&1 || true
  sleep 0.5

  cat > /usr/local/bin/ksl-hop-sync <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
CFG="/etc/kestrel/server.json"
[[ -f "$CFG" ]] || exit 0
RANGE="$(sed -n 's/.*"hop_range"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CFG" | head -n1 || true)"
DST="$(sed -n 's/.*"listen"[[:space:]]*:[[:space:]]*":\([0-9][0-9]*\)".*/\1/p' "$CFG" | head -n1 || true)"
DST="${DST:-443}"
if [[ -z "$RANGE" ]]; then
  command -v nft >/dev/null 2>&1 && nft delete table inet ksl_hop >/dev/null 2>&1 || true
  if command -v iptables >/dev/null 2>&1; then
    iptables -t nat -D PREROUTING -j KSL_HOP >/dev/null 2>&1 || true
    iptables -t nat -D PREROUTING -p udp -j KSL_HOP >/dev/null 2>&1 || true
    iptables -t nat -F KSL_HOP >/dev/null 2>&1 || true
    iptables -t nat -X KSL_HOP >/dev/null 2>&1 || true
  fi
  exit 0
fi
LO="${RANGE%-*}"; HI="${RANGE#*-}"
EXEMPT=()
if command -v ss >/dev/null 2>&1; then
  while IFS= read -r p; do
    [[ -n "$p" ]] || continue
    if (( p >= LO && p <= HI && p != DST )); then EXEMPT+=("$p"); fi
  done < <(ss -ulnp 2>/dev/null | grep -vE 'kestrel-server|gft-server' | awk 'NR>1 {print $4}' | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p' | sort -nu)
fi
if command -v nft >/dev/null 2>&1; then
  nft delete table inet gft_hop >/dev/null 2>&1 || true
  nft delete table inet ksl_hop >/dev/null 2>&1 || true
  {
    echo "add table inet ksl_hop"
    echo "add chain inet ksl_hop prerouting { type nat hook prerouting priority dstnat; policy accept; }"
    if (( ${#EXEMPT[@]} > 0 )); then
      PSET=$(IFS=,; echo "${EXEMPT[*]}")
      echo "add rule inet ksl_hop prerouting udp dport { ${PSET} } return"
    fi
    echo "add rule inet ksl_hop prerouting udp dport ${LO}-${HI} redirect to :${DST}"
  } | nft -f -
elif command -v iptables >/dev/null 2>&1; then
  iptables -t nat -D PREROUTING -j GFT_HOP >/dev/null 2>&1 || true
  iptables -t nat -D PREROUTING -p udp -j GFT_HOP >/dev/null 2>&1 || true
  iptables -t nat -D PREROUTING -j KSL_HOP >/dev/null 2>&1 || true
  iptables -t nat -N KSL_HOP >/dev/null 2>&1 || true
  iptables -t nat -F KSL_HOP
  iptables -t nat -C PREROUTING -p udp -j KSL_HOP >/dev/null 2>&1 || iptables -t nat -A PREROUTING -p udp -j KSL_HOP
  if (( ${#EXEMPT[@]} > 0 )); then
    i=0; chunk=""
    for p in "${EXEMPT[@]}"; do
      chunk="${chunk:+${chunk},}${p}"; i=$((i+1))
      if (( i % 15 == 0 )); then
        iptables -t nat -A KSL_HOP -p udp -m multiport --dports "${chunk}" -j RETURN; chunk=""
      fi
    done
    [[ -n "$chunk" ]] && iptables -t nat -A KSL_HOP -p udp -m multiport --dports "${chunk}" -j RETURN
  fi
  iptables -t nat -A KSL_HOP -p udp --dport "${LO}:${HI}" -j REDIRECT --to-ports "${DST}"
fi
EOF
  chmod 0755 /usr/local/bin/ksl-hop-sync

  cat > /etc/systemd/system/kestrel.service <<'EOF'
[Unit]
Description=Kestrel (Kestrel-RTC) v4.2.0 Dual-Stack Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=gft
Group=gft
ExecStartPre=+/usr/local/bin/ksl-hop-sync
ExecStart=/opt/kestrel/kestrel-server run -config /etc/kestrel/server.json
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
  systemctl enable kestrel >/dev/null 2>&1
  systemctl restart kestrel
  sleep 1.5
  systemctl is-active --quiet kestrel || die "kestrel failed to start; inspect: journalctl -u kestrel -n 30"

  echo ""
  /opt/kestrel/kestrel-server show-card -config /etc/kestrel/server.json
  ok "Installation complete! Type 'ksl' (or 'gft') anytime to open the interactive control center."
}

install_client() {
  [[ -n "$CLIENT_LINK" ]] || die "--role client requires --link \"ksl4://...\" (or legacy \"gft3://...\")"
  download_verified_asset "kestrel-core-linux-${ARCH}" "/usr/local/bin/kestrel-core"
  ln -sf /usr/local/bin/kestrel-core /usr/local/bin/gft-core
  mkdir -p /etc/kestrel

  local extra_flags="-no-sysproxy"
  if [[ "$LOW_MEM" -eq 1 ]]; then
    extra_flags="${extra_flags} -low-mem"
  fi

  if [[ "$INIT_SYS" == "systemd" ]]; then
    if systemctl list-unit-files 2>/dev/null | grep -q '^gft-core\.service'; then
      systemctl stop gft-core >/dev/null 2>&1 || true
      systemctl disable gft-core >/dev/null 2>&1 || true
    fi
    cat > /etc/systemd/system/kestrel-core.service <<EOF
[Unit]
Description=Kestrel (Kestrel-RTC) v4.2.0 Headless Core Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/kestrel-core ${extra_flags} -socks "${SOCKS_ADDR}" -link "${CLIENT_LINK}"
Restart=always
RestartSec=3s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable kestrel-core >/dev/null 2>&1
    systemctl restart kestrel-core
    ok "kestrel-core systemd service installed and started (SOCKS5: ${SOCKS_ADDR})"
  elif [[ "$INIT_SYS" == "procd" ]]; then
    cat > /etc/init.d/kestrel-core <<EOF
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1

start_service() {
  procd_open_instance
  procd_set_param command /usr/local/bin/kestrel-core ${extra_flags} -socks "${SOCKS_ADDR}" -link "${CLIENT_LINK}"
  procd_set_param respawn 3600 5 5
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_close_instance
}
EOF
    chmod 0755 /etc/init.d/kestrel-core
    /etc/init.d/kestrel-core enable
    /etc/init.d/kestrel-core restart
    ok "kestrel-core OpenWrt procd service installed and started (SOCKS5: ${SOCKS_ADDR})"
  else
    warn "Neither systemd nor procd detected; run manually:"
    printf "/usr/local/bin/kestrel-core %s -socks %q -link %q\n" "$extra_flags" "$SOCKS_ADDR" "$CLIENT_LINK"
  fi
}

case "$ROLE" in
  server) install_server ;;
  client) install_client ;;
  *) die "Invalid --role: ${ROLE} (must be 'server' or 'client')" ;;
esac
