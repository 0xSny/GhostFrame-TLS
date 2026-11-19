# Deployment & Usage Guide

## 1. Server Setup (Linux)

Run the installer on Ubuntu / Debian / Rocky / Arch Linux:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Spittingjiu/GhostFrame-TLS/main/install.sh)
```

For unattended installation on port `443` with conflict-free UDP port hopping (avoiding any existing services and Linux `32768-60999` ephemeral ports):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Spittingjiu/GhostFrame-TLS/main/install.sh) \
  --unattended --port 443 --hop 25000-32000
```

Manage the server anytime with the `gft` interactive TUI:

```bash
gft
systemctl status ghostframe
journalctl -u ghostframe -f
```

### Recommended High-BDP Kernel Tuning (`/etc/sysctl.d/99-gft-rtc.conf`)

```ini
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 8388608
net.core.wmem_default = 8388608
net.ipv4.udp_rmem_min = 65536
net.ipv4.udp_wmem_min = 65536
net.core.netdev_max_backlog = 16384
```

Apply with `sysctl --system`.

---

## 2. Windows Desktop Client (`GhostFrame-Pro.exe`)

1. Launch `GhostFrame-Pro.exe` (no external runtime or browser required).
2. Copy a `gft3://` link from the server `gft` menu and press `Ctrl+V` (or click **导入 gft3://**), or place your configuration in `%USERPROFILE%\.gft\client.json` based on [configs/client.example.json](../configs/client.example.json).
3. Default local listeners are SOCKS5 `127.0.0.1:10808` (TCP + UDP ASSOCIATE) and HTTP `127.0.0.1:10809`.
4. To hot-swap local ports while connected without dropping active listeners, click the top port pill (`S5 :10808 · HTTP :10809`) or edit the **本地端口** fields and press `Enter` / **保存**.
5. Closing the window minimizes to the system tray; use the tray context menu to switch nodes/modes or quit cleanly (restoring the pre-connection system proxy snapshot from `sysproxy_backup.json`).

For automated testing or sandboxed runs without touching Windows Registry proxy settings:

```powershell
$env:GFT_NO_SYSPROXY = "1"
.\GhostFrame-Pro.exe -no-sysproxy
```

---

## 3. Linux / ARM64 Router (`gft-core`) & Clash Meta

Start `gft-core` as a headless daemon (use `-low-mem` on memory-constrained routers such as Phicomm N1 / S905D):

```bash
./gft-core -link "gft3://..." -socks 0.0.0.0:10808 -http 0.0.0.0:10809 -low-mem
```

Clash Meta / Mihomo outbound snippet (click **复制 Clash YAML** in the Windows UI to copy automatically):

```yaml
proxies:
  - name: "GhostFrame-Apex"
    type: socks5
    server: 127.0.0.1
    port: 10808
    udp: true
```
