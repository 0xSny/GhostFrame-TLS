package tproxy

import "encoding/json"

// GatewayMode controls how 0Ghost intercepts LAN and local router traffic.
type GatewayMode string

const (
	ModeRule   GatewayMode = "rule"   // Bypass LAN/CN IP + Split DNS + TPROXY overseas
	ModeGlobal GatewayMode = "global" // Transparently proxy all non-LAN/non-VPS traffic
	ModePort   GatewayMode = "port"   // Explicit LAN SOCKS5/HTTP ports only (no firewall rules)
)

// DeviceMode controls optional LAN client IP filtering in transparent modes.
type DeviceMode string

const (
	DeviceAll    DeviceMode = "all"    // Proxy all LAN devices
	DeviceOnly   DeviceMode = "only"   // Proxy ONLY listed DeviceIPs
	DeviceBypass DeviceMode = "bypass" // Bypass listed DeviceIPs (proxy all others)
)

// GatewayConfig persists side-router transparent gateway settings.
type GatewayConfig struct {
	GatewayMode        GatewayMode `json:"gateway_mode"`
	DeviceMode         DeviceMode  `json:"device_mode"`
	DeviceIPs          []string    `json:"device_ips,omitempty"`
	DirectDNS          []string    `json:"direct_dns,omitempty"`
	EnableIPv6         bool        `json:"enable_ipv6"`
	FilterAAAA         bool        `json:"filter_aaaa"`
	LANMasquerade      bool        `json:"lan_masquerade"`
	AutoYieldConflicts bool        `json:"auto_yield_conflicts"`
	TCPPort            int         `json:"tproxy_tcp_port"`
	UDPPort            int         `json:"tproxy_udp_port"`
	DNSPort            int         `json:"dns_port"`
	WebAddr            string      `json:"web_addr"`
	AllowLANWeb        bool        `json:"allow_lan_web,omitempty"`
	WebPassword        string      `json:"web_password,omitempty"`
	FWMark             int         `json:"fwmark"`
}

// DefaultGatewayConfig returns sensible, safe N1 side-router defaults.
func DefaultGatewayConfig() GatewayConfig {
	return GatewayConfig{
		GatewayMode:        ModeRule,
		DeviceMode:         DeviceAll,
		FilterAAAA:         true,
		AutoYieldConflicts: true,
		TCPPort:            10880,
		UDPPort:            10881,
		DNSPort:            7853,
		WebAddr:            "127.0.0.1:19080",
		FWMark:             0xff,
	}
}

// Normalize fills zero/invalid fields with safe defaults.
func (c *GatewayConfig) Normalize() {
	def := DefaultGatewayConfig()
	switch c.GatewayMode {
	case ModeRule, ModeGlobal, ModePort:
	default:
		c.GatewayMode = def.GatewayMode
	}
	switch c.DeviceMode {
	case DeviceAll, DeviceOnly, DeviceBypass:
	default:
		c.DeviceMode = def.DeviceMode
	}
	if c.TCPPort <= 0 || c.TCPPort > 65535 {
		c.TCPPort = def.TCPPort
	}
	if c.UDPPort <= 0 || c.UDPPort > 65535 {
		c.UDPPort = def.UDPPort
	}
	if c.DNSPort <= 0 || c.DNSPort > 65535 {
		c.DNSPort = def.DNSPort
	}
	if c.WebAddr == "" {
		c.WebAddr = def.WebAddr
	}
	if c.FWMark <= 0 {
		c.FWMark = def.FWMark
	}
	c.FilterAAAA = !c.EnableIPv6
}

// UnmarshalJSON keeps modern enable_ipv6 and legacy filter_aaaa bidirectional and unambiguous.
func (c *GatewayConfig) UnmarshalJSON(data []byte) error {
	type alias GatewayConfig
	var raw struct {
		alias
		HasEnableIPv6 *bool `json:"enable_ipv6"`
		HasFilterAAAA *bool `json:"filter_aaaa"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*c = GatewayConfig(raw.alias)
	switch {
	case raw.HasEnableIPv6 != nil:
		c.EnableIPv6 = *raw.HasEnableIPv6
		c.FilterAAAA = !c.EnableIPv6
	case raw.HasFilterAAAA != nil:
		c.FilterAAAA = *raw.HasFilterAAAA
		c.EnableIPv6 = !c.FilterAAAA
	default:
		c.EnableIPv6 = false
		c.FilterAAAA = true
	}
	return nil
}

// ConflictItem describes a detected third-party proxy daemon, routing hijack, or port collision.
type ConflictItem struct {
	Kind    string `json:"kind"`    // "service" | "process" | "port" | "route" | "firewall"
	Name    string `json:"name"`
	Detail  string `json:"detail"`
	Service string `json:"service,omitempty"`
}

// ConflictReport summarizes proxy conflicts on the Linux router host.
type ConflictReport struct {
	HasConflict bool           `json:"has_conflict"`
	Resolved    bool           `json:"resolved"`
	Items       []ConflictItem `json:"items"`
	Actions     []string       `json:"actions,omitempty"`
}

// FirewallSpec passes runtime parameters into the atomic nftables/iptables manager.
type FirewallSpec struct {
	Mode        GatewayMode
	DeviceMode  DeviceMode
	DeviceIPs   []string
	VPSIPs      []string
	VPSIPv6s    []string
	DirectDNS   []string
	TCPPort     int
	UDPPort     int
	DNSPort     int
	WebPort     int
	SocksPort   int
	HTTPPort    int
	FWMark      int
	TProxyMark  int
	RouteTable  int
	PreferTProxy       bool
	EnableIPv6         bool
	FilterAAAA         bool
	LANMasquerade      bool
	CNIPv4OverridePath string
}

// Stats reports live transparent gateway counters for telemetry and UI dashboards.
type Stats struct {
	FirewallActive  bool           `json:"firewall_active"`
	FirewallBackend string         `json:"firewall_backend"`
	LanIface        string         `json:"lan_iface"`
	LanIP           string         `json:"lan_ip"`
	GatewayIP       string         `json:"gateway_ip"`
	TCPConns        uint64         `json:"tcp_conns"`
	UDPConns        uint64         `json:"udp_conns"`
	DNSQueries      uint64         `json:"dns_queries"`
	DNSDirectHits   uint64         `json:"dns_direct_hits"`
	DNSTunnelHits   uint64         `json:"dns_tunnel_hits"`
	DNSRejectHits   uint64         `json:"dns_reject_hits"`
	Conflicts       ConflictReport `json:"conflicts"`
}
