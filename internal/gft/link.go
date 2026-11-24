package gft

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"ghostframe/internal/gftrtc"
)

// Address types in CONNECT and UDP payloads.
const (
	AtypIPv4   = gftrtc.AtypIPv4
	AtypDomain = gftrtc.AtypDomain
	AtypIPv6   = gftrtc.AtypIPv6
)

// EncodeAddr encodes "host:port" as [atyp | addr | port BE].
func EncodeAddr(hostport string) ([]byte, error) {
	return gftrtc.EncodeAddr(hostport)
}

// DecodeAddr parses an address; rest is any trailing payload bytes.
func DecodeAddr(b []byte) (hostport string, rest []byte, err error) {
	return gftrtc.DecodeAddr(b)
}

// SPKIOf returns the hex SHA-256 hash of a certificate's SubjectPublicKeyInfo (SPKI).
func SPKIOf(c *x509.Certificate) string {
	s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(s[:])
}

// PinOf is an alias for SPKIOf for v2 SPKI pinning.
func PinOf(c *x509.Certificate) string { return SPKIOf(c) }

// UnmarshalParams parses obfuscation params JSON.
func UnmarshalParams(b []byte) (Params, error) {
	var p Params
	err := json.Unmarshal(b, &p)
	return p, err
}

// Link represents a GhostFrame node link (gft3://, gft2://, or legacy gft://).
type Link struct {
	V         int     `json:"v"`
	Host      string  `json:"host"`
	Port      int     `json:"port"`
	SNI       string  `json:"sni"`
	PSK       string  `json:"psk"`                 // base64
	Verify    string  `json:"verify,omitempty"`    // "ca" or "spki"
	Pin       string  `json:"pin,omitempty"`       // SHA-256 hex of SPKI (required for "spki")
	FP        string  `json:"fp,omitempty"`        // "chrome" (default), "edge", "firefox", "ios"
	Transport string  `json:"transport,omitempty"` // "auto" (default dual-track), "rtc" (or legacy "quic"), "tcp"
	SplitSNI  bool    `json:"split_sni,omitempty"` // split first ClientHello record across SNI
	HopRange  string  `json:"hop_range,omitempty"` // optional UDP port range e.g. "20000-40000"
	UpMbps    int     `json:"up_mbps,omitempty"`   // optional Smart-Brutal upload target Mbps (0 = Auto-Probe)
	DownMbps  int     `json:"down_mbps,omitempty"` // optional Smart-Brutal download target Mbps (0 = Auto-Probe)
	Params    *Params `json:"params,omitempty"`
	Remark    string  `json:"remark,omitempty"`
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$`)

// PSKBytes decodes the base64 pre-shared key.
func (l *Link) PSKBytes() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(l.PSK)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(l.PSK)
	}
	return b, err
}

// EffectiveVerify returns "ca" or "spki".
func (l *Link) EffectiveVerify() string {
	v := strings.ToLower(strings.TrimSpace(l.Verify))
	if v != "" {
		return v
	}
	if l.Pin != "" {
		return "spki"
	}
	return "ca"
}

// EffectiveFP returns normalized browser fingerprint identifier.
func (l *Link) EffectiveFP() string {
	fp := strings.ToLower(strings.TrimSpace(l.FP))
	if fp == "" {
		return "chrome"
	}
	return fp
}

// EffectiveTransport returns normalized transport priority: "rtc" (UDP-first) or "tcp" (TCP-first).
// Legacy "", "auto", "quic", "udp", "udp_first" normalize to "rtc"; "tcp_first" normalizes to "tcp".
func (l *Link) EffectiveTransport() string {
	t := strings.ToLower(strings.TrimSpace(l.Transport))
	switch t {
	case "", "auto", "quic", "rtc", "udp", "udp_first":
		return "rtc"
	case "tcp", "tcp_first":
		return "tcp"
	default:
		return t
	}
}

// ParseHopRange returns minPort, maxPort, ok for UDP dynamic port hopping.
func (l *Link) ParseHopRange() (int, int, bool) {
	hr := strings.TrimSpace(l.HopRange)
	if hr == "" {
		return 0, 0, false
	}
	parts := strings.Split(hr, "-")
	if len(parts) != 2 {
		return 0, 0, false
	}
	lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, false
	}
	return lo, hi, true
}

// Validate checks link version and all field legalities.
func (l *Link) Validate() error {
	if l.V < 1 || l.V > 4 {
		return fmt.Errorf("unsupported link version %d", l.V)
	}
	if net.ParseIP(l.Host) == nil && !hostRe.MatchString(l.Host) {
		return errors.New("invalid host")
	}
	if l.Port < 1 || l.Port > 65535 {
		return errors.New("invalid port")
	}
	if l.SNI != "" && !hostRe.MatchString(l.SNI) {
		return errors.New("invalid sni")
	}
	psk, err := l.PSKBytes()
	if err != nil || len(psk) < 16 {
		return errors.New("invalid psk (base64, >=16 bytes)")
	}
	switch l.EffectiveVerify() {
	case "ca":
		if l.SNI == "" && net.ParseIP(l.Host) != nil {
			return errors.New("ca verify requires sni domain name")
		}
	case "spki":
		if len(l.Pin) != 64 {
			return errors.New("invalid spki pin (sha256 hex)")
		}
		if _, err := hex.DecodeString(l.Pin); err != nil {
			return errors.New("invalid pin hex")
		}
	default:
		return fmt.Errorf("unsupported verify mode %q (want ca or spki)", l.Verify)
	}
	switch l.EffectiveFP() {
	case "chrome", "edge", "firefox", "ios":
	default:
		return fmt.Errorf("unsupported fingerprint %q", l.FP)
	}
	switch l.EffectiveTransport() {
	case "rtc", "tcp":
	default:
		return fmt.Errorf("unsupported transport %q", l.Transport)
	}
	if l.UpMbps < 0 || l.UpMbps > 65535 || l.DownMbps < 0 || l.DownMbps > 65535 {
		return errors.New("up_mbps/down_mbps must be 0..65535")
	}
	if strings.TrimSpace(l.HopRange) != "" {
		if _, _, ok := l.ParseHopRange(); !ok {
			return fmt.Errorf("invalid hop_range %q", l.HopRange)
		}
	}
	if l.Params != nil {
		if err := l.Params.Validate(); err != nil {
			return fmt.Errorf("invalid params: %w", err)
		}
	}
	return nil
}

// Encode serializes the link as a ksl4:// URI (or legacy gft2:// if explicitly set V == 2 with no v3+ options).
func (l *Link) Encode() string {
	cp := *l
	cp.Remark = "" // keep wire base64 compact; remark travels in URL #fragment
	scheme := "ksl4://"
	if cp.V == 2 && !cp.SplitSNI && cp.HopRange == "" && (cp.Transport == "" || cp.Transport == "tcp") {
		scheme = "gft2://"
	} else {
		cp.V = 4
		if cp.Transport == "" {
			cp.Transport = "rtc"
		}
	}
	if cp.Verify == "" {
		cp.Verify = cp.EffectiveVerify()
	}
	if cp.FP == "" {
		cp.FP = cp.EffectiveFP()
	}
	b, _ := json.Marshal(cp)
	s := scheme + base64.RawURLEncoding.EncodeToString(b)
	if l.Remark != "" {
		s += "#" + url.PathEscape(l.Remark)
	}
	return s
}

// ParseLink decodes a ksl4://, gft3://, gft2://, or legacy gft:// link.
func ParseLink(s string) (*Link, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "ksl4://"):
		s = s[len("ksl4://"):]
	case strings.HasPrefix(s, "gft3://"):
		s = s[len("gft3://"):]
	case strings.HasPrefix(s, "gft2://"):
		s = s[len("gft2://"):]
	case strings.HasPrefix(s, "gft://"):
		s = s[len("gft://"):]
	default:
		return nil, errors.New("not a ksl4:// or gft3:// link")
	}
	remark := ""
	if i := strings.IndexByte(s, '#'); i >= 0 {
		remark, _ = url.PathUnescape(s[i+1:])
		s = s[:i]
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, errors.New("bad base64url payload")
	}
	var l Link
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&l); err != nil {
		return nil, errors.New("bad json payload")
	}
	if l.V == 1 {
		l.V = 2
	}
	l.Remark = remark
	if err := l.Validate(); err != nil {
		return nil, err
	}
	return &l, nil
}
