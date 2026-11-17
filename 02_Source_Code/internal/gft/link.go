package gft

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Address types in CONNECT and UDP payloads.
const (
	AtypIPv4   = 1
	AtypDomain = 3
	AtypIPv6   = 4
)

// EncodeAddr encodes "host:port" as [atyp | addr | port BE].
func EncodeAddr(hostport string) ([]byte, error) {
	h, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("bad port")
	}
	var out []byte
	if ip := net.ParseIP(h); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, AtypIPv4)
			out = append(out, v4...)
		} else {
			out = append(out, AtypIPv6)
			out = append(out, ip.To16()...)
		}
	} else {
		if len(h) == 0 || len(h) > 255 {
			return nil, errors.New("bad host")
		}
		out = append(out, AtypDomain, byte(len(h)))
		out = append(out, h...)
	}
	out = binary.BigEndian.AppendUint16(out, uint16(port))
	return out, nil
}

// DecodeAddr parses an address; rest is any trailing payload bytes.
func DecodeAddr(b []byte) (hostport string, rest []byte, err error) {
	if len(b) < 1 {
		return "", nil, errors.New("short addr")
	}
	var host string
	var off int
	switch b[0] {
	case AtypIPv4:
		if len(b) < 1+4+2 {
			return "", nil, errors.New("short addr")
		}
		host = net.IP(b[1:5]).String()
		off = 5
	case AtypIPv6:
		if len(b) < 1+16+2 {
			return "", nil, errors.New("short addr")
		}
		host = net.IP(b[1:17]).String()
		off = 17
	case AtypDomain:
		if len(b) < 2 || len(b) < 2+int(b[1])+2 || b[1] == 0 {
			return "", nil, errors.New("short addr")
		}
		host = string(b[2 : 2+int(b[1])])
		off = 2 + int(b[1])
	default:
		return "", nil, errors.New("bad atyp")
	}
	port := binary.BigEndian.Uint16(b[off:])
	if port == 0 {
		return "", nil, errors.New("bad port")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), b[off+2:], nil
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
	Transport string  `json:"transport,omitempty"` // "auto" (default dual-track), "quic", "tcp"
	SplitSNI  bool    `json:"split_sni,omitempty"` // split first ClientHello record across SNI
	HopRange  string  `json:"hop_range,omitempty"` // optional UDP port range e.g. "20000-30000"
	Params    *Params `json:"params,omitempty"`
	Remark    string  `json:"-"`
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

// EffectiveTransport returns normalized transport strategy: "auto", "quic", or "tcp".
func (l *Link) EffectiveTransport() string {
	t := strings.ToLower(strings.TrimSpace(l.Transport))
	if t == "" {
		return "auto"
	}
	return t
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
	if l.V != 1 && l.V != 2 && l.V != 3 {
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
	case "auto", "quic", "tcp":
	default:
		return fmt.Errorf("unsupported transport %q", l.Transport)
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

// Encode serializes the link as a gft3:// URI (or gft2:// if explicitly set V == 2 with no v3 options).
func (l *Link) Encode() string {
	cp := *l
	scheme := "gft3://"
	if cp.V == 2 && !cp.SplitSNI && cp.HopRange == "" && (cp.Transport == "" || cp.Transport == "tcp") {
		scheme = "gft2://"
	} else {
		cp.V = 3
		if cp.Transport == "" {
			cp.Transport = "auto"
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

// ParseLink decodes a gft3://, gft2://, or legacy gft:// link.
func ParseLink(s string) (*Link, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "gft3://"):
		s = s[len("gft3://"):]
	case strings.HasPrefix(s, "gft2://"):
		s = s[len("gft2://"):]
	case strings.HasPrefix(s, "gft://"):
		s = s[len("gft://"):]
	default:
		return nil, errors.New("not a gft3:// or gft2:// link")
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
