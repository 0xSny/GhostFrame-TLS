package gft

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"ghostframe/internal/netbind"
	utls "github.com/refraction-networking/utls"
)

func clientHelloIDFor(fp string) utls.ClientHelloID {
	switch fp {
	case "edge":
		return utls.HelloEdge_Auto
	case "firefox":
		return utls.HelloFirefox_Auto
	case "ios":
		return utls.HelloIOS_Auto
	default:
		return utls.HelloChrome_Auto
	}
}

// UTLSConfigFor builds a uTLS client config honoring Link.Verify ("ca" or "spki").
func UTLSConfigFor(l *Link) (*utls.Config, error) {
	sni := l.SNI
	if sni == "" && net.ParseIP(l.Host) == nil {
		sni = l.Host
	}
	cfg := &utls.Config{
		ServerName: sni,
		MinVersion: utls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	}

	switch l.EffectiveVerify() {
	case "ca":
		cfg.InsecureSkipVerify = false
	case "spki":
		want, err := hex.DecodeString(l.Pin)
		if err != nil || len(want) != sha256.Size {
			return nil, errors.New("invalid spki pin")
		}
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs utls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(sum[:], want) != 1 {
				return errors.New("certificate spki pin mismatch")
			}
			return nil
		}
	default:
		return nil, fmt.Errorf("unsupported verify mode %q", l.Verify)
	}
	return cfg, nil
}

// DialV3Stealth performs TCP (NoDelay + optional RecordSplitConn) + uTLS ClientHello
// with Pre-TLS SessionID steganography (bound to ClientRandom) + post-TLS ClientAuthFrame.
func DialV3Stealth(ctx context.Context, l *Link, timeout time.Duration) (net.Conn, []byte, time.Duration, error) {
	return DialV3StealthWithID(ctx, l, timeout, DefaultClientID)
}

// DialV3StealthWithID connects with an explicit 8-byte ClientID for server NAT port preservation.
func DialV3StealthWithID(ctx context.Context, l *Link, timeout time.Duration, clientID [8]byte) (net.Conn, []byte, time.Duration, error) {
	psk, err := l.PSKBytes()
	if err != nil {
		return nil, nil, 0, err
	}
	ucfg, err := UTLSConfigFor(l)
	if err != nil {
		return nil, nil, 0, err
	}
	d := net.Dialer{Timeout: timeout, Control: netbind.Control}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(l.Host, strconv.Itoa(l.Port)))
	if err != nil {
		return nil, nil, 0, err
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	var transport net.Conn = raw
	if l.SplitSNI || l.V >= 3 {
		transport = NewRecordSplitConn(raw)
	}
	uc := newUClientWithHardware(transport, ucfg, clientHelloIDFor(l.EffectiveFP()))
	if err := InjectStegoSessionID(uc, psk, time.Now()); err != nil {
		_ = raw.Close()
		return nil, nil, 0, err
	}
	t0 := time.Now()
	_ = uc.SetDeadline(time.Now().Add(timeout))
	if err := uc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, nil, 0, err
	}
	hs := time.Since(t0)

	authFrame, salt, err := BuildClientAuthFrameWithID(psk, time.Now(), clientID)
	if err != nil {
		_ = raw.Close()
		return nil, nil, 0, err
	}
	if _, err := uc.Write(authFrame); err != nil {
		_ = raw.Close()
		return nil, nil, 0, err
	}
	_ = uc.SetDeadline(time.Time{})
	return uc, salt, hs, nil
}

// DialKnock performs TCP (NoDelay) + uTLS browser fingerprint handshake and
// atomically writes the single-syscall Knock v2 packet.
func DialKnock(ctx context.Context, l *Link, poolFlags uint16, timeout time.Duration) (net.Conn, [16]byte, time.Duration, error) {
	var salt [16]byte
	psk, err := l.PSKBytes()
	if err != nil {
		return nil, salt, 0, err
	}
	ucfg, err := UTLSConfigFor(l)
	if err != nil {
		return nil, salt, 0, err
	}

	d := net.Dialer{Timeout: timeout, Control: netbind.Control}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(l.Host, strconv.Itoa(l.Port)))
	if err != nil {
		return nil, salt, 0, err
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	uc := newUClientWithHardware(raw, ucfg, clientHelloIDFor(l.EffectiveFP()))
	t0 := time.Now()
	_ = uc.SetDeadline(time.Now().Add(timeout))
	if err := uc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, salt, 0, err
	}
	hs := time.Since(t0)

	pkt, salt, err := BuildKnockV2(psk, time.Now(), poolFlags)
	if err != nil {
		_ = raw.Close()
		return nil, salt, 0, err
	}
	// Single atomic Write() call so Knock v2 lands in one TLS record.
	if _, err := uc.Write(pkt); err != nil {
		_ = raw.Close()
		return nil, salt, 0, err
	}
	_ = uc.SetDeadline(time.Time{})
	return uc, salt, hs, nil
}

// DialSession connects using v3 Pre-TLS stealth (default for V>=3 or SplitSNI)
// or Knock v2 fallback and starts a Ghost Frame Session.
func DialSession(ctx context.Context, l *Link, ps *ParamStore, poolFlags uint16, timeout time.Duration) (*Session, time.Duration, error) {
	return DialSessionWithID(ctx, l, ps, poolFlags, timeout, DefaultClientID)
}

// DialSessionWithID connects using an explicit 8-byte ClientID for server NAT port preservation.
func DialSessionWithID(ctx context.Context, l *Link, ps *ParamStore, poolFlags uint16, timeout time.Duration, clientID [8]byte) (*Session, time.Duration, error) {
	psk, err := l.PSKBytes()
	if err != nil {
		return nil, 0, err
	}
	if l.V >= 3 || l.SplitSNI {
		conn, salt, hs, err := DialV3StealthWithID(ctx, l, timeout, clientID)
		if err != nil {
			return nil, 0, err
		}
		s := NewSession(conn, true, ps, nil)
		s.SetExpectedV3Ack(psk, salt)
		s.SetOnParam(func(p Params) { ps.Set(p) })
		go func() { _ = s.Run() }()
		return s, hs, nil
	}
	uc, salt, hs, err := DialKnock(ctx, l, poolFlags, timeout)
	if err != nil {
		return nil, 0, err
	}
	s := NewSession(uc, true, ps, nil)
	s.SetExpectedAck(psk, salt)
	s.SetOnParam(func(p Params) { ps.Set(p) })
	go func() { _ = s.Run() }()
	return s, hs, nil
}

// PingResult holds handshake and in-session echo latencies.
type PingResult struct {
	Handshake time.Duration
	KnockRTT  time.Duration
	Total     time.Duration
}

// Ping measures a full handshake + auth + in-band CmdPing echo RTT (for CLI/tests).
func Ping(ctx context.Context, l *Link, timeout time.Duration) (PingResult, error) {
	t0 := time.Now()
	ps := NewParamStore(DefaultParams())
	if l.Params != nil {
		ps.Set(*l.Params)
	}
	s, hs, err := DialSession(ctx, l, ps, 0, timeout)
	if err != nil {
		return PingResult{}, err
	}
	defer s.Close()

	got := make(chan time.Duration, 1)
	s.SetOnPing(func(d time.Duration) {
		select {
		case got <- d:
		default:
		}
	})

	if err := s.SendPingReq(); err != nil {
		return PingResult{}, err
	}
	select {
	case d := <-got:
		return PingResult{Handshake: hs, KnockRTT: d, Total: time.Since(t0)}, nil
	case <-time.After(timeout):
		return PingResult{}, errors.New("knock echo timeout")
	case <-ctx.Done():
		return PingResult{}, ctx.Err()
	}
}
