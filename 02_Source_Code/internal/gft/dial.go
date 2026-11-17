package gft

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
)

// TLSConfigFor builds a client TLS config that authenticates the server ONLY by
// SHA-256 fingerprint pinning of the leaf certificate (self-signed servers).
// A pin is mandatory: a link without a valid pin is rejected.
func TLSConfigFor(l *Link) (*tls.Config, error) {
	want, err := hex.DecodeString(l.Pin)
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("invalid pin")
	}
	sni := l.SNI
	if sni == "" && net.ParseIP(l.Host) == nil {
		sni = l.Host
	}
	return &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
		// Standard Go pattern for fingerprint pinning: chain verification is replaced by the
		// mandatory pin comparison in VerifyConnection below (the connection fails without a match).
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(sum[:], want) != 1 {
				return errors.New("certificate pin mismatch")
			}
			return nil
		},
	}, nil
}

func uTLSConfigFor(l *Link) (*utls.Config, error) {
	want, err := hex.DecodeString(l.Pin)
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("invalid pin")
	}
	sni := l.SNI
	if sni == "" && net.ParseIP(l.Host) == nil {
		sni = l.Host
	}
	return &utls.Config{
		ServerName:         sni,
		MinVersion:         utls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no peer certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if subtle.ConstantTimeCompare(sum[:], want) != 1 {
				return errors.New("certificate pin mismatch")
			}
			return nil
		},
	}, nil
}

// PinOf returns the hex SHA-256 pin of a certificate.
func PinOf(c *x509.Certificate) string { s := sha256.Sum256(c.Raw); return hex.EncodeToString(s[:]) }

// DialKnockTCP performs TCP + uTLS (Chrome ClientHello fingerprint + Pinning) and sends the Knock Frame.
func DialKnockTCP(ctx context.Context, l *Link, timeout time.Duration) (net.Conn, time.Duration, error) {
	psk, err := l.PSKBytes()
	if err != nil {
		return nil, 0, err
	}
	ucfg, err := uTLSConfigFor(l)
	if err != nil {
		return nil, 0, err
	}
	d := net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(l.Host, strconv.Itoa(l.Port)))
	if err != nil {
		return nil, 0, err
	}
	uc := utls.UClient(raw, ucfg, utls.HelloChrome_Auto)
	t0 := time.Now()
	_ = uc.SetDeadline(time.Now().Add(timeout))
	if err := uc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, 0, err
	}
	hs := time.Since(t0)
	if _, err := uc.Write(BuildKnock(psk, time.Now())); err != nil {
		_ = raw.Close()
		return nil, 0, err
	}
	_ = uc.SetDeadline(time.Time{})
	return uc, hs, nil
}

// DialKnockQUIC performs QUIC (TLS 1.3 over UDP + Pinning, HTTP/3 ALPN camouflage) and sends the Knock Frame.
func DialKnockQUIC(ctx context.Context, l *Link, timeout time.Duration) (net.Conn, time.Duration, error) {
	psk, err := l.PSKBytes()
	if err != nil {
		return nil, 0, err
	}
	cfg, err := TLSConfigFor(l)
	if err != nil {
		return nil, 0, err
	}
	cfg.NextProtos = []string{"h3", "http/1.1"}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(l.Host, strconv.Itoa(l.Port))
	t0 := time.Now()
	qconn, err := quic.DialAddr(dialCtx, addr, cfg, DefaultQUICConfig())
	if err != nil {
		return nil, 0, err
	}
	hs := time.Since(t0)

	st, err := qconn.OpenStreamSync(dialCtx)
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, 0, err
	}
	qsc := &QUICStreamConn{Stream: st, Conn: qconn}
	_ = qsc.SetDeadline(time.Now().Add(timeout))
	if _, err := qsc.Write(BuildKnock(psk, time.Now())); err != nil {
		_ = qsc.Close()
		return nil, 0, err
	}
	_ = qsc.SetDeadline(time.Time{})
	return qsc, hs, nil
}

type dialRaceRes struct {
	conn net.Conn
	hs   time.Duration
	mode string
	err  error
}

// DialKnockProto dials according to l.Transport ("auto", "tcp", "quic"/"udp").
// In "auto" mode it performs a staggered Happy Eyeballs race: uTLS-TCP starts first
// and QUIC-UDP joins after 200ms (or immediately if TCP fails), defeating TCP blocking cleanly.
func DialKnockProto(ctx context.Context, l *Link, timeout time.Duration) (net.Conn, string, time.Duration, error) {
	mode := strings.ToLower(strings.TrimSpace(l.Transport))
	switch mode {
	case "tcp":
		c, hs, err := DialKnockTCP(ctx, l, timeout)
		return c, "tcp-utls", hs, err
	case "quic", "udp":
		c, hs, err := DialKnockQUIC(ctx, l, timeout)
		return c, "quic-udp", hs, err
	case "", "auto":
		raceCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		ch := make(chan dialRaceRes, 2)
		tcpFailedEarly := make(chan struct{})
		var failOnce sync.Once

		go func() {
			c, hs, err := DialKnockTCP(raceCtx, l, timeout)
			if err != nil {
				failOnce.Do(func() { close(tcpFailedEarly) })
			}
			ch <- dialRaceRes{conn: c, hs: hs, mode: "tcp-utls", err: err}
		}()

		go func() {
			// Stagger QUIC by 200ms so unblocked TCP wins cleanly, while blocked TCP falls back immediately.
			select {
			case <-time.After(200 * time.Millisecond):
			case <-tcpFailedEarly:
			case <-raceCtx.Done():
				ch <- dialRaceRes{mode: "quic-udp", err: raceCtx.Err()}
				return
			}
			c, hs, err := DialKnockQUIC(raceCtx, l, timeout)
			ch <- dialRaceRes{conn: c, hs: hs, mode: "quic-udp", err: err}
		}()

		var errs []string
		for i := 0; i < 2; i++ {
			r := <-ch
			if r.err == nil && r.conn != nil {
				cancel()
				// Drain loser asynchronously so no leaked connection stays open.
				if i == 0 {
					go func() {
						if r2 := <-ch; r2.conn != nil {
							_ = r2.conn.Close()
						}
					}()
				}
				return r.conn, r.mode, r.hs, nil
			}
			if r.err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", r.mode, r.err))
			}
		}
		return nil, "", 0, fmt.Errorf("all transports failed (%s)", strings.Join(errs, "; "))
	default:
		return nil, "", 0, fmt.Errorf("unsupported transport %q", l.Transport)
	}
}

// DialKnock performs dual-stack (or selected) TLS1.3/QUIC handshake + Pinning and sends the Knock Frame.
func DialKnock(ctx context.Context, l *Link, timeout time.Duration) (net.Conn, time.Duration, error) {
	c, _, hs, err := DialKnockProto(ctx, l, timeout)
	return c, hs, err
}

// DialSessionInfo connects, starts a client session, and also returns the winning transport mode.
func DialSessionInfo(ctx context.Context, l *Link, ps *ParamStore, timeout time.Duration) (*Session, string, time.Duration, error) {
	c, mode, hs, err := DialKnockProto(ctx, l, timeout)
	if err != nil {
		return nil, "", 0, err
	}
	s := NewSession(c, true, ps, nil)
	s.SetOnParam(func(p Params) { ps.Set(p) })
	go func() { _ = s.Run() }()
	return s, mode, hs, nil
}

// DialSession connects and starts a client session (read loop running).
func DialSession(ctx context.Context, l *Link, ps *ParamStore, timeout time.Duration) (*Session, time.Duration, error) {
	s, _, hs, err := DialSessionInfo(ctx, l, ps, timeout)
	return s, hs, err
}

// PingResult holds real handshake + knock round-trip latencies.
type PingResult struct {
	Handshake time.Duration // TCP/QUIC handshake time
	KnockRTT  time.Duration // knock sent -> echo response received
	Total     time.Duration
	Transport string // "tcp-utls" or "quic-udp"
}

// Ping dials a fresh connection, knocks, and measures an echo round trip.
func Ping(ctx context.Context, l *Link, timeout time.Duration) (PingResult, error) {
	t0 := time.Now()
	ps := NewParamStore(DefaultParams())
	if l.Params != nil {
		ps.Set(*l.Params)
	}
	c, mode, hs, err := DialKnockProto(ctx, l, timeout)
	if err != nil {
		return PingResult{}, err
	}
	s := NewSession(c, true, ps, nil)
	defer s.Close()
	got := make(chan time.Duration, 1)
	s.SetOnPing(func(d time.Duration) {
		select {
		case got <- d:
		default:
		}
	})
	go func() { _ = s.Run() }()
	if err := s.SendPingReq(); err != nil {
		return PingResult{}, err
	}
	select {
	case d := <-got:
		return PingResult{Handshake: hs, KnockRTT: d, Total: time.Since(t0), Transport: mode}, nil
	case <-time.After(timeout):
		return PingResult{}, errors.New("knock echo timeout")
	case <-ctx.Done():
		return PingResult{}, ctx.Err()
	}
}
