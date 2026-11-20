package gft

import (
	"context"
	"io"
	"net"
	"strconv"
	"time"

	"ghostframe/internal/gftrtc"
)

// DataStream abstracts a multiplexed bidirectional byte stream across either
// Ghost Frame v3 TCP Sessions or Kestrel-RTC Zero-HOL-Blocking streams.
type DataStream interface {
	io.ReadWriteCloser
	CloseWrite() error
	RemoteTarget() string
}

// UDPAssociation abstracts a client/server multiplexed UDP association.
type UDPAssociation interface {
	ID() uint16
	SendTo(target string, data []byte) error
	Recv() <-chan UDPPacket
	Done() <-chan struct{}
	Close() error
}

// UDPReplySink lets server outbound forward UDP responses back over TCP mux or Kestrel-RTC.
type UDPReplySink = gftrtc.UDPReplySink

// SplitBandwidthMbps divides total manual bandwidth target across poolSize concurrent
// Kestrel-RTC sessions (floor 1 Mbps when totalMbps > 0; 0 preserves Auto-Probe mode).
func SplitBandwidthMbps(totalMbps, poolSize int) int {
	if totalMbps <= 0 {
		return 0
	}
	if poolSize <= 1 {
		return totalMbps
	}
	v := totalMbps / poolSize
	if v < 1 {
		v = 1
	}
	return v
}

// PickHopPort chooses an initial or hopped UDP port within HopRange or returns Link.Port.
func PickHopPort(l *Link) int {
	lo, hi, ok := l.ParseHopRange()
	if !ok {
		return l.Port
	}
	return randRange(lo, hi)
}

// DialRTCSession opens a Kestrel-RTC session using DefaultClientID.
func DialRTCSession(ctx context.Context, l *Link, ps *ParamStore, port int, timeout time.Duration) (*gftrtc.RTCSession, time.Duration, error) {
	return DialRTCSessionWithID(ctx, l, ps, port, timeout, DefaultClientID)
}

// DialRTCSessionWithID opens a Kestrel-RTC session carrying clientID in the STUN Binding Request.
func DialRTCSessionWithID(ctx context.Context, l *Link, ps *ParamStore, port int, timeout time.Duration, clientID [8]byte) (*gftrtc.RTCSession, time.Duration, error) {
	if port <= 0 {
		port = PickHopPort(l)
	}
	psk, err := l.PSKBytes()
	if err != nil {
		return nil, 0, err
	}
	sess, hs, err := gftrtc.Dial(ctx, gftrtc.DialOptions{
		Host:     l.Host,
		Port:     port,
		PSK:      psk,
		ClientID: clientID,
		UpMbps:   l.UpMbps,
		DownMbps: l.DownMbps,
		Timeout:  timeout,
	})
	if err != nil {
		return nil, 0, err
	}
	applySessionParams(ps, sess)
	return sess, hs, nil
}

// DialRTCWithPacketConn dials Kestrel-RTC over an injected PacketConn (e.g., virtual/lossy test switch).
func DialRTCWithPacketConn(ctx context.Context, pc net.PacketConn, ownPC bool, raddr net.Addr, remotePort int, l *Link, ps *ParamStore, timeout time.Duration) (*gftrtc.RTCSession, time.Duration, error) {
	return DialRTCWithPacketConnAndID(ctx, pc, ownPC, raddr, remotePort, l, ps, timeout, DefaultClientID)
}

// DialRTCWithPacketConnAndID dials Kestrel-RTC over pc with an explicit 8-byte ClientID.
func DialRTCWithPacketConnAndID(ctx context.Context, pc net.PacketConn, ownPC bool, raddr net.Addr, remotePort int, l *Link, ps *ParamStore, timeout time.Duration, clientID [8]byte) (*gftrtc.RTCSession, time.Duration, error) {
	psk, err := l.PSKBytes()
	if err != nil {
		return nil, 0, err
	}
	if remotePort <= 0 {
		remotePort = l.Port
	}
	sess, hs, err := gftrtc.DialWithPacketConn(ctx, pc, ownPC, raddr, gftrtc.DialOptions{
		Host:     l.Host,
		Port:     remotePort,
		PSK:      psk,
		ClientID: clientID,
		UpMbps:   l.UpMbps,
		DownMbps: l.DownMbps,
		Timeout:  timeout,
	})
	if err != nil {
		return nil, 0, err
	}
	applySessionParams(ps, sess)
	return sess, hs, nil
}

func applySessionParams(ps *ParamStore, sess *gftrtc.RTCSession) {
	if ps == nil || sess == nil {
		return
	}
	if pj := sess.ParamsJSON(); len(pj) > 0 {
		if p, err := UnmarshalParams(pj); err == nil && p.Validate() == nil {
			ps.Set(p)
		}
	}
}

var _ = strconv.Itoa
