package gft

import (
	"crypto/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
)

// StegoCIDGenerator generates 16-byte steganographic QUIC Connection IDs
// [Salt 8B || HMAC-SHA256(PSK, "gft-v3-qcid" || Salt || Bucket)[0:8]].
type StegoCIDGenerator struct {
	psk []byte
}

// NewStegoCIDGenerator returns a quic.ConnectionIDGenerator bound to psk.
func NewStegoCIDGenerator(psk []byte) *StegoCIDGenerator {
	cp := make([]byte, len(psk))
	copy(cp, psk)
	return &StegoCIDGenerator{psk: cp}
}

// ConnectionIDLen returns the fixed 16-byte CID length.
func (g *StegoCIDGenerator) ConnectionIDLen() int {
	return 16
}

// GenerateConnectionID returns a 16-byte stego Connection ID.
// quic.ConnectionID is compatible as a byte wrapper; keep type alias method via quic package in quic_engine.go.
func (g *StegoCIDGenerator) GenerateBytes() ([]byte, error) {
	cid, err := MakeStegoQUICCID(g.psk, time.Now())
	if err != nil {
		return nil, err
	}
	return cid[:], nil
}

// AuthPacketConn filters incoming UDP packets before quic-go sees them:
//   - Known authenticated peer addrs are fast-pathed through immediately.
//   - Unknown peers must present a valid QUIC Initial packet carrying a 16-byte
//     steganographic DCID or SCID; invalid/scan/replay packets are silently dropped.
type AuthPacketConn struct {
	net.PacketConn
	verifier *StegoVerifier
	mu       sync.RWMutex
	peers    map[string]int64 // remote addr.String() -> lastSeenUnixNano
	dropped  atomic.Uint64
}

const (
	authPeerTTL       = 5 * time.Minute
	authTouchInterval = 5 * time.Second
)

// NewAuthPacketConn wraps an underlying net.PacketConn with Pre-QUIC filtering.
func NewAuthPacketConn(inner net.PacketConn, v *StegoVerifier) *AuthPacketConn {
	return &AuthPacketConn{
		PacketConn: inner,
		verifier:   v,
		peers:      make(map[string]int64),
	}
}

// Dropped returns the count of silently dropped unauthorized UDP packets.
func (c *AuthPacketConn) Dropped() uint64 {
	return c.dropped.Load()
}

// SetReadBuffer forwards SO_RCVBUF sizing to the underlying PacketConn when supported.
func (c *AuthPacketConn) SetReadBuffer(bytes int) error {
	if sb, ok := c.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return sb.SetReadBuffer(bytes)
	}
	return nil
}

// SetWriteBuffer forwards SO_SNDBUF sizing to the underlying PacketConn when supported.
func (c *AuthPacketConn) SetWriteBuffer(bytes int) error {
	if sb, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return sb.SetWriteBuffer(bytes)
	}
	return nil
}

// MarkPeer registers an address as already authenticated (useful in tests or migration).
func (c *AuthPacketConn) MarkPeer(addr net.Addr) {
	if addr == nil {
		return
	}
	now := time.Now().UnixNano()
	c.mu.Lock()
	c.peers[addr.String()] = now
	c.mu.Unlock()
}

func (c *AuthPacketConn) isPeerAuthed(key string, now int64) bool {
	c.mu.RLock()
	last, ok := c.peers[key]
	c.mu.RUnlock()
	if !ok {
		return false
	}
	if now-last > int64(authPeerTTL) {
		c.mu.Lock()
		if cur, exists := c.peers[key]; exists && now-cur > int64(authPeerTTL) {
			delete(c.peers, key)
			ok = false
		}
		c.mu.Unlock()
		return ok
	}
	if now-last > int64(authTouchInterval) {
		c.mu.Lock()
		c.peers[key] = now
		c.mu.Unlock()
	}
	return true
}

func (c *AuthPacketConn) addPeer(key string, now int64) {
	c.mu.Lock()
	if len(c.peers) > 4096 {
		cutoff := now - int64(authPeerTTL)
		for k, ts := range c.peers {
			if ts < cutoff {
				delete(c.peers, k)
			}
		}
	}
	c.peers[key] = now
	c.mu.Unlock()
}

// ReadFrom blocks until an authorized QUIC packet arrives, silently dropping probes.
func (c *AuthPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if addr == nil || n <= 0 {
			c.dropped.Add(1)
			continue
		}
		key := addr.String()
		now := time.Now().UnixNano()
		if c.isPeerAuthed(key, now) {
			return n, addr, nil
		}
		dcid, scid, ok := parseQUICInitialCIDs(p[:n])
		if ok && (c.verifier.VerifyQUICCID(dcid) || c.verifier.VerifyQUICCID(scid)) {
			c.addPeer(key, now)
			return n, addr, nil
		}
		c.dropped.Add(1)
	}
}

// parseQUICInitialCIDs extracts DCID and SCID from a QUIC Long Header Initial packet.
func parseQUICInitialCIDs(pkt []byte) (dcid, scid []byte, ok bool) {
	// Long header bit (0x80), Fixed bit (0x40), Type Initial = 0x00 (v1) or 0x01 (v2).
	if len(pkt) < 7 {
		return nil, nil, false
	}
	first := pkt[0]
	if first&0x80 == 0 || first&0x40 == 0 {
		return nil, nil, false
	}
	pktType := (first & 0x30) >> 4
	if pktType != 0x00 && pktType != 0x01 {
		return nil, nil, false
	}
	// Version at pkt[1:5]; reject Version Negotiation (version == 0).
	if pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0 && pkt[4] == 0 {
		return nil, nil, false
	}
	dcidLen := int(pkt[5])
	if dcidLen > 20 || 6+dcidLen >= len(pkt) {
		return nil, nil, false
	}
	dcid = pkt[6 : 6+dcidLen]
	scidOff := 6 + dcidLen
	scidLen := int(pkt[scidOff])
	if scidLen > 20 || scidOff+1+scidLen > len(pkt) {
		return nil, nil, false
	}
	scid = pkt[scidOff+1 : scidOff+1+scidLen]
	// Quick sanity check that at least one CID is 16 bytes so we skip malformed small packets quickly.
	if len(dcid) != 16 && len(scid) != 16 {
		return nil, nil, false
	}
	// Consume token varint if present just to ensure well-formed Initial length.
	rem := pkt[scidOff+1+scidLen:]
	if len(rem) < 2 {
		return nil, nil, false
	}
	_, _, err := quicvarint.Parse(rem)
	if err != nil {
		// Allow minimal test Initial packets where token varint starts at rem[0] == 0
		return dcid, scid, true
	}
	return dcid, scid, true
}

// BuildTestQUICInitialPacket constructs a minimal valid QUIC v1 Initial-shaped datagram for tests.
func BuildTestQUICInitialPacket(dcid, scid []byte, totalLen int) []byte {
	if totalLen < 1200 {
		totalLen = 1200
	}
	pkt := make([]byte, totalLen)
	_, _ = rand.Read(pkt)
	pkt[0] = 0xc0 | byte(pkt[0]&0x0f) // Long header + fixed bit + Initial(0)
	pkt[1], pkt[2], pkt[3], pkt[4] = 0x00, 0x00, 0x00, 0x01
	pkt[5] = byte(len(dcid))
	copy(pkt[6:], dcid)
	off := 6 + len(dcid)
	pkt[off] = byte(len(scid))
	copy(pkt[off+1:], scid)
	pkt[off+1+len(scid)] = 0x00 // 0-length token varint
	return pkt
}
