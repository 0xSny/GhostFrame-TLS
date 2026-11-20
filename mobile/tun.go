package mobile

import (
	"errors"
	"sync"

	"ghostframe/internal/tunstack"
)

// TunPacketWriter is implemented by Swift's NEPacketTunnelProvider to inject
// outbound IPv4 packets from Go's gVisor netstack back into iOS packetFlow.
type TunPacketWriter interface {
	WritePacket(pkt []byte, family int)
}

var (
	tunMu    sync.Mutex
	tunStack *tunstack.Stack
)

// StartTUN attaches a memory-bounded gVisor L3/L4 TUN stack to the active mobile Engine.
// It also enables direct CN DNS bypass on the Engine so ActionDirect connections never
// self-resolve against the TUN Fake-IP DNS (198.18.0.1).
func StartTUN(writer TunPacketWriter, mtu int) error {
	if writer == nil {
		return errors.New("mobile: nil TUN packet writer")
	}

	mu.Lock()
	eng := engineInst
	isTunnel := tunnelExtState
	mu.Unlock()
	if eng == nil {
		return errors.New("mobile: engine not started")
	}

	eng.SetDirectDNSBypass(true)
	st, err := tunstack.New(eng, writer, mtu, isTunnel)
	if err != nil {
		return err
	}

	tunMu.Lock()
	old := tunStack
	tunStack = st
	tunMu.Unlock()
	if old != nil {
		old.Close()
	}

	eng.Logf("[TUN] True TUN L3/L4 stack active (MTU=%d, Fake-IP DNS=198.18.0.1, lowMem=%v)", mtu, isTunnel)
	return nil
}

// StartTUNJSON wraps StartTUN into a JSON envelope {"ok":bool,"error":string} for Swift callers.
func StartTUNJSON(writer TunPacketWriter, mtu int) string {
	return marshalEnvelope(StartTUN(writer, mtu), nil)
}

// StopTUN closes the active userspace TUN stack if running.
func StopTUN() {
	tunMu.Lock()
	st := tunStack
	tunStack = nil
	tunMu.Unlock()
	if st != nil {
		st.Close()
	}

	mu.Lock()
	eng := engineInst
	mu.Unlock()
	if eng != nil {
		eng.SetDirectDNSBypass(false)
	}
}

// StopTUNJSON wraps StopTUN into a JSON envelope for Swift callers.
func StopTUNJSON() string {
	StopTUN()
	return marshalEnvelope(nil, nil)
}

// PushTunPacket forwards a single raw IPv4 packet read from iOS NEPacketTunnelFlow into gVisor netstack.
func PushTunPacket(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	tunMu.Lock()
	st := tunStack
	tunMu.Unlock()
	if st != nil {
		st.PushPacket(pkt)
	}
}

func currentTUNStats() *tunstack.Stats {
	tunMu.Lock()
	st := tunStack
	tunMu.Unlock()
	if st == nil {
		return nil
	}
	stats := st.Stats()
	return &stats
}
