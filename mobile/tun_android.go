//go:build android

package mobile

import (
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

type androidTUNBridge struct {
	file      *os.File
	closeOnce sync.Once
	closed    atomic.Bool
}

func (b *androidTUNBridge) WritePacket(pkt []byte, _ int) {
	if b.closed.Load() || len(pkt) == 0 {
		return
	}
	_, _ = b.file.Write(pkt)
}

func (b *androidTUNBridge) WritePacketBatch(concat []byte, lens []byte, count int, _ int) {
	if b.closed.Load() || count <= 0 || len(lens) < count*2 {
		return
	}
	off := 0
	for i := 0; i < count; i++ {
		n := int(binary.BigEndian.Uint16(lens[i*2 : i*2+2]))
		if n <= 0 || off+n > len(concat) {
			break
		}
		_, _ = b.file.Write(concat[off : off+n])
		off += n
	}
}

func (b *androidTUNBridge) Close() {
	b.closeOnce.Do(func() {
		b.closed.Store(true)
		_ = b.file.Close()
	})
}

// StartTUNWithFD attaches Go's gVisor TUN stack directly to an Android VpnService
// TUN file descriptor (eliminating per-packet JNI boundary overhead).
// It duplicates fd so the Java/Kotlin caller retains ownership of its ParcelFileDescriptor.
func StartTUNWithFD(fd int, mtu int) error {
	if fd < 0 {
		return errors.New("mobile: invalid Android TUN fd")
	}
	if mtu < 576 || mtu > 9000 {
		mtu = 1400
	}
	dupFD, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	if err := unix.SetNonblock(dupFD, true); err != nil {
		_ = unix.Close(dupFD)
		return err
	}
	f := os.NewFile(uintptr(dupFD), "kestrel-tun")
	if f == nil {
		_ = unix.Close(dupFD)
		return errors.New("mobile: failed to wrap Android TUN fd")
	}

	bridge := &androidTUNBridge{file: f}
	if err := StartTUN(bridge, mtu); err != nil {
		bridge.Close()
		return err
	}
	setTUNCloseHook(bridge.Close)

	go func(br *androidTUNBridge, bufSize int) {
		buf := make([]byte, bufSize)
		for !br.closed.Load() {
			n, rerr := br.file.Read(buf)
			if n > 0 {
				PushTunPacket(buf[:n])
			}
			if rerr != nil {
				return
			}
		}
	}(bridge, mtu+128)

	return nil
}

// StartTUNWithFDJSON wraps StartTUNWithFD into a JSON envelope for Kotlin callers.
func StartTUNWithFDJSON(fd int, mtu int) string {
	return marshalEnvelope(StartTUNWithFD(fd, mtu), nil)
}
