// Package gft implements the GhostFrame-TLS v2 protocol primitives:
// AEAD Knock v2, RewindConn, Ghost Frame v2, uTLS Dialer, SessionPool, and Multiplexer.
package gft

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	KnockMagic      = "GFT2"
	KnockPrefixLen  = 16 + 32 // 16B Salt + 32B SealedHeader (16B + 16B Tag)
	KnockHeaderLen  = 16
	KnockPadMin     = 192
	KnockPadMax     = 768
	ServerAckPadMin = 128
	ServerAckPadMax = 512

	KnockWindow      = 90 * time.Second
	KnockReplayTTL   = 180 * time.Second
	KnockReadTimeout = 1500 * time.Millisecond
	knockMaxCache    = 200000
)

// KnockResult is the outcome of Knock v2 verification.
type KnockResult int

const (
	KnockOK KnockResult = iota
	KnockBadAuth
	KnockExpired
	KnockReplay
	KnockTimeoutFail
	KnockIncomplete
	KnockHTTPProbe
)

func (r KnockResult) String() string {
	switch r {
	case KnockOK:
		return "ok"
	case KnockBadAuth:
		return "auth"
	case KnockExpired:
		return "expired"
	case KnockReplay:
		return "replay"
	case KnockTimeoutFail:
		return "timeout"
	case KnockIncomplete:
		return "incomplete"
	case KnockHTTPProbe:
		return "web-probe"
	}
	return "unknown"
}

func cryptoRandInt(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	if err != nil {
		return lo
	}
	return lo + int(nBig.Int64())
}

func deriveKnockKey(psk, salt []byte, info string) ([32]byte, error) {
	var key [32]byte
	r := hkdf.New(sha256.New, psk, salt, []byte(info))
	_, err := io.ReadFull(r, key[:])
	return key, err
}

// BuildKnockV2 constructs a complete single-write Knock v2 AEAD packet (240..816 bytes)
// and returns the packet bytes alongside the 16-byte Salt.
func BuildKnockV2(psk []byte, now time.Time, poolFlags uint16) ([]byte, [16]byte, error) {
	var salt [16]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return nil, salt, err
	}
	key, err := deriveKnockKey(psk, salt[:], "gft-v2-knock-c2s")
	if err != nil {
		return nil, salt, err
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, salt, err
	}

	padLen := cryptoRandInt(KnockPadMin, KnockPadMax)
	var plain [KnockHeaderLen]byte
	copy(plain[0:4], KnockMagic)
	binary.BigEndian.PutUint64(plain[4:12], uint64(now.Unix()))
	binary.BigEndian.PutUint16(plain[12:14], uint16(padLen))
	binary.BigEndian.PutUint16(plain[14:16], poolFlags)

	var nonce [chacha20poly1305.NonceSize]byte // 12 zero bytes (Salt ensures unique key per knock)
	out := make([]byte, KnockPrefixLen+padLen)
	copy(out[:16], salt[:])
	aead.Seal(out[16:16], nonce[:], plain[:], salt[:])
	if _, err := io.ReadFull(rand.Reader, out[KnockPrefixLen:]); err != nil {
		return nil, salt, err
	}
	return out, salt, nil
}

// BuildServerAck builds the encrypted ServerAck frame derived via HKDF ("gft-v2-knock-s2c").
func BuildServerAck(psk []byte, salt [16]byte, p Params) ([]byte, error) {
	key, err := deriveKnockKey(psk, salt[:], "gft-v2-knock-s2c")
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	pBytes := MarshalParams(p)
	padLen := cryptoRandInt(ServerAckPadMin, ServerAckPadMax)

	plain := make([]byte, 2+len(pBytes)+2+padLen)
	binary.BigEndian.PutUint16(plain[0:2], uint16(len(pBytes)))
	copy(plain[2:], pBytes)
	binary.BigEndian.PutUint16(plain[2+len(pBytes):4+len(pBytes)], uint16(padLen))
	if _, err := io.ReadFull(rand.Reader, plain[4+len(pBytes):]); err != nil {
		return nil, err
	}

	var nonce [chacha20poly1305.NonceSize]byte
	sealedLen := len(plain) + aead.Overhead()
	frame := make([]byte, 2+sealedLen)
	binary.BigEndian.PutUint16(frame[0:2], uint16(sealedLen))
	aead.Seal(frame[2:2], nonce[:], plain, salt[:])
	return frame, nil
}

// ReadServerAck reads and decrypts the ServerAck frame using the connection's Salt.
func ReadServerAck(r io.Reader, psk []byte, salt [16]byte) (Params, bool, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return Params{}, false, err
	}
	frameLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if frameLen < chacha20poly1305.Overhead+4 || frameLen > 4096 {
		return Params{}, false, errors.New("bad server ack length")
	}
	sealed := make([]byte, frameLen)
	if _, err := io.ReadFull(r, sealed); err != nil {
		return Params{}, false, err
	}
	key, err := deriveKnockKey(psk, salt[:], "gft-v2-knock-s2c")
	if err != nil {
		return Params{}, false, err
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return Params{}, false, err
	}
	var nonce [chacha20poly1305.NonceSize]byte
	plain, err := aead.Open(nil, nonce[:], sealed, salt[:])
	if err != nil || len(plain) < 4 {
		return Params{}, false, errors.New("bad server ack auth")
	}
	pLen := int(binary.BigEndian.Uint16(plain[0:2]))
	if 2+pLen+2 > len(plain) {
		return Params{}, false, errors.New("corrupt server ack params")
	}
	p, err := UnmarshalParams(plain[2 : 2+pLen])
	if err != nil || p.Validate() != nil {
		return Params{}, false, nil
	}
	return p, true, nil
}

// IsHTTPPrefix checks if the initial bytes match an HTTP/1.x request method or HTTP/2 preface.
func IsHTTPPrefix(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	s := string(b)
	prefixes := []string{
		"GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
		"OPTIONS ", "TRACE ", "PATCH ", "CONNECT ",
		"PRI * ",
	}
	for _, m := range prefixes {
		if len(s) >= len(m) && strings.HasPrefix(s, m) {
			return true
		}
		if len(s) < len(m) && strings.HasPrefix(m, s) {
			return true
		}
	}
	return false
}

// KnockVerifier validates Knock v2 packets and maintains the Salt replay cache.
type KnockVerifier struct {
	psk  []byte
	mu   sync.Mutex
	seen map[[16]byte]int64 // salt -> expiry (unix nano)
}

func NewKnockVerifier(psk []byte) *KnockVerifier {
	return &KnockVerifier{
		psk:  append([]byte(nil), psk...),
		seen: make(map[[16]byte]int64, 1024),
	}
}

// CheckPacket validates the first 48 bytes (Salt + SealedHeader) of a Knock v2 packet.
func (v *KnockVerifier) CheckPacket(buf []byte, now time.Time) (salt [16]byte, padLen int, poolFlags uint16, res KnockResult) {
	if len(buf) < KnockPrefixLen {
		return salt, 0, 0, KnockIncomplete
	}
	copy(salt[:], buf[:16])
	key, err := deriveKnockKey(v.psk, salt[:], "gft-v2-knock-c2s")
	if err != nil {
		return salt, 0, 0, KnockBadAuth
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return salt, 0, 0, KnockBadAuth
	}
	var nonce [chacha20poly1305.NonceSize]byte
	var plainBuf [KnockHeaderLen]byte
	plain, err := aead.Open(plainBuf[:0], nonce[:], buf[16:KnockPrefixLen], salt[:])
	if err != nil || len(plain) != KnockHeaderLen || string(plain[0:4]) != KnockMagic {
		return salt, 0, 0, KnockBadAuth
	}

	ts := int64(binary.BigEndian.Uint64(plain[4:12]))
	padLen = int(binary.BigEndian.Uint16(plain[12:14]))
	poolFlags = binary.BigEndian.Uint16(plain[14:16])
	if padLen < KnockPadMin || padLen > KnockPadMax {
		return salt, 0, 0, KnockBadAuth
	}

	d := now.Unix() - ts
	if d < 0 {
		d = -d
	}
	if d > int64(KnockWindow/time.Second) {
		return salt, 0, 0, KnockExpired
	}

	nowN := now.UnixNano()
	v.mu.Lock()
	defer v.mu.Unlock()
	if exp, ok := v.seen[salt]; ok && exp > nowN {
		return salt, 0, 0, KnockReplay
	}
	if len(v.seen) >= knockMaxCache {
		v.sweepLocked(nowN)
		if len(v.seen) >= knockMaxCache {
			return salt, 0, 0, KnockReplay
		}
	}
	v.seen[salt] = nowN + int64(KnockReplayTTL)
	return salt, padLen, poolFlags, KnockOK
}

func (v *KnockVerifier) sweepLocked(nowN int64) {
	for k, exp := range v.seen {
		if exp <= nowN {
			delete(v.seen, k)
		}
	}
}

// Sweep removes expired salts (call periodically).
func (v *KnockVerifier) Sweep(now time.Time) {
	v.mu.Lock()
	v.sweepLocked(now.UnixNano())
	v.mu.Unlock()
}

// CacheSize returns the current replay cache size.
func (v *KnockVerifier) CacheSize() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.seen)
}

// VerifyFirstRead performs zero-delay sniffing using a single Read() call on rc.
// On failure, rc preserves every read byte for lossless Rewind() fallback without blocking.
func (v *KnockVerifier) VerifyFirstRead(rc *RewindConn, now time.Time) (salt [16]byte, poolFlags uint16, res KnockResult) {
	_ = rc.SetReadDeadline(time.Now().Add(KnockReadTimeout))
	var buf [1024]byte
	n, err := rc.Read(buf[:])
	if n == 0 {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return salt, 0, KnockTimeoutFail
		}
		return salt, 0, KnockIncomplete
	}

	if IsHTTPPrefix(buf[:n]) {
		return salt, 0, KnockHTTPProbe
	}

	if n < KnockPrefixLen {
		return salt, 0, KnockIncomplete
	}

	salt, padLen, poolFlags, res := v.CheckPacket(buf[:n], now)
	if res != KnockOK {
		return salt, 0, res
	}

	totalNeeded := KnockPrefixLen + padLen
	if n < totalNeeded {
		rem := totalNeeded - n
		junk := make([]byte, rem)
		if _, err := io.ReadFull(rc, junk); err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return salt, 0, KnockTimeoutFail
			}
			return salt, 0, KnockIncomplete
		}
	}
	rc.ConsumePrefix(totalNeeded)
	_ = rc.SetReadDeadline(time.Time{})
	return salt, poolFlags, KnockOK
}
