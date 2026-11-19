package gftrtc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	mrand "math/rand/v2"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sys/cpu"
)

const (
	// MaxUDPPayload is the outer UDP payload ceiling (safe for PPPoE 1492 MTU zero fragmentation).
	MaxUDPPayload = 1360
	// RTPOverhead = 12B RTP header + 8B masked PktNum + 16B AEAD tag.
	RTPOverhead = 36
	// MaxInnerPlaintext is the maximum plaintext size inside one SRTP packet.
	MaxInnerPlaintext = MaxUDPPayload - RTPOverhead // 1324
	// FECHeaderLen = 4B groupID + 1B idx + 1B count.
	FECHeaderLen = 6
	// MaxFrameArea = MaxInnerPlaintext - FECHeaderLen (when FEC disabled).
	MaxFrameArea = MaxInnerPlaintext - FECHeaderLen // 1318
	// MaxFECFrameArea leaves 2B for the original payload length prefix inside XOR parity.
	MaxFECFrameArea = MaxFrameArea - 2 // 1316

	PTVideoData uint8 = 96
	PTAudioCtrl uint8 = 111

	stunHeaderLen        = 20
	stunMagicCookie      = uint32(0x2112A442)
	stunTypeBindingReq   = uint16(0x0001)
	stunTypeBindingResp  = uint16(0x0101)
	stunTypeBindingInd   = uint16(0x0011)
	stunFingerprintXOR   = uint32(0x5354554E)
	attrUsername         = uint16(0x0006)
	attrXorMappedAddr    = uint16(0x0020)
	attrPriority         = uint16(0x0024)
	attrFingerprint      = uint16(0x8028)
	attrIceControlling   = uint16(0x802A)
	attrGFTTicket        = uint16(0xC057)
	stunTicketMagic      = "GRTC"
	stunSkewSec          = int64(90)
	stunReplayWindowSec  = int64(180)
	DefaultInitWin       = 4 * 1024 * 1024
	DefaultMaxWin        = 16 * 1024 * 1024
	LowMemInitWin        = 1024 * 1024
	LowMemMaxWin         = 4 * 1024 * 1024
	DefaultSocketBufSize = 8 * 1024 * 1024
	LowMemSocketBufSize  = 1024 * 1024

	FlagPreferChaCha20 uint16 = 0x0001

	pktBufCap = 1600
)

const (
	AtypIPv4   = 1
	AtypDomain = 3
	AtypIPv6   = 4
)

var (
	lowMemMode atomic.Bool

	pktBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, pktBufCap)
			return &b
		},
	}
	lowMemPktPool = make(chan *[]byte, 64)
)

// SetLowMemMode configures memory footprint targets for constrained devices.
func SetLowMemMode(on bool) { lowMemMode.Store(on) }

// IsLowMemMode reports whether low-memory mode is enabled.
func IsLowMemMode() bool { return lowMemMode.Load() }

// EffectiveInitStreamWindow returns 4MB by default or 1MB in LowMemMode.
func EffectiveInitStreamWindow() int {
	if lowMemMode.Load() {
		return LowMemInitWin
	}
	return DefaultInitWin
}

// EffectiveMaxStreamWindow returns 16MB by default or 4MB in LowMemMode.
func EffectiveMaxStreamWindow() int {
	if lowMemMode.Load() {
		return LowMemMaxWin
	}
	return DefaultMaxWin
}

// EffectiveUDPSocketBuffer returns 8MB by default or 1MB in LowMemMode.
func EffectiveUDPSocketBuffer() int {
	if lowMemMode.Load() {
		return LowMemSocketBufSize
	}
	return DefaultSocketBufSize
}

// TuneUDPSocketBuffers sets SO_RCVBUF and SO_SNDBUF on a UDP PacketConn.
func TuneUDPSocketBuffers(pc net.PacketConn) {
	if pc == nil {
		return
	}
	sz := EffectiveUDPSocketBuffer()
	if rb, ok := pc.(interface{ SetReadBuffer(int) error }); ok {
		_ = rb.SetReadBuffer(sz)
	}
	if wb, ok := pc.(interface{ SetWriteBuffer(int) error }); ok {
		_ = wb.SetWriteBuffer(sz)
	}
}

// PrioritizeChaCha20 returns true on ARM64 SoCs lacking hardware AES instructions.
func PrioritizeChaCha20() bool {
	return runtime.GOARCH == "arm64" && !cpu.ARM64.HasAES
}

// GetPktBuf obtains a reusable 1600B buffer from pool.
func GetPktBuf() *[]byte {
	if lowMemMode.Load() {
		select {
		case p := <-lowMemPktPool:
			*p = (*p)[:cap(*p)]
			return p
		default:
			b := make([]byte, pktBufCap)
			return &b
		}
	}
	p := pktBufPool.Get().(*[]byte)
	*p = (*p)[:cap(*p)]
	return p
}

// PutPktBuf returns a buffer obtained via GetPktBuf.
func PutPktBuf(p *[]byte) {
	if p == nil || cap(*p) < pktBufCap {
		return
	}
	if lowMemMode.Load() {
		select {
		case lowMemPktPool <- p:
		default:
		}
		return
	}
	pktBufPool.Put(p)
}

// EncodeAddr encodes "host:port" into [atyp | addr | portBE].
func EncodeAddr(hostport string) ([]byte, error) {
	h, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("bad port")
	}
	out := make([]byte, 0, 32)
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

// DecodeAddr parses an encoded address and returns trailing bytes.
func DecodeAddr(b []byte) (hostport string, rest []byte, err error) {
	if len(b) < 1 {
		return "", nil, errors.New("short addr")
	}
	var host string
	var off int
	switch b[0] {
	case AtypIPv4:
		if len(b) < 7 {
			return "", nil, errors.New("short addr")
		}
		host = net.IP(b[1:5]).String()
		off = 5
	case AtypIPv6:
		if len(b) < 19 {
			return "", nil, errors.New("short addr")
		}
		host = net.IP(b[1:17]).String()
		off = 17
	case AtypDomain:
		if len(b) < 2 || b[1] == 0 || len(b) < 2+int(b[1])+2 {
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

func fillFastRandom(b []byte) {
	i := 0
	for ; i+8 <= len(b); i += 8 {
		v := mrand.Uint64()
		binary.LittleEndian.PutUint64(b[i:], v)
	}
	if i < len(b) {
		v := mrand.Uint64()
		for ; i < len(b); i++ {
			b[i] = byte(v)
			v >>= 8
		}
	}
}

func appendSTUNAttr(buf []byte, typ uint16, val []byte) []byte {
	buf = binary.BigEndian.AppendUint16(buf, typ)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(val)))
	buf = append(buf, val...)
	if rem := len(val) & 3; rem != 0 {
		pad := 4 - rem
		for i := 0; i < pad; i++ {
			buf = append(buf, 0)
		}
	}
	return buf
}

func finalizeSTUNWithFingerprint(buf []byte) []byte {
	// Append empty FINGERPRINT header first, update header MessageLength including FINGERPRINT (8B),
	// then compute CRC32-IEEE over all preceding bytes ^ 0x5354554E.
	fpOff := len(buf)
	buf = binary.BigEndian.AppendUint16(buf, attrFingerprint)
	buf = binary.BigEndian.AppendUint16(buf, 4)
	msgLen := len(buf) + 4 - stunHeaderLen
	binary.BigEndian.PutUint16(buf[2:4], uint16(msgLen))
	crc := crc32.ChecksumIEEE(buf[:fpOff]) ^ stunFingerprintXOR
	buf = binary.BigEndian.AppendUint32(buf, crc)
	return buf
}

func verifySTUNBaseAndFingerprint(pkt []byte, expectType uint16) (txID [12]byte, attrs []byte, ok bool) {
	if len(pkt) < stunHeaderLen+8 {
		return txID, nil, false
	}
	msgType := binary.BigEndian.Uint16(pkt[0:2])
	if msgType != expectType {
		return txID, nil, false
	}
	msgLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if msgLen%4 != 0 || stunHeaderLen+msgLen != len(pkt) {
		return txID, nil, false
	}
	if binary.BigEndian.Uint32(pkt[4:8]) != stunMagicCookie {
		return txID, nil, false
	}
	copy(txID[:], pkt[8:20])

	fpOff := len(pkt) - 8
	if binary.BigEndian.Uint16(pkt[fpOff:fpOff+2]) != attrFingerprint ||
		binary.BigEndian.Uint16(pkt[fpOff+2:fpOff+4]) != 4 {
		return txID, nil, false
	}
	wantCRC := crc32.ChecksumIEEE(pkt[:fpOff]) ^ stunFingerprintXOR
	gotCRC := binary.BigEndian.Uint32(pkt[fpOff+4:])
	if gotCRC != wantCRC {
		return txID, nil, false
	}
	return txID, pkt[stunHeaderLen:fpOff], true
}

func findSTUNAttr(attrs []byte, wantType uint16) ([]byte, bool) {
	off := 0
	for off+4 <= len(attrs) {
		t := binary.BigEndian.Uint16(attrs[off : off+2])
		l := int(binary.BigEndian.Uint16(attrs[off+2 : off+4]))
		off += 4
		if off+l > len(attrs) {
			return nil, false
		}
		if t == wantType {
			return attrs[off : off+l], true
		}
		padded := (l + 3) &^ 3
		if off+padded > len(attrs) {
			return nil, false
		}
		off += padded
	}
	return nil, false
}

func hkdfAEADChaCha(secret, salt []byte, info string) (cipher.AEAD, error) {
	r := hkdf.New(sha256.New, secret, salt, []byte(info))
	var k [32]byte
	if _, err := io.ReadFull(r, k[:]); err != nil {
		return nil, err
	}
	return chacha20poly1305.New(k[:])
}

// ReplayGuard rejects replayed STUN client binding requests within a 180-second window.
type ReplayGuard struct {
	mu     sync.Mutex
	seen   map[[20]byte]int64
	lastGC int64
	nowFn  func() time.Time
}

// NewReplayGuard constructs a handshake anti-replay cache.
func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{
		seen:  make(map[[20]byte]int64),
		nowFn: time.Now,
	}
}

func (g *ReplayGuard) checkAndRecord(txID [12]byte, cliPubPrefix []byte, nowUnix int64) bool {
	if g == nil {
		return true
	}
	var key [20]byte
	copy(key[:12], txID[:])
	copy(key[12:20], cliPubPrefix[:8])

	g.mu.Lock()
	defer g.mu.Unlock()
	if nowUnix-g.lastGC >= 30 {
		g.lastGC = nowUnix
		for k, exp := range g.seen {
			if exp <= nowUnix {
				delete(g.seen, k)
			}
		}
	}
	if exp, exists := g.seen[key]; exists && exp > nowUnix {
		return false
	}
	g.seen[key] = nowUnix + stunReplayWindowSec
	return true
}

// SessionKeys holds forward-secret bi-directional AEAD keys, packet-number masks, and IV prefixes.
type SessionKeys struct {
	C2SAEAD    cipher.AEAD
	S2CAEAD    cipher.AEAD
	C2SMask    uint64
	S2CMask    uint64
	C2SIV      [4]byte
	S2CIV      [4]byte
	UseChaCha  bool
	CipherName string
}

func deriveSessionKeys(sharedSecret, psk []byte, txID [12]byte, useChaCha bool) (*SessionKeys, cipher.AEAD, error) {
	ikm := make([]byte, len(sharedSecret)+len(psk))
	copy(ikm, sharedSecret)
	copy(ikm[len(sharedSecret):], psk)

	prk := hkdf.Extract(sha256.New, ikm, txID[:])
	expand := func(info string, out []byte) error {
		r := hkdf.Expand(sha256.New, prk, []byte(info))
		_, err := io.ReadFull(r, out)
		return err
	}

	keyLen := 16
	cipherName := "AES-128-GCM"
	if useChaCha {
		keyLen = 32
		cipherName = "ChaCha20-Poly1305"
	}

	c2sKey := make([]byte, keyLen)
	s2cKey := make([]byte, keyLen)
	var ackKey [32]byte
	var maskBuf [16]byte
	var ivBuf [8]byte

	if err := expand("gftrtc-v1-key-c2s", c2sKey); err != nil {
		return nil, nil, err
	}
	if err := expand("gftrtc-v1-key-s2c", s2cKey); err != nil {
		return nil, nil, err
	}
	if err := expand("gftrtc-v1-s2c-ack", ackKey[:]); err != nil {
		return nil, nil, err
	}
	if err := expand("gftrtc-v1-masks", maskBuf[:]); err != nil {
		return nil, nil, err
	}
	if err := expand("gftrtc-v1-ivs", ivBuf[:]); err != nil {
		return nil, nil, err
	}

	var c2sAEAD, s2cAEAD cipher.AEAD
	var err error
	if useChaCha {
		c2sAEAD, err = chacha20poly1305.New(c2sKey)
		if err != nil {
			return nil, nil, err
		}
		s2cAEAD, err = chacha20poly1305.New(s2cKey)
		if err != nil {
			return nil, nil, err
		}
	} else {
		var bc, bs cipher.Block
		bc, err = aes.NewCipher(c2sKey)
		if err != nil {
			return nil, nil, err
		}
		bs, err = aes.NewCipher(s2cKey)
		if err != nil {
			return nil, nil, err
		}
		c2sAEAD, err = cipher.NewGCM(bc)
		if err != nil {
			return nil, nil, err
		}
		s2cAEAD, err = cipher.NewGCM(bs)
		if err != nil {
			return nil, nil, err
		}
	}

	ackAEAD, err := chacha20poly1305.New(ackKey[:])
	if err != nil {
		return nil, nil, err
	}

	sk := &SessionKeys{
		C2SAEAD:    c2sAEAD,
		S2CAEAD:    s2cAEAD,
		C2SMask:    binary.BigEndian.Uint64(maskBuf[0:8]),
		S2CMask:    binary.BigEndian.Uint64(maskBuf[8:16]),
		UseChaCha:  useChaCha,
		CipherName: cipherName,
	}
	copy(sk.C2SIV[:], ivBuf[0:4])
	copy(sk.S2CIV[:], ivBuf[4:8])
	return sk, ackAEAD, nil
}

func randomICEUser() string {
	const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
	var b [9]byte
	for i := 0; i < 4; i++ {
		b[i] = alpha[mrand.IntN(len(alpha))]
	}
	b[4] = ':'
	for i := 5; i < 9; i++ {
		b[i] = alpha[mrand.IntN(len(alpha))]
	}
	return string(b[:])
}

// BuildClientBindingReq builds an RFC 5389 ICE-STUN Binding Request carrying an
// encrypted ephemeral X25519 + PSK auth ticket inside attribute 0xC057.
func BuildClientBindingReq(psk []byte, clientID [8]byte, maxRxMbps, flags uint16, now time.Time) ([]byte, *ecdh.PrivateKey, [12]byte, error) {
	var txID [12]byte
	if len(psk) < 16 {
		return nil, nil, txID, errors.New("gftrtc: invalid psk length")
	}
	if _, err := io.ReadFull(rand.Reader, txID[:]); err != nil {
		return nil, nil, txID, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, txID, err
	}
	pub := priv.PublicKey().Bytes()

	aead, err := hkdfAEADChaCha(psk, txID[:], "gftrtc-v1-c2s")
	if err != nil {
		return nil, nil, txID, err
	}

	if PrioritizeChaCha20() {
		flags |= FlagPreferChaCha20
	}
	padLen := 16 + mrand.IntN(33) // 16..48
	pt := make([]byte, 24+padLen)
	copy(pt[0:4], stunTicketMagic)
	binary.BigEndian.PutUint64(pt[4:12], uint64(now.Unix()))
	copy(pt[12:20], clientID[:])
	binary.BigEndian.PutUint16(pt[20:22], maxRxMbps)
	binary.BigEndian.PutUint16(pt[22:24], flags)
	fillFastRandom(pt[24:])

	ticket := make([]byte, 32, 32+len(pt)+aead.Overhead())
	copy(ticket, pub)
	ticket = aead.Seal(ticket, txID[:], pt, pub)

	buf := make([]byte, 0, 256)
	buf = binary.BigEndian.AppendUint16(buf, stunTypeBindingReq)
	buf = binary.BigEndian.AppendUint16(buf, 0) // filled in finalize
	buf = binary.BigEndian.AppendUint32(buf, stunMagicCookie)
	buf = append(buf, txID[:]...)

	buf = appendSTUNAttr(buf, attrUsername, []byte(randomICEUser()))
	var iceCtrl [8]byte
	fillFastRandom(iceCtrl[:])
	buf = appendSTUNAttr(buf, attrIceControlling, iceCtrl[:])
	var prio [4]byte
	binary.BigEndian.PutUint32(prio[:], 0x6E001EFF)
	buf = appendSTUNAttr(buf, attrPriority, prio[:])
	buf = appendSTUNAttr(buf, attrGFTTicket, ticket)
	buf = finalizeSTUNWithFingerprint(buf)
	return buf, priv, txID, nil
}

// ParsedClientReq carries verified client authentication metadata from Stage 1 handshake.
type ParsedClientReq struct {
	TxID         [12]byte
	ClientPub    *ecdh.PublicKey
	ClientID     [8]byte
	ClientRxMbps uint16
	ClientFlags  uint16
}

// ParseClientBindingReq validates CRC32 fingerprint, ChaCha20 auth ticket, time skew (±90s), and replay cache.
func ParseClientBindingReq(pkt, psk []byte, guard *ReplayGuard, now time.Time) (*ParsedClientReq, bool) {
	if len(psk) < 16 {
		return nil, false
	}
	txID, attrs, ok := verifySTUNBaseAndFingerprint(pkt, stunTypeBindingReq)
	if !ok {
		return nil, false
	}
	ticket, ok := findSTUNAttr(attrs, attrGFTTicket)
	if !ok || len(ticket) < 32+24+chacha20poly1305.Overhead {
		return nil, false
	}
	pubBytes := ticket[:32]
	cliPub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return nil, false
	}
	aead, err := hkdfAEADChaCha(psk, txID[:], "gftrtc-v1-c2s")
	if err != nil {
		return nil, false
	}
	pt, err := aead.Open(nil, txID[:], ticket[32:], pubBytes)
	if err != nil || len(pt) < 24 {
		return nil, false
	}
	if string(pt[0:4]) != stunTicketMagic {
		return nil, false
	}
	ts := int64(binary.BigEndian.Uint64(pt[4:12]))
	diff := now.Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > stunSkewSec {
		return nil, false
	}
	if !guard.checkAndRecord(txID, pubBytes[:8], now.Unix()) {
		return nil, false
	}
	res := &ParsedClientReq{
		TxID:         txID,
		ClientPub:    cliPub,
		ClientRxMbps: binary.BigEndian.Uint16(pt[20:22]),
		ClientFlags:  binary.BigEndian.Uint16(pt[22:24]),
	}
	copy(res.ClientID[:], pt[12:20])
	return res, true
}

func encodeXorMappedAddr(addr net.Addr, txID [12]byte) []byte {
	var ip net.IP
	var port int
	switch v := addr.(type) {
	case *net.UDPAddr:
		ip = v.IP
		port = v.Port
	default:
		if addr != nil {
			h, ps, err := net.SplitHostPort(addr.String())
			if err == nil {
				ip = net.ParseIP(h)
				port, _ = strconv.Atoi(ps)
			}
		}
	}
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1)
	}
	if v4 := ip.To4(); v4 != nil {
		var val [8]byte
		val[1] = 0x01
		binary.BigEndian.PutUint16(val[2:4], uint16(port)^uint16(stunMagicCookie>>16))
		var cookie [4]byte
		binary.BigEndian.PutUint32(cookie[:], stunMagicCookie)
		for i := 0; i < 4; i++ {
			val[4+i] = v4[i] ^ cookie[i]
		}
		return val[:]
	}
	v6 := ip.To16()
	var val [20]byte
	val[1] = 0x02
	binary.BigEndian.PutUint16(val[2:4], uint16(port)^uint16(stunMagicCookie>>16))
	var mask [16]byte
	binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
	copy(mask[4:16], txID[:])
	for i := 0; i < 16; i++ {
		val[4+i] = v6[i] ^ mask[i]
	}
	return val[:]
}

// BuildServerBindingResp completes ECDH, derives forward-secret session keys, and builds STUN Binding Success Response.
func BuildServerBindingResp(psk []byte, req *ParsedClientReq, clientAddr net.Addr, ssrc uint32, negotiatedTxMbps, serverFlags uint16, paramsJSON []byte) ([]byte, *SessionKeys, error) {
	srvPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	shared, err := srvPriv.ECDH(req.ClientPub)
	if err != nil {
		return nil, nil, err
	}
	useChaCha := (req.ClientFlags&FlagPreferChaCha20 != 0) || (serverFlags&FlagPreferChaCha20 != 0) || PrioritizeChaCha20()
	outFlags := uint16(0)
	if useChaCha {
		outFlags |= FlagPreferChaCha20
	}

	keys, ackAEAD, err := deriveSessionKeys(shared, psk, req.TxID, useChaCha)
	if err != nil {
		return nil, nil, err
	}

	padLen := 16 + mrand.IntN(33)
	pt := make([]byte, 10+len(paramsJSON)+padLen)
	binary.BigEndian.PutUint32(pt[0:4], ssrc)
	binary.BigEndian.PutUint16(pt[4:6], negotiatedTxMbps)
	binary.BigEndian.PutUint16(pt[6:8], outFlags)
	binary.BigEndian.PutUint16(pt[8:10], uint16(len(paramsJSON)))
	copy(pt[10:10+len(paramsJSON)], paramsJSON)
	fillFastRandom(pt[10+len(paramsJSON):])

	srvPub := srvPriv.PublicKey().Bytes()
	ticket := make([]byte, 32, 32+len(pt)+ackAEAD.Overhead())
	copy(ticket, srvPub)
	ticket = ackAEAD.Seal(ticket, req.TxID[:], pt, srvPub)

	buf := make([]byte, 0, 256)
	buf = binary.BigEndian.AppendUint16(buf, stunTypeBindingResp)
	buf = binary.BigEndian.AppendUint16(buf, 0)
	buf = binary.BigEndian.AppendUint32(buf, stunMagicCookie)
	buf = append(buf, req.TxID[:]...)
	buf = appendSTUNAttr(buf, attrXorMappedAddr, encodeXorMappedAddr(clientAddr, req.TxID))
	buf = appendSTUNAttr(buf, attrGFTTicket, ticket)
	buf = finalizeSTUNWithFingerprint(buf)
	return buf, keys, nil
}

// ParsedServerResp carries decrypted Stage 1 handshake response metadata.
type ParsedServerResp struct {
	SessionSSRC      uint32
	NegotiatedTxMbps uint16
	Flags            uint16
	ParamsJSON       []byte
}

// ParseServerBindingResp verifies a server STUN Binding Response and derives SessionKeys.
func ParseServerBindingResp(pkt, psk []byte, cliPriv *ecdh.PrivateKey, expectedTxID [12]byte) (*ParsedServerResp, *SessionKeys, bool) {
	if cliPriv == nil || len(psk) < 16 {
		return nil, nil, false
	}
	txID, attrs, ok := verifySTUNBaseAndFingerprint(pkt, stunTypeBindingResp)
	if !ok || txID != expectedTxID {
		return nil, nil, false
	}
	ticket, ok := findSTUNAttr(attrs, attrGFTTicket)
	if !ok || len(ticket) < 32+10+chacha20poly1305.Overhead {
		return nil, nil, false
	}
	srvPubBytes := ticket[:32]
	srvPub, err := ecdh.X25519().NewPublicKey(srvPubBytes)
	if err != nil {
		return nil, nil, false
	}
	shared, err := cliPriv.ECDH(srvPub)
	if err != nil {
		return nil, nil, false
	}
	// Derive ackAEAD from shared||psk without knowing useChaCha yet; cipher suite is carried inside ack plaintext.
	ikm := make([]byte, len(shared)+len(psk))
	copy(ikm, shared)
	copy(ikm[len(shared):], psk)
	prk := hkdf.Extract(sha256.New, ikm, txID[:])
	var ackKey [32]byte
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("gftrtc-v1-s2c-ack")), ackKey[:]); err != nil {
		return nil, nil, false
	}
	ackAEAD, err := chacha20poly1305.New(ackKey[:])
	if err != nil {
		return nil, nil, false
	}
	pt, err := ackAEAD.Open(nil, txID[:], ticket[32:], srvPubBytes)
	if err != nil || len(pt) < 10 {
		return nil, nil, false
	}
	ssrc := binary.BigEndian.Uint32(pt[0:4])
	txMbps := binary.BigEndian.Uint16(pt[4:6])
	flags := binary.BigEndian.Uint16(pt[6:8])
	pLen := int(binary.BigEndian.Uint16(pt[8:10]))
	if 10+pLen > len(pt) {
		return nil, nil, false
	}
	pj := make([]byte, pLen)
	copy(pj, pt[10:10+pLen])

	useChaCha := flags&FlagPreferChaCha20 != 0
	keys, _, err := deriveSessionKeys(shared, psk, txID, useChaCha)
	if err != nil {
		return nil, nil, false
	}
	return &ParsedServerResp{
		SessionSSRC:      ssrc,
		NegotiatedTxMbps: txMbps,
		Flags:            flags,
		ParamsJSON:       pj,
	}, keys, true
}

// BuildSTUNIndication creates an RFC 5389 Binding Indication (0x0011) keepalive packet with Fingerprint.
func BuildSTUNIndication() []byte {
	var txID [12]byte
	fillFastRandom(txID[:])
	buf := make([]byte, 0, 32)
	buf = binary.BigEndian.AppendUint16(buf, stunTypeBindingInd)
	buf = binary.BigEndian.AppendUint16(buf, 0)
	buf = binary.BigEndian.AppendUint32(buf, stunMagicCookie)
	buf = append(buf, txID[:]...)
	return finalizeSTUNWithFingerprint(buf)
}

// IsValidSTUNIndication validates an RFC 5389 Binding Indication keepalive packet.
func IsValidSTUNIndication(pkt []byte) bool {
	_, _, ok := verifySTUNBaseAndFingerprint(pkt, stunTypeBindingInd)
	return ok
}

// IsRTPPacket checks whether pkt has an RTP v2 header (first two bits == 10b, len >= 36).
func IsRTPPacket(pkt []byte) bool {
	return len(pkt) >= RTPOverhead && (pkt[0]&0xC0) == 0x80
}

// ParseRTPHeaderFields extracts SSRC and masked PktNum without decrypting.
func ParseRTPHeaderFields(pkt []byte) (ssrc uint32, maskedPktNum uint64, ok bool) {
	if !IsRTPPacket(pkt) {
		return 0, 0, false
	}
	ssrc = binary.BigEndian.Uint32(pkt[8:12])
	maskedPktNum = binary.BigEndian.Uint64(pkt[12:20])
	return ssrc, maskedPktNum, true
}

// SealRTP wraps plaintext into an SRTP v2 packet using buf[:MaxUDPPayload] as backing space.
// It returns the sealed slice without heap allocations if cap(buf) >= RTPOverhead + len(plaintext).
func SealRTP(buf []byte, aead cipher.AEAD, iv [4]byte, mask uint64, ssrc uint32, seq uint16, ts90k uint32, pt uint8, marker bool, pktNum uint64, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxInnerPlaintext {
		return nil, fmt.Errorf("gftrtc: plaintext %d exceeds %d", len(plaintext), MaxInnerPlaintext)
	}
	need := 20 + len(plaintext) + aead.Overhead()
	if cap(buf) < need {
		buf = make([]byte, need)
	} else {
		buf = buf[:20]
	}
	buf[0] = 0x80
	b1 := pt & 0x7F
	if marker {
		b1 |= 0x80
	}
	buf[1] = b1
	binary.BigEndian.PutUint16(buf[2:4], seq)
	binary.BigEndian.PutUint32(buf[4:8], ts90k)
	binary.BigEndian.PutUint32(buf[8:12], ssrc)
	binary.BigEndian.PutUint64(buf[12:20], pktNum^mask)

	var nonce [12]byte
	copy(nonce[0:4], iv[:])
	binary.BigEndian.PutUint64(nonce[4:12], pktNum)

	out := aead.Seal(buf[:20], nonce[:], plaintext, buf[:12])
	return out, nil
}

// OpenRTP decrypts an SRTP v2 packet into dst[:0], validating the 12-byte RTP AAD.
func OpenRTP(dst, pkt []byte, aead cipher.AEAD, iv [4]byte, mask uint64) (pktNum uint64, pt []byte, payloadType uint8, marker bool, err error) {
	if !IsRTPPacket(pkt) {
		return 0, nil, 0, false, errors.New("not rtp")
	}
	masked := binary.BigEndian.Uint64(pkt[12:20])
	pktNum = masked ^ mask

	var nonce [12]byte
	copy(nonce[0:4], iv[:])
	binary.BigEndian.PutUint64(nonce[4:12], pktNum)

	pt, err = aead.Open(dst[:0], nonce[:], pkt[20:], pkt[:12])
	if err != nil {
		return 0, nil, 0, false, err
	}
	marker = (pkt[1] & 0x80) != 0
	payloadType = pkt[1] & 0x7F
	return pktNum, pt, payloadType, marker, nil
}
