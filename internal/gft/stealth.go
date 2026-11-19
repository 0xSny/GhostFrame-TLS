package gft

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	stegoBucketSeconds   int64 = 30
	stegoReplayWindowSec int64 = 180
	inspectTimeout             = 1500 * time.Millisecond
)

var (
	errBadClientAuth = errors.New("gft: bad client auth frame")
	errBadServerAck  = errors.New("gft: bad server ack")
)

// StegoVerifier validates Pre-TLS SessionID steganography, Pre-QUIC CID tags,
// and post-TLS AEAD ClientAuthFrames while preventing Salt replay within 180s.
type StegoVerifier struct {
	psk   []byte
	nowFn func() time.Time

	mu       sync.Mutex
	sidSeen  map[[16]byte]int64
	qcidSeen map[[8]byte]int64
	authSeen map[[16]byte]int64
	lastGC   int64
}

// NewStegoVerifier builds a verifier bound to PSK.
func NewStegoVerifier(psk []byte) *StegoVerifier {
	cp := make([]byte, len(psk))
	copy(cp, psk)
	return &StegoVerifier{
		psk:      cp,
		nowFn:    time.Now,
		sidSeen:  make(map[[16]byte]int64),
		qcidSeen: make(map[[8]byte]int64),
		authSeen: make(map[[16]byte]int64),
	}
}

func (v *StegoVerifier) now() time.Time {
	if v != nil && v.nowFn != nil {
		return v.nowFn()
	}
	return time.Now()
}

// MakeStegoSessionID produces a 32-byte random-looking SessionID bound to clientRandom.
func MakeStegoSessionID(psk, clientRandom []byte, now time.Time) ([32]byte, error) {
	var sid [32]byte
	if len(psk) < 16 || len(clientRandom) != 32 {
		return sid, errors.New("invalid stego sid inputs")
	}
	if _, err := io.ReadFull(rand.Reader, sid[:16]); err != nil {
		return sid, err
	}
	bucket := uint64(now.Unix() / stegoBucketSeconds)
	tag := computeSessionIDTag(psk, sid[:16], clientRandom, bucket)
	copy(sid[16:32], tag[:])
	return sid, nil
}

func computeSessionIDTag(psk, salt, clientRandom []byte, bucket uint64) [16]byte {
	var bbuf [8]byte
	binary.BigEndian.PutUint64(bbuf[:], bucket)
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte("gft-v3-sid"))
	_, _ = mac.Write(salt)
	_, _ = mac.Write(clientRandom)
	_, _ = mac.Write(bbuf[:])
	var full [32]byte
	sum := mac.Sum(full[:0])
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

// InjectStegoSessionID populates Hello.SessionId with the stego tag bound to uTLS ClientRandom.
func InjectStegoSessionID(uc *utls.UConn, psk []byte, now time.Time) error {
	if err := uc.BuildHandshakeState(); err != nil {
		return err
	}
	rnd := uc.HandshakeState.Hello.Random
	if len(rnd) != 32 {
		return errors.New("unexpected uTLS client random length")
	}
	sid, err := MakeStegoSessionID(psk, rnd, now)
	if err != nil {
		return err
	}
	uc.HandshakeState.Hello.SessionId = sid[:]
	uc.HandshakeState.Hello.Raw = nil
	return nil
}

// VerifySessionID validates the 32-byte SessionID against ClientRandom with replay cache.
func (v *StegoVerifier) VerifySessionID(sessionID, clientRandom []byte) bool {
	if len(sessionID) != 32 || len(clientRandom) != 32 {
		return false
	}
	nowUnix := v.now().Unix()
	baseBucket := nowUnix / stegoBucketSeconds
	saltSlice := sessionID[:16]
	tagSlice := sessionID[16:32]

	matched := false
	for _, delta := range [3]int64{-1, 0, 1} {
		b := baseBucket + delta
		if b < 0 {
			continue
		}
		exp := computeSessionIDTag(v.psk, saltSlice, clientRandom, uint64(b))
		if hmac.Equal(exp[:], tagSlice) {
			matched = true
		}
	}
	if !matched {
		return false
	}

	var saltKey [16]byte
	copy(saltKey[:], saltSlice)
	v.mu.Lock()
	defer v.mu.Unlock()
	v.gcLocked(nowUnix)
	if exp, dup := v.sidSeen[saltKey]; dup && exp > nowUnix {
		return false
	}
	v.sidSeen[saltKey] = nowUnix + stegoReplayWindowSec
	return true
}

// MakeStegoQUICCID produces a 16-byte random-looking QUIC Connection ID: Salt(8B) || Tag(8B).
func MakeStegoQUICCID(psk []byte, now time.Time) ([16]byte, error) {
	var cid [16]byte
	if len(psk) < 16 {
		return cid, errors.New("invalid psk")
	}
	if _, err := io.ReadFull(rand.Reader, cid[:8]); err != nil {
		return cid, err
	}
	bucket := uint64(now.Unix() / stegoBucketSeconds)
	tag := computeQUICCIDTag(psk, cid[:8], bucket)
	copy(cid[8:16], tag[:])
	return cid, nil
}

func computeQUICCIDTag(psk, salt []byte, bucket uint64) [8]byte {
	var bbuf [8]byte
	binary.BigEndian.PutUint64(bbuf[:], bucket)
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte("gft-v3-qcid"))
	_, _ = mac.Write(salt)
	_, _ = mac.Write(bbuf[:])
	var full [32]byte
	sum := mac.Sum(full[:0])
	var out [8]byte
	copy(out[:], sum[:8])
	return out
}

// VerifyQUICCID verifies a 16-byte QUIC CID and records its 8B salt against replay.
func (v *StegoVerifier) VerifyQUICCID(cid []byte) bool {
	if len(cid) != 16 {
		return false
	}
	nowUnix := v.now().Unix()
	baseBucket := nowUnix / stegoBucketSeconds
	saltSlice := cid[:8]
	tagSlice := cid[8:16]

	matched := false
	for _, delta := range [3]int64{-1, 0, 1} {
		b := baseBucket + delta
		if b < 0 {
			continue
		}
		exp := computeQUICCIDTag(v.psk, saltSlice, uint64(b))
		if hmac.Equal(exp[:], tagSlice) {
			matched = true
		}
	}
	if !matched {
		return false
	}

	var saltKey [8]byte
	copy(saltKey[:], saltSlice)
	v.mu.Lock()
	defer v.mu.Unlock()
	v.gcLocked(nowUnix)
	if exp, dup := v.qcidSeen[saltKey]; dup && exp > nowUnix {
		return false
	}
	v.qcidSeen[saltKey] = nowUnix + stegoReplayWindowSec
	return true
}

func (v *StegoVerifier) gcLocked(nowUnix int64) {
	if nowUnix-v.lastGC < 30 {
		return
	}
	v.lastGC = nowUnix
	for k, exp := range v.sidSeen {
		if exp <= nowUnix {
			delete(v.sidSeen, k)
		}
	}
	for k, exp := range v.qcidSeen {
		if exp <= nowUnix {
			delete(v.qcidSeen, k)
		}
	}
	for k, exp := range v.authSeen {
		if exp <= nowUnix {
			delete(v.authSeen, k)
		}
	}
}

// MirrorInspector sniffs the first TLS ClientHello on rc (reassembling fragmented
// TLS handshake records cleanly within 1500ms). Regardless of pass or fail, rc
// is rewound before returning so tls.Server or bidirectional fallback sees every byte.
func MirrorInspector(rc *RewindConn, v *StegoVerifier) bool {
	if rc == nil || v == nil {
		return false
	}
	_ = rc.SetReadDeadline(time.Now().Add(inspectTimeout))
	defer func() {
		_ = rc.SetReadDeadline(time.Time{})
		rc.Rewind()
	}()

	var hdr [5]byte
	hsBuf := make([]byte, 0, 96)
	need := 71 // handshake hdr(4) + legacy_ver(2) + random(32) + sid_len(1) + sid(32)

	for len(hsBuf) < need {
		if _, err := io.ReadFull(rc, hdr[:]); err != nil {
			return false
		}
		if hdr[0] != 0x16 || hdr[1] != 0x03 {
			return false
		}
		recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		if recLen <= 0 || recLen > 16384 {
			return false
		}
		chunk := make([]byte, recLen)
		if _, err := io.ReadFull(rc, chunk); err != nil {
			return false
		}
		hsBuf = append(hsBuf, chunk...)
		if len(hsBuf) >= 1 && hsBuf[0] != 0x01 {
			return false
		}
		if len(hsBuf) >= 39 {
			sidLen := int(hsBuf[38])
			if sidLen != 32 {
				return false
			}
		}
		if len(hsBuf) > 16384 {
			return false
		}
	}
	clientRandom := hsBuf[6:38]
	sidLen := int(hsBuf[38])
	if sidLen != 32 || len(hsBuf) < 39+32 {
		return false
	}
	sessionID := hsBuf[39 : 39+32]
	return v.VerifySessionID(sessionID, clientRandom)
}

func deriveAuthAEAD(psk, salt []byte, info string) (cipher.AEAD, error) {
	r := hkdf.New(sha256.New, psk, salt, []byte(info))
	var key [32]byte
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return nil, err
	}
	return chacha20poly1305.New(key[:])
}

// DefaultClientID is a process-wide random 8-byte client session-group ID
// shared across QUIC hops and TCP failovers so server NAT bindings persist.
var DefaultClientID = func() [8]byte {
	var id [8]byte
	_, _ = io.ReadFull(rand.Reader, id[:])
	return id
}()

// BuildClientAuthFrame builds the post-TLS encrypted authentication frame using DefaultClientID.
func BuildClientAuthFrame(psk []byte, now time.Time) ([]byte, []byte, error) {
	return BuildClientAuthFrameWithID(psk, now, DefaultClientID)
}

// BuildClientAuthFrameWithID builds the 22B-plaintext encrypted ClientAuthFrame:
// [Salt 16B][Sealed(Magic="GFT3"(4B) | Timestamp uint64BE(8B) | PadLen uint16(2B) | ClientID 8B)][RandomPad]
func BuildClientAuthFrameWithID(psk []byte, now time.Time, clientID [8]byte) ([]byte, []byte, error) {
	var salt [16]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return nil, nil, err
	}
	padLen := randRange(64, 256)
	out := make([]byte, 16+22+16+padLen)
	copy(out[:16], salt[:])

	var pt [22]byte
	copy(pt[:4], "GFT3")
	binary.BigEndian.PutUint64(pt[4:12], uint64(now.Unix()))
	binary.BigEndian.PutUint16(pt[12:14], uint16(padLen))
	copy(pt[14:22], clientID[:])

	aead, err := deriveAuthAEAD(psk, salt[:], "gft-v3-auth")
	if err != nil {
		return nil, nil, err
	}
	var nonce [12]byte
	aead.Seal(out[16:16], nonce[:], pt[:], salt[:])
	fillRandom(out[16+38:])
	return out, salt[:], nil
}

// VerifyClientAuthFrame reads and verifies a ClientAuthFrame (14B or 22B plaintext).
func (v *StegoVerifier) VerifyClientAuthFrame(r io.Reader) ([]byte, error) {
	salt, _, err := v.VerifyClientAuthFrameWithID(r)
	return salt, err
}

// VerifyClientAuthFrameWithID reads and verifies a 14B (legacy) or 22B (with 8B ClientID)
// post-TLS ClientAuthFrame, returning its 16B salt and 8B ClientID.
func (v *StegoVerifier) VerifyClientAuthFrameWithID(r io.Reader) ([]byte, [8]byte, error) {
	var clientID [8]byte
	var hdr [54]byte // 16B salt + up to 22B pt + 16B tag
	if _, err := io.ReadFull(r, hdr[:46]); err != nil {
		return nil, clientID, err
	}
	salt := make([]byte, 16)
	copy(salt, hdr[:16])

	aead, err := deriveAuthAEAD(v.psk, salt, "gft-v3-auth")
	if err != nil {
		return nil, clientID, err
	}
	var nonce [12]byte
	pt, err := aead.Open(nil, nonce[:], hdr[16:46], salt)
	if err != nil || len(pt) != 14 {
		// Try 22-byte format (+8 bytes ciphertext)
		if _, err2 := io.ReadFull(r, hdr[46:54]); err2 != nil {
			return nil, clientID, errBadClientAuth
		}
		pt, err = aead.Open(nil, nonce[:], hdr[16:54], salt)
		if err != nil || len(pt) != 22 {
			return nil, clientID, errBadClientAuth
		}
		copy(clientID[:], pt[14:22])
	}
	if string(pt[:4]) != "GFT3" {
		return nil, clientID, errBadClientAuth
	}
	ts := int64(binary.BigEndian.Uint64(pt[4:12]))
	nowUnix := v.now().Unix()
	diff := nowUnix - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > 90 {
		return nil, clientID, errBadClientAuth
	}
	padLen := int(binary.BigEndian.Uint16(pt[12:14]))
	if padLen > 4096 {
		return nil, clientID, errBadClientAuth
	}
	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
			return nil, clientID, err
		}
	}

	var saltKey [16]byte
	copy(saltKey[:], salt)
	v.mu.Lock()
	defer v.mu.Unlock()
	v.gcLocked(nowUnix)
	if exp, dup := v.authSeen[saltKey]; dup && exp > nowUnix {
		return nil, clientID, errBadClientAuth
	}
	v.authSeen[saltKey] = nowUnix + stegoReplayWindowSec
	return salt, clientID, nil
}

// BuildServerAuthAck builds encrypted Params ack bound to the client's 16B auth salt.
func BuildServerAuthAck(psk, clientSalt []byte, p Params) ([]byte, error) {
	pj, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	aead, err := deriveAuthAEAD(psk, clientSalt, "gft-v3-ack")
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	padLen := randRange(16, 128)
	sealed := aead.Seal(nil, nonce[:], pj, clientSalt)
	// Format: [Nonce 12B][EncLen uint16][EncParams][PadLen uint16][RandomPad]
	out := make([]byte, 12+2+len(sealed)+2+padLen)
	copy(out[:12], nonce[:])
	binary.BigEndian.PutUint16(out[12:14], uint16(len(sealed)))
	copy(out[14:14+len(sealed)], sealed)
	binary.BigEndian.PutUint16(out[14+len(sealed):16+len(sealed)], uint16(padLen))
	fillRandom(out[16+len(sealed):])
	return out, nil
}

// ReadServerAuthAck decrypts the server's Params acknowledgement.
func ReadServerAuthAck(r io.Reader, psk, clientSalt []byte) (Params, error) {
	var hdr [14]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Params{}, err
	}
	encLen := int(binary.BigEndian.Uint16(hdr[12:14]))
	if encLen < 16 || encLen > 4096 {
		return Params{}, errBadServerAck
	}
	buf := make([]byte, encLen+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Params{}, err
	}
	padLen := int(binary.BigEndian.Uint16(buf[encLen:]))
	if padLen > 4096 {
		return Params{}, errBadServerAck
	}
	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
			return Params{}, err
		}
	}
	aead, err := deriveAuthAEAD(psk, clientSalt, "gft-v3-ack")
	if err != nil {
		return Params{}, err
	}
	pt, err := aead.Open(nil, hdr[:12], buf[:encLen], clientSalt)
	if err != nil {
		return Params{}, errBadServerAck
	}
	p, err := UnmarshalParams(pt)
	if err != nil {
		return Params{}, err
	}
	return p, nil
}
