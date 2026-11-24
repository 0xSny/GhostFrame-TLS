package gft

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"sync"
	"time"

	"ghostframe/internal/sni"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	tlsCipherAES128GCM uint16 = 0x1301
	tlsCipherAES256GCM uint16 = 0x1302
	tlsCipherChaCha20  uint16 = 0x1303

	tlsGroupP256          uint16 = 0x0017
	tlsGroupX25519        uint16 = 0x001d
	tlsGroupX25519MLKEM   uint16 = 0x11ec
	mlkem768EncapKeyBytes        = 1184
	x25519PubKeyBytes            = 32

	tlsExtServerName        uint16 = 0x0000
	tlsExtSigAlgorithms     uint16 = 0x000d
	tlsExtALPN              uint16 = 0x0010
	tlsExtSupportedVersions uint16 = 0x002b
	tlsExtPSKModes          uint16 = 0x002d
	tlsExtKeyShare          uint16 = 0x0033

	sigECDSAP256SHA256 uint16 = 0x0403
	sigECDSAP384SHA384 uint16 = 0x0503
	sigRSAPSSSHA256    uint16 = 0x0804
	sigRSAPSSSHA384    uint16 = 0x0805
	sigEd25519         uint16 = 0x0807

	shadowMaxRecordPlain = 16384
	shadowPoolBufSize    = shadowMaxRecordPlain + 256
)

var (
	// RFC 8446 §4.1.3 downgrade sentinels & HRR random.
	tls12DowngradeSentinel = [8]byte{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01}
	tls11DowngradeSentinel = [8]byte{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00}
	hrrRandomSentinel      = [32]byte{
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
		0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
		0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
	}

	shadowRecordBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, shadowPoolBufSize)
			return &b
		},
	}
)

type parsedClientHello struct {
	rawHandshake []byte
	random       [32]byte
	sessionID    []byte
	ciphers      []uint16
	supports13   bool
	keyShares    map[uint16][]byte
	alpnList     []string
	sigAlgs      []uint16
	hasPSKModes  bool
}

type tls13SuiteSpec struct {
	id     uint16
	hashID crypto.Hash
	keyLen int
	ivLen  int
}

func lookupTLS13Suite(id uint16) (tls13SuiteSpec, bool) {
	switch id {
	case tlsCipherAES128GCM:
		return tls13SuiteSpec{id: id, hashID: crypto.SHA256, keyLen: 16, ivLen: 12}, true
	case tlsCipherAES256GCM:
		return tls13SuiteSpec{id: id, hashID: crypto.SHA384, keyLen: 32, ivLen: 12}, true
	case tlsCipherChaCha20:
		return tls13SuiteSpec{id: id, hashID: crypto.SHA256, keyLen: 32, ivLen: 12}, true
	default:
		return tls13SuiteSpec{}, false
	}
}

func newHashForSuite(s tls13SuiteSpec) hash.Hash {
	if s.hashID == crypto.SHA384 {
		return sha512.New384()
	}
	return sha256.New()
}

func newAEADForSuite(s tls13SuiteSpec, key []byte) (cipher.AEAD, error) {
	if s.id == tlsCipherChaCha20 {
		return chacha20poly1305.New(key)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func hkdfExtract(hFn func() hash.Hash, salt, ikm []byte) []byte {
	return hkdf.Extract(hFn, ikm, salt)
}

func hkdfExpandLabel(hFn func() hash.Hash, secret []byte, label string, ctxData []byte, length int) []byte {
	fullLabel := "tls13 " + label
	info := make([]byte, 2+1+len(fullLabel)+1+len(ctxData))
	binary.BigEndian.PutUint16(info[0:2], uint16(length))
	info[2] = byte(len(fullLabel))
	copy(info[3:], fullLabel)
	info[3+len(fullLabel)] = byte(len(ctxData))
	copy(info[4+len(fullLabel):], ctxData)

	out := make([]byte, length)
	r := hkdf.Expand(hFn, secret, info)
	_, _ = io.ReadFull(r, out)
	return out
}

func deriveSecret(hFn func() hash.Hash, hashLen int, secret []byte, label string, msgsHash []byte) []byte {
	return hkdfExpandLabel(hFn, secret, label, msgsHash, hashLen)
}

func hmacDigest(hFn func() hash.Hash, key, data []byte) []byte {
	m := hmac.New(hFn, key)
	_, _ = m.Write(data)
	return m.Sum(nil)
}

// PerformShadowTLS13Server performs an RFC 8446 TLS 1.3 handshake aligned to the passive
// ServerHello, CCS, Flight 2 record sizing, ALPN, and NewSessionTicket pattern captured from
// CamouflageTarget, while using the server's leaf certificate and private key (SPKI Pin invariant).
// If the ClientHello or CamouflageProfile cannot be satisfied cleanly (e.g. unsupported extensions,
// cipher/curve mismatch, or HRR), it rewinds the connection before writing any byte and falls back
// to stdlib tls.Server configured with matching CurvePreferences.
func PerformShadowTLS13Server(ctx context.Context, rawConn net.Conn, leafCertDER []byte, signer crypto.Signer, profile *sni.CamouflageProfile) (net.Conn, string, error) {
	if rawConn == nil {
		return nil, "", errors.New("gft: nil rawConn")
	}

	deadline := time.Now().Add(10 * time.Second)
	if dl, ok := ctx.Deadline(); ok {
		deadline = dl
	}
	_ = rawConn.SetDeadline(deadline)
	clearDeadline := false
	defer func() {
		if clearDeadline {
			_ = rawConn.SetDeadline(time.Time{})
		}
	}()

	if len(leafCertDER) == 0 || signer == nil || profile == nil {
		c, alpn, err := fallbackStdlibTLSServer(ctx, rawConn, leafCertDER, signer, profile)
		if err == nil {
			clearDeadline = true
		}
		return c, alpn, err
	}

	rc := NewRewindConn(rawConn)
	runRewoundFallback := func() (net.Conn, string, error) {
		c, alpn, ferr := fallbackRewoundStdlibTLSServer(ctx, rc, leafCertDER, signer, profile)
		if ferr == nil {
			clearDeadline = true
		}
		return c, alpn, ferr
	}

	ch, err := readClientHelloFromConn(ctx, rc)
	if err != nil {
		return nil, "", err
	}

	spec, okSuite := lookupTLS13Suite(profile.CipherSuite)
	extOrder := profile.ServerHelloExtOrder
	if len(extOrder) == 0 {
		extOrder = []uint16{tlsExtSupportedVersions, tlsExtKeyShare}
	}
	if !okSuite || !ch.supports13 || !containsUint16(ch.ciphers, spec.id) || !extOrderSupported(extOrder) {
		return runRewoundFallback()
	}

	selectedGroup, peerShare, okShare := selectKeyShareGroup(profile.KeyShareGroup, ch.keyShares)
	if !okShare {
		return runRewoundFallback()
	}
	srvShare, sharedSecret, err := computeServerKeyShare(selectedGroup, peerShare)
	if err != nil {
		return runRewoundFallback()
	}

	sigScheme, sigHash, err := pickSignatureScheme(signer, ch.sigAlgs)
	if err != nil {
		return runRewoundFallback()
	}

	selectedALPN := selectProfileALPN(profile.ALPN, ch.alpnList)
	var srvRandom [32]byte
	for {
		if _, err := io.ReadFull(rand.Reader, srvRandom[:]); err != nil {
			return nil, "", err
		}
		if !bytes.Equal(srvRandom[:], hrrRandomSentinel[:]) &&
			!bytes.Equal(srvRandom[24:], tls12DowngradeSentinel[:]) &&
			!bytes.Equal(srvRandom[24:], tls11DowngradeSentinel[:]) {
			break
		}
	}

	shBody := buildServerHelloBody(srvRandom, ch.sessionID, spec.id, selectedGroup, srvShare, extOrder)
	shHandshake := wrapHandshakeMsg(0x02, shBody)

	hFn := func() hash.Hash { return newHashForSuite(spec) }
	transcript := newHashForSuite(spec)
	_, _ = transcript.Write(ch.rawHandshake)
	_, _ = transcript.Write(shHandshake)
	chSHHash := transcript.Sum(nil)

	hashLen := transcript.Size()
	zeroKey := make([]byte, hashLen)
	earlySecret := hkdfExtract(hFn, zeroKey, zeroKey)
	emptyHash := hFn().Sum(nil)
	derived1 := deriveSecret(hFn, hashLen, earlySecret, "derived", emptyHash)
	handshakeSecret := hkdfExtract(hFn, derived1, sharedSecret)

	cHsTraffic := deriveSecret(hFn, hashLen, handshakeSecret, "c hs traffic", chSHHash)
	sHsTraffic := deriveSecret(hFn, hashLen, handshakeSecret, "s hs traffic", chSHHash)

	sHsKey := hkdfExpandLabel(hFn, sHsTraffic, "key", nil, spec.keyLen)
	sHsIV := hkdfExpandLabel(hFn, sHsTraffic, "iv", nil, spec.ivLen)
	cHsKey := hkdfExpandLabel(hFn, cHsTraffic, "key", nil, spec.keyLen)
	cHsIV := hkdfExpandLabel(hFn, cHsTraffic, "iv", nil, spec.ivLen)

	sHsAEAD, err := newAEADForSuite(spec, sHsKey)
	if err != nil {
		return runRewoundFallback()
	}
	cHsAEAD, err := newAEADForSuite(spec, cHsKey)
	if err != nil {
		return runRewoundFallback()
	}

	eeMsg := buildEncryptedExtensionsMsg(selectedALPN)
	certMsg := buildCertificateMsg(leafCertDER)
	_, _ = transcript.Write(eeMsg)
	_, _ = transcript.Write(certMsg)
	certTranscriptHash := transcript.Sum(nil)

	cvMsg, err := buildCertificateVerifyMsg(signer, sigScheme, sigHash, certTranscriptHash)
	if err != nil {
		return runRewoundFallback()
	}
	_, _ = transcript.Write(cvMsg)
	cvTranscriptHash := transcript.Sum(nil)

	sFinKey := hkdfExpandLabel(hFn, sHsTraffic, "finished", nil, hashLen)
	sVerifyData := hmacDigest(hFn, sFinKey, cvTranscriptHash)
	finMsg := wrapHandshakeMsg(0x14, sVerifyData)
	_, _ = transcript.Write(finMsg)
	sFinTranscriptHash := transcript.Sum(nil)

	derived2 := deriveSecret(hFn, hashLen, handshakeSecret, "derived", emptyHash)
	masterSecret := hkdfExtract(hFn, derived2, zeroKey)
	cAppTraffic := deriveSecret(hFn, hashLen, masterSecret, "c ap traffic", sFinTranscriptHash)
	sAppTraffic := deriveSecret(hFn, hashLen, masterSecret, "s ap traffic", sFinTranscriptHash)

	hsPlain := make([]byte, 0, len(eeMsg)+len(certMsg)+len(cvMsg)+len(finMsg))
	hsPlain = append(hsPlain, eeMsg...)
	hsPlain = append(hsPlain, certMsg...)
	hsPlain = append(hsPlain, cvMsg...)
	hsPlain = append(hsPlain, finMsg...)

	// Stop recording before writing ServerHello: past this point we own the wire state.
	rc.StopRecording()

	var flightBuf bytes.Buffer
	flightBuf.Grow(5 + len(shHandshake) + 6 + len(hsPlain) + 4096)
	appendPlainRecord(&flightBuf, 0x16, shHandshake)
	if profile.SendCCS {
		flightBuf.Write([]byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01})
	}

	var sHsSeq uint64
	if err := appendShapedHandshakeFlight(&flightBuf, sHsAEAD, sHsIV, &sHsSeq, hsPlain, profile.Flight2RecordLens); err != nil {
		return nil, "", err
	}

	if err := writeAll(rawConn, flightBuf.Bytes()); err != nil {
		return nil, "", err
	}

	// Read Client Flight 3 (optional 0x14 CCS + encrypted Finished).
	expectedClientVerify := hmacDigest(hFn, hkdfExpandLabel(hFn, cHsTraffic, "finished", nil, hashLen), sFinTranscriptHash)
	if err := readAndVerifyClientFinished(ctx, rawConn, cHsAEAD, cHsIV, hashLen, expectedClientVerify); err != nil {
		return nil, "", err
	}

	sAppAEAD, sAppIV, err := deriveTrafficCipher(spec, hFn, sAppTraffic)
	if err != nil {
		return nil, "", err
	}
	cAppAEAD, cAppIV, err := deriveTrafficCipher(spec, hFn, cAppTraffic)
	if err != nil {
		return nil, "", err
	}

	sc := &shadowTLSConn{
		Conn:          rawConn,
		spec:          spec,
		hFn:           hFn,
		hashLen:       hashLen,
		cAppSecret:    cAppTraffic,
		sAppSecret:    sAppTraffic,
		rAEAD:         cAppAEAD,
		rIV:           cAppIV,
		wAEAD:         sAppAEAD,
		wIV:           sAppIV,
		negotiatedALP: selectedALPN,
	}

	if ch.hasPSKModes && len(profile.PostTicketRecordLens) > 0 {
		var ticketBuf bytes.Buffer
		for _, targetLen := range profile.PostTicketRecordLens {
			tkt := buildNewSessionTicketMsg()
			if err := sc.appendEncryptedMsgLocked(&ticketBuf, 0x16, tkt, targetLen); err != nil {
				return nil, "", err
			}
		}
		if ticketBuf.Len() > 0 {
			if err := writeAll(rawConn, ticketBuf.Bytes()); err != nil {
				return nil, "", err
			}
		}
	}

	clearDeadline = true
	return sc, selectedALPN, nil
}

func selectKeyShareGroup(profileGroup uint16, clientShares map[uint16][]byte) (uint16, []byte, bool) {
	candidates := [4]uint16{profileGroup, tlsGroupX25519, tlsGroupP256, tlsGroupX25519MLKEM}
	for i, grp := range candidates {
		if grp == 0 {
			continue
		}
		if i > 0 && grp == profileGroup {
			continue
		}
		if share, ok := clientShares[grp]; ok && len(share) > 0 {
			return grp, share, true
		}
	}
	return 0, nil, false
}

func fallbackStdlibTLSServer(ctx context.Context, rawConn net.Conn, leafCertDER []byte, signer crypto.Signer, profile *sni.CamouflageProfile) (net.Conn, string, error) {
	rc := NewRewindConn(rawConn)
	rc.StopRecording()
	return fallbackRewoundStdlibTLSServer(ctx, rc, leafCertDER, signer, profile)
}

func fallbackRewoundStdlibTLSServer(ctx context.Context, rc *RewindConn, leafCertDER []byte, signer crypto.Signer, profile *sni.CamouflageProfile) (net.Conn, string, error) {
	rc.Rewind()
	if len(leafCertDER) == 0 || signer == nil {
		return nil, "", errors.New("gft: missing certificate for TLS fallback")
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafCertDER},
			PrivateKey:  signer,
		}},
	}
	OptimizeTLSConfigForHardware(cfg)
	if profile != nil && profile.KeyShareGroup != 0 {
		switch profile.KeyShareGroup {
		case tlsGroupX25519MLKEM:
			cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}
		case tlsGroupX25519:
			cfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
		case tlsGroupP256:
			cfg.CurvePreferences = []tls.CurveID{tls.CurveP256, tls.X25519}
		}
	}
	tc := tls.Server(rc, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = rawConnCloseSafe(rc.Conn)
		return nil, "", err
	}
	return tc, tc.ConnectionState().NegotiatedProtocol, nil
}

func rawConnCloseSafe(c net.Conn) error {
	if c != nil {
		return c.Close()
	}
	return nil
}

func readClientHelloFromConn(ctx context.Context, c net.Conn) (*parsedClientHello, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetReadDeadline(dl)
	} else {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	}
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	var hdr [5]byte
	var hsBuf []byte
	needLen := 4
	for len(hsBuf) < needLen {
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return nil, err
		}
		if hdr[0] != 0x16 || hdr[1] != 0x03 {
			return nil, errors.New("gft: expected TLS ClientHello record")
		}
		recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		if recLen <= 0 || recLen > 16384 {
			return nil, errors.New("gft: invalid ClientHello record length")
		}
		chunk := make([]byte, recLen)
		if _, err := io.ReadFull(c, chunk); err != nil {
			return nil, err
		}
		hsBuf = append(hsBuf, chunk...)
		if len(hsBuf) >= 4 {
			if hsBuf[0] != 0x01 {
				return nil, errors.New("gft: expected ClientHello handshake type")
			}
			msgLen := int(hsBuf[1])<<16 | int(hsBuf[2])<<8 | int(hsBuf[3])
			if msgLen <= 0 || msgLen > 65536 {
				return nil, errors.New("gft: invalid ClientHello message length")
			}
			needLen = 4 + msgLen
		}
	}

	rawHS := hsBuf[:needLen]
	body := rawHS[4:]
	if len(body) < 38 {
		return nil, errors.New("gft: truncated ClientHello")
	}

	ch := &parsedClientHello{
		rawHandshake: rawHS,
		keyShares:    make(map[uint16][]byte, 4),
	}
	copy(ch.random[:], body[2:34])
	off := 34
	sidLen := int(body[off])
	off++
	if off+sidLen+2 > len(body) {
		return nil, errors.New("gft: truncated ClientHello session id")
	}
	ch.sessionID = append([]byte(nil), body[off:off+sidLen]...)
	off += sidLen

	cipherLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if cipherLen%2 != 0 || off+cipherLen+1 > len(body) {
		return nil, errors.New("gft: invalid ClientHello cipher suites")
	}
	for i := 0; i < cipherLen; i += 2 {
		ch.ciphers = append(ch.ciphers, binary.BigEndian.Uint16(body[off+i:off+i+2]))
	}
	off += cipherLen

	compLen := int(body[off])
	off++
	if off+compLen > len(body) {
		return nil, errors.New("gft: truncated ClientHello compression methods")
	}
	off += compLen

	if off+2 > len(body) {
		return ch, nil
	}
	extTotal := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+extTotal > len(body) {
		return nil, errors.New("gft: truncated ClientHello extensions")
	}
	extEnd := off + extTotal
	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[off : off+2])
		extLen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
		off += 4
		if off+extLen > extEnd {
			return nil, errors.New("gft: truncated ClientHello extension body")
		}
		extData := body[off : off+extLen]
		off += extLen

		switch extType {
		case tlsExtSupportedVersions:
			if len(extData) >= 1 {
				vLen := int(extData[0])
				if 1+vLen <= len(extData) {
					for i := 1; i+1 < 1+vLen; i += 2 {
						if binary.BigEndian.Uint16(extData[i:i+2]) == 0x0304 {
							ch.supports13 = true
						}
					}
				}
			}
		case tlsExtKeyShare:
			if len(extData) >= 2 {
				ksLen := int(binary.BigEndian.Uint16(extData[0:2]))
				p := 2
				ksEnd := 2 + ksLen
				if ksEnd > len(extData) {
					ksEnd = len(extData)
				}
				for p+4 <= ksEnd {
					grp := binary.BigEndian.Uint16(extData[p : p+2])
					kLen := int(binary.BigEndian.Uint16(extData[p+2 : p+4]))
					p += 4
					if p+kLen > ksEnd {
						break
					}
					ch.keyShares[grp] = append([]byte(nil), extData[p:p+kLen]...)
					p += kLen
				}
			}
		case tlsExtALPN:
			if len(extData) >= 2 {
				lLen := int(binary.BigEndian.Uint16(extData[0:2]))
				p := 2
				lEnd := 2 + lLen
				if lEnd > len(extData) {
					lEnd = len(extData)
				}
				for p < lEnd {
					nLen := int(extData[p])
					p++
					if p+nLen > lEnd {
						break
					}
					ch.alpnList = append(ch.alpnList, string(extData[p:p+nLen]))
					p += nLen
				}
			}
		case tlsExtSigAlgorithms:
			if len(extData) >= 2 {
				sLen := int(binary.BigEndian.Uint16(extData[0:2]))
				for i := 2; i+1 < 2+sLen && i+1 < len(extData); i += 2 {
					ch.sigAlgs = append(ch.sigAlgs, binary.BigEndian.Uint16(extData[i:i+2]))
				}
			}
		case tlsExtPSKModes:
			ch.hasPSKModes = true
		}
	}
	return ch, nil
}

func containsUint16(list []uint16, target uint16) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

func extOrderSupported(order []uint16) bool {
	hasSV := false
	hasKS := false
	for _, ext := range order {
		switch ext {
		case tlsExtSupportedVersions:
			hasSV = true
		case tlsExtKeyShare:
			hasKS = true
		default:
			return false
		}
	}
	return hasSV && hasKS
}

func computeServerKeyShare(group uint16, clientPub []byte) (serverShare, sharedSecret []byte, err error) {
	switch group {
	case tlsGroupX25519:
		curve := ecdh.X25519()
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		peer, err := curve.NewPublicKey(clientPub)
		if err != nil {
			return nil, nil, err
		}
		ss, err := priv.ECDH(peer)
		if err != nil {
			return nil, nil, err
		}
		return priv.PublicKey().Bytes(), ss, nil

	case tlsGroupP256:
		curve := ecdh.P256()
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		peer, err := curve.NewPublicKey(clientPub)
		if err != nil {
			return nil, nil, err
		}
		ss, err := priv.ECDH(peer)
		if err != nil {
			return nil, nil, err
		}
		return priv.PublicKey().Bytes(), ss, nil

	case tlsGroupX25519MLKEM:
		if len(clientPub) != mlkem768EncapKeyBytes+x25519PubKeyBytes {
			return nil, nil, errors.New("gft: invalid client X25519MLKEM768 key share length")
		}
		ek, err := mlkem.NewEncapsulationKey768(clientPub[:mlkem768EncapKeyBytes])
		if err != nil {
			return nil, nil, err
		}
		mlkemSS, mlkemCT := ek.Encapsulate()
		curve := ecdh.X25519()
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		peer, err := curve.NewPublicKey(clientPub[mlkem768EncapKeyBytes:])
		if err != nil {
			return nil, nil, err
		}
		ecdhSS, err := priv.ECDH(peer)
		if err != nil {
			return nil, nil, err
		}
		outShare := make([]byte, 0, len(mlkemCT)+x25519PubKeyBytes)
		outShare = append(outShare, mlkemCT...)
		outShare = append(outShare, priv.PublicKey().Bytes()...)
		outSS := make([]byte, 0, len(mlkemSS)+len(ecdhSS))
		outSS = append(outSS, mlkemSS...)
		outSS = append(outSS, ecdhSS...)
		return outShare, outSS, nil

	default:
		return nil, nil, fmt.Errorf("gft: unsupported key_share group 0x%04x", group)
	}
}

func pickSignatureScheme(signer crypto.Signer, clientAlgs []uint16) (uint16, crypto.Hash, error) {
	switch pub := signer.Public().(type) {
	case *ecdsa.PublicKey:
		if pub.Curve.Params().BitSize == 256 && (len(clientAlgs) == 0 || containsUint16(clientAlgs, sigECDSAP256SHA256)) {
			return sigECDSAP256SHA256, crypto.SHA256, nil
		}
		if pub.Curve.Params().BitSize == 384 && containsUint16(clientAlgs, sigECDSAP384SHA384) {
			return sigECDSAP384SHA384, crypto.SHA384, nil
		}
	case *rsa.PublicKey:
		if len(clientAlgs) == 0 || containsUint16(clientAlgs, sigRSAPSSSHA256) {
			return sigRSAPSSSHA256, crypto.SHA256, nil
		}
		if containsUint16(clientAlgs, sigRSAPSSSHA384) {
			return sigRSAPSSSHA384, crypto.SHA384, nil
		}
	case ed25519.PublicKey:
		if len(clientAlgs) == 0 || containsUint16(clientAlgs, sigEd25519) {
			return sigEd25519, crypto.Hash(0), nil
		}
	}
	return 0, 0, errors.New("gft: no matching TLS 1.3 signature scheme")
}

func selectProfileALPN(profileALPN string, clientALPN []string) string {
	if len(clientALPN) == 0 {
		return ""
	}
	if profileALPN != "" {
		for _, a := range clientALPN {
			if a == profileALPN {
				return profileALPN
			}
		}
	}
	for _, a := range clientALPN {
		if a == "h2" {
			return "h2"
		}
	}
	return clientALPN[0]
}

func buildServerHelloBody(srvRandom [32]byte, sessionID []byte, cipherSuite, ksGroup uint16, ksData []byte, extOrder []uint16) []byte {
	var extBuf bytes.Buffer
	for _, ext := range extOrder {
		switch ext {
		case tlsExtSupportedVersions:
			extBuf.Write([]byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04})
		case tlsExtKeyShare:
			extLen := 4 + len(ksData)
			var hdr [8]byte
			binary.BigEndian.PutUint16(hdr[0:2], tlsExtKeyShare)
			binary.BigEndian.PutUint16(hdr[2:4], uint16(extLen))
			binary.BigEndian.PutUint16(hdr[4:6], ksGroup)
			binary.BigEndian.PutUint16(hdr[6:8], uint16(len(ksData)))
			extBuf.Write(hdr[:])
			extBuf.Write(ksData)
		}
	}

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03}) // legacy_version = TLS 1.2
	body.Write(srvRandom[:])
	body.WriteByte(byte(len(sessionID)))
	body.Write(sessionID)
	var tail [5]byte
	binary.BigEndian.PutUint16(tail[0:2], cipherSuite)
	tail[2] = 0x00 // legacy_compression_method
	binary.BigEndian.PutUint16(tail[3:5], uint16(extBuf.Len()))
	body.Write(tail[:])
	body.Write(extBuf.Bytes())
	return body.Bytes()
}

func wrapHandshakeMsg(hsType byte, body []byte) []byte {
	out := make([]byte, 4+len(body))
	out[0] = hsType
	out[1] = byte(len(body) >> 16)
	out[2] = byte(len(body) >> 8)
	out[3] = byte(len(body))
	copy(out[4:], body)
	return out
}

func buildEncryptedExtensionsMsg(alpn string) []byte {
	if alpn == "" {
		return wrapHandshakeMsg(0x08, []byte{0x00, 0x00})
	}
	protoLen := 1 + len(alpn)
	listLen := protoLen
	extLen := 2 + listLen
	totalExtLen := 4 + extLen
	body := make([]byte, 2+totalExtLen)
	binary.BigEndian.PutUint16(body[0:2], uint16(totalExtLen))
	binary.BigEndian.PutUint16(body[2:4], tlsExtALPN)
	binary.BigEndian.PutUint16(body[4:6], uint16(extLen))
	binary.BigEndian.PutUint16(body[6:8], uint16(listLen))
	body[8] = byte(len(alpn))
	copy(body[9:], alpn)
	return wrapHandshakeMsg(0x08, body)
}

func buildCertificateMsg(leafDER []byte) []byte {
	entryLen := 3 + len(leafDER) + 2
	body := make([]byte, 1+3+entryLen)
	body[0] = 0x00 // certificate_request_context len = 0
	body[1] = byte(entryLen >> 16)
	body[2] = byte(entryLen >> 8)
	body[3] = byte(entryLen)
	body[4] = byte(len(leafDER) >> 16)
	body[5] = byte(len(leafDER) >> 8)
	body[6] = byte(len(leafDER))
	copy(body[7:], leafDER)
	// trailing 2-byte extensions_len = 0x0000 already zero
	return wrapHandshakeMsg(0x0b, body)
}

func buildCertificateVerifyMsg(signer crypto.Signer, sigScheme uint16, sigHash crypto.Hash, transcriptHash []byte) ([]byte, error) {
	var msg bytes.Buffer
	for i := 0; i < 64; i++ {
		msg.WriteByte(0x20)
	}
	msg.WriteString("TLS 1.3, server CertificateVerify")
	msg.WriteByte(0x00)
	msg.Write(transcriptHash)

	var sig []byte
	var err error
	if sigHash == crypto.Hash(0) {
		sig, err = signer.Sign(rand.Reader, msg.Bytes(), crypto.Hash(0))
	} else {
		h := sigHash.New()
		_, _ = h.Write(msg.Bytes())
		digest := h.Sum(nil)
		if _, isRSA := signer.Public().(*rsa.PublicKey); isRSA {
			sig, err = signer.Sign(rand.Reader, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash})
		} else {
			sig, err = signer.Sign(rand.Reader, digest, sigHash)
		}
	}
	if err != nil {
		return nil, err
	}
	body := make([]byte, 4+len(sig))
	binary.BigEndian.PutUint16(body[0:2], sigScheme)
	binary.BigEndian.PutUint16(body[2:4], uint16(len(sig)))
	copy(body[4:], sig)
	return wrapHandshakeMsg(0x0f, body), nil
}

func buildNewSessionTicketMsg() []byte {
	var nonce [8]byte
	var ticket [32]byte
	var ageAdd [4]byte
	_, _ = rand.Read(nonce[:])
	_, _ = rand.Read(ticket[:])
	_, _ = rand.Read(ageAdd[:])

	body := make([]byte, 4+4+1+len(nonce)+2+len(ticket)+2)
	binary.BigEndian.PutUint32(body[0:4], 86400) // ticket_lifetime (24h)
	copy(body[4:8], ageAdd[:])
	body[8] = byte(len(nonce))
	copy(body[9:9+len(nonce)], nonce[:])
	off := 9 + len(nonce)
	binary.BigEndian.PutUint16(body[off:off+2], uint16(len(ticket)))
	copy(body[off+2:off+2+len(ticket)], ticket[:])
	// trailing 2-byte extensions = 0
	return wrapHandshakeMsg(0x04, body)
}

func appendPlainRecord(dst *bytes.Buffer, recType byte, payload []byte) {
	var hdr [5]byte
	hdr[0] = recType
	hdr[1] = 0x03
	hdr[2] = 0x03
	binary.BigEndian.PutUint16(hdr[3:5], uint16(len(payload)))
	dst.Write(hdr[:])
	dst.Write(payload)
}

func makeRecordNonce(iv []byte, seq uint64, nonceOut []byte) {
	copy(nonceOut, iv)
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], seq)
	off := len(iv) - 8
	for i := 0; i < 8; i++ {
		nonceOut[off+i] ^= seqBuf[i]
	}
}

func sealTLS13RecordPooled(aead cipher.AEAD, iv []byte, seq *uint64, innerType byte, chunk []byte, padLen int, dst *bytes.Buffer) error {
	overhead := aead.Overhead()
	innerLen := len(chunk) + 1 + padLen
	cipherLen := innerLen + overhead
	if cipherLen > shadowMaxRecordPlain+256 {
		return errors.New("gft: TLS 1.3 record exceeds max capacity")
	}

	bp := shadowRecordBufPool.Get().(*[]byte)
	buf := *bp
	defer shadowRecordBufPool.Put(bp)

	buf[0] = 0x17
	buf[1] = 0x03
	buf[2] = 0x03
	binary.BigEndian.PutUint16(buf[3:5], uint16(cipherLen))

	copy(buf[5:], chunk)
	buf[5+len(chunk)] = innerType
	if padLen > 0 {
		clear(buf[5+len(chunk)+1 : 5+innerLen])
	}

	var nonce [12]byte
	makeRecordNonce(iv, *seq, nonce[:])
	*seq++

	sealed := aead.Seal(buf[5:5], nonce[:], buf[5:5+innerLen], buf[:5])
	dst.Write(buf[:5+len(sealed)])
	return nil
}

func appendShapedHandshakeFlight(dst *bytes.Buffer, aead cipher.AEAD, iv []byte, seq *uint64, hsPlain []byte, targetOuterLens []int) error {
	if len(hsPlain) == 0 {
		return nil
	}
	if len(targetOuterLens) == 0 {
		for off := 0; off < len(hsPlain); {
			n := len(hsPlain) - off
			if n > shadowMaxRecordPlain {
				n = shadowMaxRecordPlain
			}
			if err := sealTLS13RecordPooled(aead, iv, seq, 0x16, hsPlain[off:off+n], 0, dst); err != nil {
				return err
			}
			off += n
		}
		return nil
	}

	overhead := aead.Overhead()
	targets := targetOuterLens
	if len(targets) > len(hsPlain) {
		targets = targets[:len(hsPlain)]
	}

	off := 0
	for i := 0; i < len(targets); i++ {
		remBytes := len(hsPlain) - off
		if remBytes <= 0 {
			break
		}
		remTargets := len(targets) - 1 - i
		targetOuter := targets[i]
		if targetOuter > shadowMaxRecordPlain+overhead+1 {
			targetOuter = shadowMaxRecordPlain + overhead + 1
		}
		capBytes := targetOuter - overhead - 1
		if capBytes < 1 {
			capBytes = 1
		}

		if i == len(targets)-1 {
			// Last record takes all remaining hsPlain (splitting only if > 16384B per RFC 8446).
			if remBytes <= capBytes {
				padLen := capBytes - remBytes
				return sealTLS13RecordPooled(aead, iv, seq, 0x16, hsPlain[off:], padLen, dst)
			}
			for off < len(hsPlain) {
				n := len(hsPlain) - off
				if n > shadowMaxRecordPlain {
					n = shadowMaxRecordPlain
				}
				if err := sealTLS13RecordPooled(aead, iv, seq, 0x16, hsPlain[off:off+n], 0, dst); err != nil {
					return err
				}
				off += n
			}
			return nil
		}

		maxSafe := remBytes - remTargets
		take := capBytes
		if take > maxSafe {
			take = maxSafe
		}
		if take < 1 {
			take = 1
		}
		padLen := 0
		if capBytes > take {
			padLen = capBytes - take
		}
		if err := sealTLS13RecordPooled(aead, iv, seq, 0x16, hsPlain[off:off+take], padLen, dst); err != nil {
			return err
		}
		off += take
	}
	return nil
}

func readAndVerifyClientFinished(ctx context.Context, c net.Conn, cHsAEAD cipher.AEAD, cHsIV []byte, hashLen int, expectedVerify []byte) error {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetReadDeadline(dl)
	} else {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	}
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	var rSeq uint64
	var hsAcc []byte
	var hdr [5]byte
	var nonce [12]byte

	bp := shadowRecordBufPool.Get().(*[]byte)
	recBuf := *bp
	defer shadowRecordBufPool.Put(bp)

	for {
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return err
		}
		recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		if recLen > len(recBuf) {
			return errors.New("gft: client handshake record too large")
		}
		if recLen > 0 {
			if _, err := io.ReadFull(c, recBuf[:recLen]); err != nil {
				return err
			}
		}
		switch hdr[0] {
		case 0x14: // ChangeCipherSpec compatibility record
			continue
		case 0x15: // Alert
			return errors.New("gft: client sent TLS alert during handshake")
		case 0x17:
			makeRecordNonce(cHsIV, rSeq, nonce[:])
			rSeq++
			plain, err := cHsAEAD.Open(recBuf[:0], nonce[:], recBuf[:recLen], hdr[:])
			if err != nil {
				return fmt.Errorf("gft: decrypt client Finished failed: %w", err)
			}
			innerType, content, err := unpadTLS13Plaintext(plain)
			if err != nil {
				return err
			}
			if innerType == 0x15 {
				return errors.New("gft: client sent encrypted TLS alert")
			}
			if innerType != 0x16 {
				continue
			}
			hsAcc = append(hsAcc, content...)
			if len(hsAcc) >= 4+hashLen {
				if hsAcc[0] != 0x14 {
					return errors.New("gft: expected client Finished handshake message")
				}
				mLen := int(hsAcc[1])<<16 | int(hsAcc[2])<<8 | int(hsAcc[3])
				if mLen != hashLen || len(hsAcc) < 4+mLen {
					return errors.New("gft: invalid client Finished length")
				}
				gotVerify := hsAcc[4 : 4+mLen]
				if subtle.ConstantTimeCompare(gotVerify, expectedVerify) != 1 {
					return errors.New("gft: client Finished verify_data mismatch")
				}
				return nil
			}
		default:
			return fmt.Errorf("gft: unexpected TLS record type 0x%02x during Finished", hdr[0])
		}
	}
}

func unpadTLS13Plaintext(plain []byte) (innerType byte, content []byte, err error) {
	i := len(plain) - 1
	for i >= 0 && plain[i] == 0 {
		i--
	}
	if i < 0 {
		return 0, nil, errors.New("gft: RFC 8446 record missing inner content type")
	}
	return plain[i], plain[:i], nil
}

func deriveTrafficCipher(spec tls13SuiteSpec, hFn func() hash.Hash, trafficSecret []byte) (cipher.AEAD, []byte, error) {
	k := hkdfExpandLabel(hFn, trafficSecret, "key", nil, spec.keyLen)
	iv := hkdfExpandLabel(hFn, trafficSecret, "iv", nil, spec.ivLen)
	aead, err := newAEADForSuite(spec, k)
	if err != nil {
		return nil, nil, err
	}
	return aead, iv, nil
}

// shadowTLSConn implements net.Conn over a negotiated ShadowTLS 1.3 session using fixed-size
// pooled buffers (16384 + 256 B) for zero-allocation in-place AEAD.Seal / AEAD.Open on Read & Write.
type shadowTLSConn struct {
	net.Conn
	spec          tls13SuiteSpec
	hFn           func() hash.Hash
	hashLen       int
	negotiatedALP string

	readMu     sync.Mutex
	rAEAD      cipher.AEAD
	rIV        []byte
	rSeq       uint64
	cAppSecret []byte
	rHdr       [5]byte
	rNonce     [12]byte
	pendingBuf [shadowPoolBufSize]byte
	pendingOff int
	pendingLen int
	readEOF    bool

	writeMu    sync.Mutex
	wAEAD      cipher.AEAD
	wIV        []byte
	wSeq       uint64
	sAppSecret []byte
	wNonce     [12]byte
}

func (c *shadowTLSConn) appendEncryptedMsgLocked(dst *bytes.Buffer, innerType byte, payload []byte, targetOuterLen int) error {
	overhead := c.wAEAD.Overhead()
	padLen := 0
	if targetOuterLen > len(payload)+1+overhead {
		padLen = targetOuterLen - len(payload) - 1 - overhead
	}
	return sealTLS13RecordPooled(c.wAEAD, c.wIV, &c.wSeq, innerType, payload, padLen, dst)
}

func (c *shadowTLSConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.pendingOff < c.pendingLen {
		n := copy(p, c.pendingBuf[c.pendingOff:c.pendingLen])
		c.pendingOff += n
		if c.pendingOff >= c.pendingLen {
			c.pendingOff = 0
			c.pendingLen = 0
		}
		return n, nil
	}
	if c.readEOF {
		return 0, io.EOF
	}

	bp := shadowRecordBufPool.Get().(*[]byte)
	recBuf := *bp
	defer shadowRecordBufPool.Put(bp)

	for {
		if _, err := io.ReadFull(c.Conn, c.rHdr[:]); err != nil {
			return 0, err
		}
		recLen := int(binary.BigEndian.Uint16(c.rHdr[3:5]))
		if recLen > len(recBuf) {
			return 0, errors.New("gft: TLS 1.3 record exceeds max capacity")
		}
		if c.rHdr[0] == 0x15 {
			if recLen > 0 {
				_, _ = io.ReadFull(c.Conn, recBuf[:recLen])
			}
			c.readEOF = true
			return 0, io.EOF
		}
		if c.rHdr[0] == 0x14 {
			if recLen > 0 {
				if _, err := io.ReadFull(c.Conn, recBuf[:recLen]); err != nil {
					return 0, err
				}
			}
			continue
		}
		if c.rHdr[0] != 0x17 {
			return 0, fmt.Errorf("gft: unexpected record type 0x%02x", c.rHdr[0])
		}
		if recLen > 0 {
			if _, err := io.ReadFull(c.Conn, recBuf[:recLen]); err != nil {
				return 0, err
			}
		}

		makeRecordNonce(c.rIV, c.rSeq, c.rNonce[:])
		c.rSeq++

		plain, err := c.rAEAD.Open(recBuf[:0], c.rNonce[:], recBuf[:recLen], c.rHdr[:])
		if err != nil {
			return 0, err
		}
		innerType, content, err := unpadTLS13Plaintext(plain)
		if err != nil {
			return 0, err
		}

		switch innerType {
		case 0x17: // Application Data
			if len(content) == 0 {
				continue
			}
			n := copy(p, content)
			if n < len(content) {
				rem := copy(c.pendingBuf[:], content[n:])
				c.pendingOff = 0
				c.pendingLen = rem
			}
			return n, nil

		case 0x15: // Alert
			c.readEOF = true
			return 0, io.EOF

		case 0x16: // Post-handshake messages (KeyUpdate = 0x18)
			if err := c.handlePostHandshakeMsgLocked(content); err != nil {
				return 0, err
			}
		default:
			return 0, fmt.Errorf("gft: unexpected inner content type 0x%02x", innerType)
		}
	}
}

func (c *shadowTLSConn) handlePostHandshakeMsgLocked(content []byte) error {
	for len(content) >= 4 {
		hsType := content[0]
		hsLen := int(content[1])<<16 | int(content[2])<<8 | int(content[3])
		if len(content) < 4+hsLen {
			break
		}
		body := content[4 : 4+hsLen]
		content = content[4+hsLen:]
		if hsType != 0x18 || len(body) != 1 {
			continue
		}
		c.cAppSecret = hkdfExpandLabel(c.hFn, c.cAppSecret, "traffic upd", nil, c.hashLen)
		newAEAD, newIV, err := deriveTrafficCipher(c.spec, c.hFn, c.cAppSecret)
		if err != nil {
			return err
		}
		c.rAEAD = newAEAD
		c.rIV = newIV
		c.rSeq = 0

		if body[0] == 1 { // update_requested -> send KeyUpdate(0) and rotate write key
			if err := c.sendKeyUpdateAndRotate(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *shadowTLSConn) sendKeyUpdateAndRotate() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	var kuMsg [5]byte
	kuMsg[0] = 0x18
	kuMsg[3] = 0x01
	kuMsg[4] = 0x00

	bp := shadowRecordBufPool.Get().(*[]byte)
	buf := *bp
	defer shadowRecordBufPool.Put(bp)

	overhead := c.wAEAD.Overhead()
	innerLen := len(kuMsg) + 1
	cipherLen := innerLen + overhead
	buf[0] = 0x17
	buf[1] = 0x03
	buf[2] = 0x03
	binary.BigEndian.PutUint16(buf[3:5], uint16(cipherLen))
	copy(buf[5:], kuMsg[:])
	buf[5+len(kuMsg)] = 0x16

	var nonce [12]byte
	makeRecordNonce(c.wIV, c.wSeq, nonce[:])
	c.wSeq++
	sealed := c.wAEAD.Seal(buf[5:5], nonce[:], buf[5:5+innerLen], buf[:5])
	if err := writeAll(c.Conn, buf[:5+len(sealed)]); err != nil {
		return err
	}

	c.sAppSecret = hkdfExpandLabel(c.hFn, c.sAppSecret, "traffic upd", nil, c.hashLen)
	newAEAD, newIV, err := deriveTrafficCipher(c.spec, c.hFn, c.sAppSecret)
	if err != nil {
		return err
	}
	c.wAEAD = newAEAD
	c.wIV = newIV
	c.wSeq = 0
	return nil
}

func (c *shadowTLSConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	bp := shadowRecordBufPool.Get().(*[]byte)
	buf := *bp
	defer shadowRecordBufPool.Put(bp)

	overhead := c.wAEAD.Overhead()
	total := 0
	for total < len(p) {
		chunkLen := len(p) - total
		if chunkLen > shadowMaxRecordPlain {
			chunkLen = shadowMaxRecordPlain
		}
		innerLen := chunkLen + 1
		cipherLen := innerLen + overhead
		buf[0] = 0x17
		buf[1] = 0x03
		buf[2] = 0x03
		binary.BigEndian.PutUint16(buf[3:5], uint16(cipherLen))
		copy(buf[5:], p[total:total+chunkLen])
		buf[5+chunkLen] = 0x17

		makeRecordNonce(c.wIV, c.wSeq, c.wNonce[:])
		c.wSeq++
		sealed := c.wAEAD.Seal(buf[5:5], c.wNonce[:], buf[5:5+innerLen], buf[:5])
		if err := writeAll(c.Conn, buf[:5+len(sealed)]); err != nil {
			return total, err
		}
		total += chunkLen
	}
	return total, nil
}

func (c *shadowTLSConn) Close() error {
	c.writeMu.Lock()
	if c.wAEAD != nil {
		bp := shadowRecordBufPool.Get().(*[]byte)
		buf := *bp
		overhead := c.wAEAD.Overhead()
		innerLen := 3 // close_notify (warning=1, close_notify=0) + contentType(0x15)
		buf[0] = 0x17
		buf[1] = 0x03
		buf[2] = 0x03
		binary.BigEndian.PutUint16(buf[3:5], uint16(innerLen+overhead))
		buf[5] = 0x01
		buf[6] = 0x00
		buf[7] = 0x15
		var nonce [12]byte
		makeRecordNonce(c.wIV, c.wSeq, nonce[:])
		c.wSeq++
		sealed := c.wAEAD.Seal(buf[5:5], nonce[:], buf[5:5+innerLen], buf[:5])
		_ = c.Conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = c.Conn.Write(buf[:5+len(sealed)])
		_ = c.Conn.SetWriteDeadline(time.Time{})
		shadowRecordBufPool.Put(bp)
	}
	c.writeMu.Unlock()
	return c.Conn.Close()
}
