package gft

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	quicStreamCtrl byte = 0x01
	quicStreamData byte = 0x02
	quicStreamUDP  byte = 0x03

	dgKindSingle byte = 0x01
	dgKindClose  byte = 0x02
	dgKindFrag   byte = 0x03

	defaultMaxDGPayload  = 1100
	fallbackMaxDGPayload = 960
	maxDGFragBody        = 8192
	maxDGFrags           = 16
	maxReassemblySlots   = 256
	reassemblyTTL        = 2 * time.Second
	maxStreamUDPPayload  = 65507
)

// DataStream abstracts a multiplexed bidirectional byte stream across either
// Ghost Frame v3 TCP Sessions or QUIC native streams.
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

// UDPReplySink lets server outbound forward UDP responses back over TCP mux or QUIC datagrams.
type UDPReplySink interface {
	SendUDPReply(id uint16, target string, data []byte) error
	SessionDone() <-chan struct{}
}

// QUICStreamHandler is invoked in its own goroutine for each QUIC data stream.
type QUICStreamHandler func(s DataStream, target string, first []byte)

// QUICUDPHandler handles incoming UDP datagrams arriving over QUIC.
type QUICUDPHandler func(sink UDPReplySink, id uint16, target string, data []byte)

// QUICUDPCloseHandler handles QUIC UDP close notifications.
type QUICUDPCloseHandler func(sink UDPReplySink, id uint16)

// GenerateConnectionID implements quic.ConnectionIDGenerator using stego CIDs.
func (g *StegoCIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	b, err := g.GenerateBytes()
	if err != nil {
		return quic.ConnectionID{}, err
	}
	return quic.ConnectionIDFromBytes(b), nil
}

// QUICConfig returns the BDP-tuned RFC9221 QUIC config (4MB/8MB init, 16MB/32MB max by default;
// 512KB/1MB init, 4MB/8MB max in LowMemMode).
func QUICConfig() *quic.Config {
	initStreamWin := uint64(4 * 1024 * 1024)
	maxStreamWin := uint64(16 * 1024 * 1024)
	initConnWin := uint64(8 * 1024 * 1024)
	maxConnWin := uint64(32 * 1024 * 1024)
	if IsLowMemMode() {
		initStreamWin = 512 * 1024
		maxStreamWin = 4 * 1024 * 1024
		initConnWin = 1024 * 1024
		maxConnWin = 8 * 1024 * 1024
	}
	return &quic.Config{
		Versions:                       []quic.Version{quic.Version1},
		InitialStreamReceiveWindow:     initStreamWin,
		MaxStreamReceiveWindow:         maxStreamWin,
		InitialConnectionReceiveWindow: initConnWin,
		MaxConnectionReceiveWindow:     maxConnWin,
		MaxIncomingStreams:             512,
		MaxIncomingUniStreams:          64,
		KeepAlivePeriod:                20 * time.Second,
		MaxIdleTimeout:                 90 * time.Second,
		HandshakeIdleTimeout:           6 * time.Second,
		InitialPacketSize:              1250,
		EnableDatagrams:                true,
	}
}

// QUICTLSConfigFor builds a TLS 1.3 config for QUIC client honoring Verify ("ca" or "spki").
func QUICTLSConfigFor(l *Link) (*tls.Config, error) {
	sni := l.SNI
	if sni == "" && net.ParseIP(l.Host) == nil {
		sni = l.Host
	}
	cfg := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"},
	}
	OptimizeTLSConfigForHardware(cfg)
	switch l.EffectiveVerify() {
	case "ca":
		cfg.InsecureSkipVerify = false
	case "spki":
		want, err := hex.DecodeString(l.Pin)
		if err != nil || len(want) != sha256.Size {
			return nil, errors.New("invalid spki pin")
		}
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
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

// QUICStream wraps *quic.Stream to satisfy DataStream cleanly.
type QUICStream struct {
	qs     *quic.Stream
	target string
	sess   *QUICSession
	Up     atomic.Uint64
	Down   atomic.Uint64
	closed atomic.Bool
}

func (s *QUICStream) RemoteTarget() string { return s.target }

func (s *QUICStream) Read(p []byte) (int, error) {
	n, err := s.qs.Read(p)
	if n > 0 {
		s.Down.Add(uint64(n))
		s.sess.DownBytes.Add(uint64(n))
	}
	return n, err
}

func (s *QUICStream) Write(p []byte) (int, error) {
	n, err := s.qs.Write(p)
	if n > 0 {
		s.Up.Add(uint64(n))
		s.sess.UpBytes.Add(uint64(n))
	}
	return n, err
}

func (s *QUICStream) CloseWrite() error { return s.qs.Close() }

func (s *QUICStream) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.sess.decStreams()
		s.qs.CancelRead(0)
		return s.qs.Close()
	}
	return nil
}

// QUICUDPAssoc implements UDPAssociation over RFC 9221 QUIC Datagrams + Stream fallback.
type QUICUDPAssoc struct {
	sess      *QUICSession
	id        uint16
	recvCh    chan UDPPacket
	done      chan struct{}
	closeOnce sync.Once
}

func (u *QUICUDPAssoc) ID() uint16             { return u.id }
func (u *QUICUDPAssoc) Recv() <-chan UDPPacket { return u.recvCh }
func (u *QUICUDPAssoc) Done() <-chan struct{}  { return u.done }

func (u *QUICUDPAssoc) push(pkt UDPPacket) {
	select {
	case <-u.done:
		return
	default:
	}
	select {
	case u.recvCh <- pkt:
	default:
	}
}

func (u *QUICUDPAssoc) SendTo(target string, data []byte) error {
	select {
	case <-u.done:
		return ErrStreamClosed
	default:
	}
	return u.sess.sendUDPPacket(u.id, target, data)
}

// closeLocal closes local channels without telling server to destroy shared ClientID NAT socket.
func (u *QUICUDPAssoc) closeLocal() {
	u.closeOnce.Do(func() {
		close(u.done)
	})
}

func (u *QUICUDPAssoc) Close() error {
	u.closeOnce.Do(func() {
		close(u.done)
		u.sess.mu.Lock()
		delete(u.sess.udps, u.id)
		u.sess.mu.Unlock()
		_ = u.sess.sendUDPClose(u.id)
	})
	return nil
}

type dgReassembly struct {
	total     int
	received  int
	parts     [][]byte
	createdAt time.Time
}

// QUICSession wraps a client or server *quic.Conn with stream opening, adaptive
// fragmented RFC9221 UDP + stream fallback, control-stream auth & RTT probing.
type QUICSession struct {
	qconn      *quic.Conn
	tr         *quic.Transport
	ownPC      net.PacketConn
	remotePort int
	ps         *ParamStore
	isClient   bool

	ctrlStream *quic.Stream
	ctrlMu     sync.Mutex
	pingCh     chan time.Duration

	maxDG     atomic.Int32
	nextMsgID atomic.Uint32

	udpStreamMu       sync.Mutex
	udpFallbackStream *quic.Stream

	fragMu     sync.Mutex
	frags      map[uint32]*dgReassembly
	lastFragGC int64

	mu        sync.Mutex
	nextUDP   uint16
	udps      map[uint16]*QUICUDPAssoc
	streams   atomic.Int64
	rttNs     atomic.Int64
	lastUDPNs atomic.Int64
	UpBytes   atomic.Uint64
	DownBytes atomic.Uint64

	onStream QUICStreamHandler
	onUDP    QUICUDPHandler
	onUDPCls QUICUDPCloseHandler

	done      chan struct{}
	closeOnce sync.Once
	errVal    atomic.Value
}

func newBaseQUICSession(qconn *quic.Conn, ps *ParamStore, isClient bool) *QUICSession {
	qs := &QUICSession{
		qconn:    qconn,
		ps:       ps,
		isClient: isClient,
		pingCh:   make(chan time.Duration, 4),
		nextUDP:  1,
		udps:     make(map[uint16]*QUICUDPAssoc),
		frags:    make(map[uint32]*dgReassembly),
		done:     make(chan struct{}),
	}
	qs.maxDG.Store(defaultMaxDGPayload)
	return qs
}

// PickHopPort chooses an initial or hopped UDP port within HopRange or returns Link.Port.
func PickHopPort(l *Link) int {
	lo, hi, ok := l.ParseHopRange()
	if !ok {
		return l.Port
	}
	return randRange(lo, hi)
}

// DialQUICSession opens a stealth QUIC connection using DefaultClientID.
func DialQUICSession(ctx context.Context, l *Link, ps *ParamStore, port int, timeout time.Duration) (*QUICSession, time.Duration, error) {
	return DialQUICSessionWithID(ctx, l, ps, port, timeout, DefaultClientID)
}

// DialQUICSessionWithID opens a stealth QUIC connection carrying clientID in ClientAuthFrame.
func DialQUICSessionWithID(ctx context.Context, l *Link, ps *ParamStore, port int, timeout time.Duration, clientID [8]byte) (*QUICSession, time.Duration, error) {
	if port <= 0 {
		port = PickHopPort(l)
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(l.Host, strconv.Itoa(port)))
	if err != nil {
		return nil, 0, err
	}
	network := "udp"
	if addr.IP != nil && addr.IP.To4() != nil {
		network = "udp4"
	}
	pc, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, 0, err
	}
	TuneUDPSocketBuffers(pc)
	return DialQUICWithPacketConnAndID(ctx, pc, true, addr, port, l, ps, timeout, clientID)
}

// DialQUICWithPacketConn dials QUIC over a caller-provided PacketConn using DefaultClientID.
func DialQUICWithPacketConn(ctx context.Context, pc net.PacketConn, ownPC bool, raddr net.Addr, remotePort int, l *Link, ps *ParamStore, timeout time.Duration) (*QUICSession, time.Duration, error) {
	return DialQUICWithPacketConnAndID(ctx, pc, ownPC, raddr, remotePort, l, ps, timeout, DefaultClientID)
}

// DialQUICWithPacketConnAndID dials QUIC over pc with an explicit 8-byte ClientID.
func DialQUICWithPacketConnAndID(ctx context.Context, pc net.PacketConn, ownPC bool, raddr net.Addr, remotePort int, l *Link, ps *ParamStore, timeout time.Duration, clientID [8]byte) (*QUICSession, time.Duration, error) {
	psk, err := l.PSKBytes()
	if err != nil {
		if ownPC {
			_ = pc.Close()
		}
		return nil, 0, err
	}
	tcfg, err := QUICTLSConfigFor(l)
	if err != nil {
		if ownPC {
			_ = pc.Close()
		}
		return nil, 0, err
	}

	cidGen := NewStegoCIDGenerator(psk)
	tr := &quic.Transport{
		Conn:                  pc,
		ConnectionIDLength:    cidGen.ConnectionIDLen(),
		ConnectionIDGenerator: cidGen,
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	t0 := time.Now()
	qconn, err := tr.Dial(dialCtx, raddr, tcfg, QUICConfig())
	if err != nil {
		_ = tr.Close()
		if ownPC {
			_ = pc.Close()
		}
		return nil, 0, err
	}
	hs := time.Since(t0)

	cs, err := qconn.OpenStreamSync(dialCtx)
	if err != nil {
		_ = qconn.CloseWithError(1, "ctrl failed")
		_ = tr.Close()
		if ownPC {
			_ = pc.Close()
		}
		return nil, 0, err
	}
	authFrame, salt, err := BuildClientAuthFrameWithID(psk, time.Now(), clientID)
	if err != nil {
		_ = qconn.CloseWithError(1, "auth build failed")
		_ = tr.Close()
		if ownPC {
			_ = pc.Close()
		}
		return nil, 0, err
	}
	ctrlInit := make([]byte, 1+len(authFrame))
	ctrlInit[0] = quicStreamCtrl
	copy(ctrlInit[1:], authFrame)
	if _, err := cs.Write(ctrlInit); err != nil {
		_ = qconn.CloseWithError(1, "auth write failed")
		_ = tr.Close()
		if ownPC {
			_ = pc.Close()
		}
		return nil, 0, err
	}

	qs := newBaseQUICSession(qconn, ps, true)
	qs.tr = tr
	qs.remotePort = remotePort
	qs.ctrlStream = cs
	if ownPC {
		qs.ownPC = pc
	}
	qs.rttNs.Store(int64(hs))

	go qs.clientCtrlLoop(psk, salt)
	go qs.datagramRecvLoop()
	go qs.clientAcceptLoop()
	return qs, hs, nil
}

func (s *QUICSession) clientAcceptLoop() {
	for {
		st, err := s.qconn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func(stream *quic.Stream) {
			var typ [1]byte
			if _, err := io.ReadFull(stream, typ[:]); err != nil {
				_ = stream.Close()
				return
			}
			if typ[0] == quicStreamUDP {
				s.serveUDPStream(stream)
				return
			}
			_ = stream.Close()
		}(st)
	}
}

func (s *QUICSession) clientCtrlLoop(psk, salt []byte) {
	defer s.Close()
	if ackParams, err := ReadServerAuthAck(s.ctrlStream, psk, salt); err == nil {
		if s.ps != nil {
			s.ps.Set(ackParams)
		}
	} else {
		s.fail(err)
		return
	}
	var msg [9]byte
	for {
		if _, err := io.ReadFull(s.ctrlStream, msg[:]); err != nil {
			s.fail(err)
			return
		}
		if msg[0] == PingResp {
			sent := int64(binary.BigEndian.Uint64(msg[1:9]))
			rtt := time.Duration(time.Now().UnixNano() - sent)
			if rtt <= 0 {
				rtt = time.Millisecond
			}
			s.rttNs.Store(int64(rtt))
			select {
			case s.pingCh <- rtt:
			default:
			}
		}
	}
}

func (s *QUICSession) deliverInboundUDP(id uint16, body []byte) {
	target, data, err := DecodeAddr(body)
	if err != nil {
		return
	}
	s.lastUDPNs.Store(time.Now().UnixNano())
	s.DownBytes.Add(uint64(len(data)))
	cp := make([]byte, len(data))
	copy(cp, data)

	if s.isClient {
		s.mu.Lock()
		u := s.udps[id]
		s.mu.Unlock()
		if u != nil {
			u.push(UDPPacket{Target: target, Data: cp})
		}
	} else if s.onUDP != nil {
		s.onUDP(s, id, target, cp)
	}
}

func (s *QUICSession) handleFragDatagram(id uint16, pkt []byte) {
	// Format: [0x03][AssocID 2B][MsgID 2B][FragIdx 1B][FragTotal 1B][Chunk]
	if len(pkt) < 8 {
		return
	}
	msgID := binary.BigEndian.Uint16(pkt[3:5])
	fragIdx := int(pkt[5])
	fragTotal := int(pkt[6])
	if fragTotal <= 0 || fragTotal > maxDGFrags || fragIdx >= fragTotal {
		return
	}
	chunk := pkt[7:]
	key := (uint32(id) << 16) | uint32(msgID)
	now := time.Now()

	s.fragMu.Lock()
	if now.UnixNano()-s.lastFragGC > int64(reassemblyTTL) {
		s.lastFragGC = now.UnixNano()
		for k, entry := range s.frags {
			if now.Sub(entry.createdAt) > reassemblyTTL {
				delete(s.frags, k)
			}
		}
	}
	entry, ok := s.frags[key]
	if !ok {
		if len(s.frags) >= maxReassemblySlots {
			// Evict oldest/any stale entry cleanly
			for k := range s.frags {
				delete(s.frags, k)
				break
			}
		}
		entry = &dgReassembly{
			total:     fragTotal,
			parts:     make([][]byte, fragTotal),
			createdAt: now,
		}
		s.frags[key] = entry
	}
	if entry.total != fragTotal {
		delete(s.frags, key)
		s.fragMu.Unlock()
		return
	}
	var assembled []byte
	if entry.parts[fragIdx] == nil {
		cp := make([]byte, len(chunk))
		copy(cp, chunk)
		entry.parts[fragIdx] = cp
		entry.received++
		if entry.received == entry.total {
			totalLen := 0
			for _, part := range entry.parts {
				totalLen += len(part)
			}
			if totalLen <= maxDGFragBody+512 {
				assembled = make([]byte, 0, totalLen)
				for _, part := range entry.parts {
					assembled = append(assembled, part...)
				}
			}
			delete(s.frags, key)
		}
	}
	s.fragMu.Unlock()

	if assembled != nil {
		s.deliverInboundUDP(id, assembled)
	}
}

func (s *QUICSession) datagramRecvLoop() {
	for {
		pkt, err := s.qconn.ReceiveDatagram(context.Background())
		if err != nil {
			s.fail(err)
			return
		}
		if len(pkt) < 3 {
			continue
		}
		kind := pkt[0]
		id := binary.BigEndian.Uint16(pkt[1:3])
		switch kind {
		case dgKindClose:
			if s.isClient {
				s.mu.Lock()
				u := s.udps[id]
				delete(s.udps, id)
				s.mu.Unlock()
				if u != nil {
					u.closeLocal()
				}
			} else if s.onUDPCls != nil {
				s.onUDPCls(s, id)
			}
		case dgKindSingle:
			if len(pkt) >= 4 {
				s.deliverInboundUDP(id, pkt[3:])
			}
		case dgKindFrag:
			s.handleFragDatagram(id, pkt)
		}
	}
}

func (s *QUICSession) sendViaUDPStream(id uint16, ab, data []byte) error {
	bodyLen := len(ab) + len(data)
	if bodyLen > maxStreamUDPPayload+300 {
		return errors.New("gft: udp packet too large")
	}
	frame := make([]byte, 4+bodyLen)
	binary.BigEndian.PutUint16(frame[0:2], id)
	binary.BigEndian.PutUint16(frame[2:4], uint16(bodyLen))
	copy(frame[4:], ab)
	copy(frame[4+len(ab):], data)

	s.udpStreamMu.Lock()
	defer s.udpStreamMu.Unlock()
	if s.udpFallbackStream == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		st, err := s.qconn.OpenStreamSync(ctx)
		cancel()
		if err != nil {
			return err
		}
		if _, err := st.Write([]byte{quicStreamUDP}); err != nil {
			_ = st.Close()
			return err
		}
		s.udpFallbackStream = st
	}
	if _, err := s.udpFallbackStream.Write(frame); err != nil {
		_ = s.udpFallbackStream.Close()
		s.udpFallbackStream = nil
		return err
	}
	s.lastUDPNs.Store(time.Now().UnixNano())
	s.UpBytes.Add(uint64(len(data)))
	return nil
}

func (s *QUICSession) serveUDPStream(st *quic.Stream) {
	defer st.Close()
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(st, hdr[:]); err != nil {
			return
		}
		id := binary.BigEndian.Uint16(hdr[0:2])
		blen := int(binary.BigEndian.Uint16(hdr[2:4]))
		if blen < 4 || blen > maxStreamUDPPayload+300 {
			return
		}
		body := make([]byte, blen)
		if _, err := io.ReadFull(st, body); err != nil {
			return
		}
		s.deliverInboundUDP(id, body)
	}
}

func (s *QUICSession) sendFragmentedDG(id uint16, ab, data []byte, maxWire int) error {
	body := make([]byte, len(ab)+len(data))
	copy(body, ab)
	copy(body[len(ab):], data)

	chunkCap := maxWire - 7
	if chunkCap < 256 {
		chunkCap = 256
	}
	total := (len(body) + chunkCap - 1) / chunkCap
	if total > maxDGFrags {
		return s.sendViaUDPStream(id, ab, data)
	}
	msgID := uint16(s.nextMsgID.Add(1))
	for i := 0; i < total; i++ {
		start := i * chunkCap
		end := start + chunkCap
		if end > len(body) {
			end = len(body)
		}
		chunk := body[start:end]
		pkt := make([]byte, 7+len(chunk))
		pkt[0] = dgKindFrag
		binary.BigEndian.PutUint16(pkt[1:3], id)
		binary.BigEndian.PutUint16(pkt[3:5], msgID)
		pkt[5] = byte(i)
		pkt[6] = byte(total)
		copy(pkt[7:], chunk)
		if err := s.qconn.SendDatagram(pkt); err != nil {
			var tooLarge *quic.DatagramTooLargeError
			if errors.As(err, &tooLarge) {
				if maxWire > fallbackMaxDGPayload {
					s.maxDG.Store(fallbackMaxDGPayload)
					return s.sendFragmentedDG(id, ab, data, fallbackMaxDGPayload)
				}
				return s.sendViaUDPStream(id, ab, data)
			}
			return err
		}
	}
	s.lastUDPNs.Store(time.Now().UnixNano())
	s.UpBytes.Add(uint64(len(data)))
	return nil
}

func (s *QUICSession) sendUDPPacket(id uint16, target string, data []byte) error {
	if len(data) > maxStreamUDPPayload {
		return errors.New("gft: udp datagram exceeds 65507 bytes")
	}
	ab, err := EncodeAddr(target)
	if err != nil {
		return err
	}
	bodyLen := len(ab) + len(data)
	curMax := int(s.maxDG.Load())
	if curMax <= 0 {
		curMax = defaultMaxDGPayload
	}

	// Oversized (>8192B) -> reliable stream fallback
	if bodyLen > maxDGFragBody {
		return s.sendViaUDPStream(id, ab, data)
	}

	// Fits in single RFC 9221 datagram
	if 3+bodyLen <= curMax {
		pkt := make([]byte, 3+bodyLen)
		pkt[0] = dgKindSingle
		binary.BigEndian.PutUint16(pkt[1:3], id)
		copy(pkt[3:], ab)
		copy(pkt[3+len(ab):], data)
		if err := s.qconn.SendDatagram(pkt); err != nil {
			var tooLarge *quic.DatagramTooLargeError
			if errors.As(err, &tooLarge) {
				s.maxDG.Store(fallbackMaxDGPayload)
				return s.sendFragmentedDG(id, ab, data, fallbackMaxDGPayload)
			}
			return err
		}
		s.lastUDPNs.Store(time.Now().UnixNano())
		s.UpBytes.Add(uint64(len(data)))
		return nil
	}

	// Medium-large (1100B .. 8192B, e.g. HTTP/3 1200B+ Initial) -> Fragmented RFC 9221 Datagrams
	return s.sendFragmentedDG(id, ab, data, curMax)
}

func (s *QUICSession) sendUDPClose(id uint16) error {
	var pkt [3]byte
	pkt[0] = dgKindClose
	binary.BigEndian.PutUint16(pkt[1:3], id)
	return s.qconn.SendDatagram(pkt[:])
}

// SendUDPReply satisfies UDPReplySink so Server can send UDP responses over QUIC Datagrams.
func (s *QUICSession) SendUDPReply(id uint16, target string, data []byte) error {
	return s.sendUDPPacket(id, target, data)
}

func (s *QUICSession) SessionDone() <-chan struct{} { return s.done }

// OpenStream opens a native QUIC bidirectional stream and sends target + optional first bytes in 1 write.
func (s *QUICSession) OpenStream(target string, first []byte) (DataStream, error) {
	select {
	case <-s.done:
		return nil, ErrSessionClosed
	default:
	}
	ab, err := EncodeAddr(target)
	if err != nil {
		return nil, err
	}
	qs, err := s.qconn.OpenStreamSync(context.Background())
	if err != nil {
		s.fail(err)
		return nil, err
	}
	hdr := make([]byte, 1+2+len(ab)+2+len(first))
	hdr[0] = quicStreamData
	binary.BigEndian.PutUint16(hdr[1:3], uint16(len(ab)))
	copy(hdr[3:3+len(ab)], ab)
	binary.BigEndian.PutUint16(hdr[3+len(ab):5+len(ab)], uint16(len(first)))
	copy(hdr[5+len(ab):], first)
	if _, err := qs.Write(hdr); err != nil {
		_ = qs.Close()
		s.fail(err)
		return nil, err
	}
	s.UpBytes.Add(uint64(len(first)))
	s.streams.Add(1)
	return &QUICStream{qs: qs, target: target, sess: s}, nil
}

// OpenUDP allocates a local UDP association ID multiplexed over QUIC datagrams.
func (s *QUICSession) OpenUDP() (UDPAssociation, error) {
	return s.OpenUDPWithID(0)
}

// OpenUDPWithID opens or reuses a QUIC UDP association with an explicit AssocID.
func (s *QUICSession) OpenUDPWithID(assocID uint16) (UDPAssociation, error) {
	select {
	case <-s.done:
		return nil, ErrSessionClosed
	default:
	}
	s.mu.Lock()
	id := assocID
	if id == 0 {
		id = s.nextUDP
		s.nextUDP++
		if s.nextUDP == 0 {
			s.nextUDP = 1
		}
	}
	if existing := s.udps[id]; existing != nil {
		s.mu.Unlock()
		return existing, nil
	}
	u := &QUICUDPAssoc{
		sess:   s,
		id:     id,
		recvCh: make(chan UDPPacket, 128),
		done:   make(chan struct{}),
	}
	s.udps[id] = u
	s.mu.Unlock()
	return u, nil
}

// LastUDPTime returns when UDP traffic was last sent/received on this QUIC session.
func (s *QUICSession) LastUDPTime() time.Time {
	ns := s.lastUDPNs.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// ProbeRTT sends an in-band Ping over QUIC control stream and returns measured RTT.
func (s *QUICSession) ProbeRTT(timeout time.Duration) (time.Duration, error) {
	if s.ctrlStream == nil {
		return 0, ErrSessionClosed
	}
	for {
		select {
		case <-s.pingCh:
		default:
			goto send
		}
	}
send:
	var msg [9]byte
	msg[0] = PingReq
	binary.BigEndian.PutUint64(msg[1:9], uint64(time.Now().UnixNano()))
	s.ctrlMu.Lock()
	_, err := s.ctrlStream.Write(msg[:])
	s.ctrlMu.Unlock()
	if err != nil {
		s.fail(err)
		return 0, err
	}
	select {
	case d := <-s.pingCh:
		return d, nil
	case <-time.After(timeout):
		return 0, errors.New("quic ping timeout")
	case <-s.done:
		return 0, ErrSessionClosed
	}
}

func (s *QUICSession) RTT() time.Duration  { return time.Duration(s.rttNs.Load()) }
func (s *QUICSession) NumStreams() int     { return int(s.streams.Load()) }
func (s *QUICSession) TotalBytes() uint64  { return s.UpBytes.Load() + s.DownBytes.Load() }
func (s *QUICSession) Done() <-chan struct{} { return s.done }
func (s *QUICSession) RemotePort() int     { return s.remotePort }
func (s *QUICSession) decStreams()         { s.streams.Add(-1) }

func (s *QUICSession) Err() error {
	if e, ok := s.errVal.Load().(error); ok {
		return e
	}
	return nil
}

func (s *QUICSession) fail(err error) {
	s.closeOnce.Do(func() {
		if err != nil {
			s.errVal.Store(err)
		}
		close(s.done)
		s.udpStreamMu.Lock()
		if s.udpFallbackStream != nil {
			_ = s.udpFallbackStream.Close()
			s.udpFallbackStream = nil
		}
		s.udpStreamMu.Unlock()
		if s.qconn != nil {
			_ = s.qconn.CloseWithError(0, "closed")
		}
		if s.ownPC != nil {
			_ = s.ownPC.Close()
			if s.tr != nil {
				_ = s.tr.Close()
			}
		} else if s.tr != nil {
			tr := s.tr
			go func() { _ = tr.Close() }()
		}
		s.mu.Lock()
		for id, u := range s.udps {
			delete(s.udps, id)
			u.closeLocal()
		}
		s.mu.Unlock()
	})
}

func (s *QUICSession) Close() { s.fail(ErrSessionClosed) }

// ServeQUICConn handles an accepted server-side *quic.Conn until close.
func ServeQUICConn(ctx context.Context, qconn *quic.Conn, verifier *StegoVerifier, ps *ParamStore, h QUICStreamHandler, uh QUICUDPHandler, uc QUICUDPCloseHandler) error {
	return ServeQUICConnWithAuth(ctx, qconn, verifier, ps, nil, h, uh, uc)
}

// ServeQUICConnWithAuth handles an accepted *quic.Conn and notifies onClientID once authenticated.
func ServeQUICConnWithAuth(ctx context.Context, qconn *quic.Conn, verifier *StegoVerifier, ps *ParamStore, onClientID func([8]byte), h QUICStreamHandler, uh QUICUDPHandler, uc QUICUDPCloseHandler) error {
	qs := newBaseQUICSession(qconn, ps, false)
	qs.onStream = h
	qs.onUDP = uh
	qs.onUDPCls = uc
	defer qs.Close()

	authCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	var authed atomic.Bool
	authedCh := make(chan struct{})
	var authedOnce sync.Once
	markAuthed := func() {
		authed.Store(true)
		authedOnce.Do(func() { close(authedCh) })
	}

	go func() {
		<-authedCh
		qs.datagramRecvLoop()
	}()

	for {
		st, err := qconn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		var typ [1]byte
		_ = st.SetReadDeadline(time.Now().Add(4 * time.Second))
		if _, err := io.ReadFull(st, typ[:]); err != nil {
			_ = st.Close()
			if !authed.Load() {
				return err
			}
			continue
		}
		_ = st.SetReadDeadline(time.Time{})

		switch typ[0] {
		case quicStreamCtrl:
			salt, clientID, err := verifier.VerifyClientAuthFrameWithID(st)
			if err != nil {
				_ = st.Close()
				return err
			}
			if onClientID != nil {
				onClientID(clientID)
			}
			ack, err := BuildServerAuthAck(verifier.psk, salt, ps.Get())
			if err != nil {
				_ = st.Close()
				return err
			}
			if _, err := st.Write(ack); err != nil {
				_ = st.Close()
				return err
			}
			markAuthed()
			go func(ctrl *quic.Stream) {
				var msg [9]byte
				for {
					if _, err := io.ReadFull(ctrl, msg[:]); err != nil {
						return
					}
					if msg[0] == PingReq {
						msg[0] = PingResp
						_, _ = ctrl.Write(msg[:])
					}
				}
			}(st)

		case quicStreamUDP:
			if !authed.Load() {
				select {
				case <-authedCh:
				case <-authCtx.Done():
					_ = st.Close()
					return errors.New("gft: quic auth timeout")
				}
			}
			go qs.serveUDPStream(st)

		case quicStreamData:
			if !authed.Load() {
				select {
				case <-authedCh:
				case <-authCtx.Done():
					_ = st.Close()
					return errors.New("gft: quic auth timeout")
				}
			}
			var lenBuf [2]byte
			if _, err := io.ReadFull(st, lenBuf[:]); err != nil {
				_ = st.Close()
				continue
			}
			alen := int(binary.BigEndian.Uint16(lenBuf[:]))
			if alen == 0 || alen > 300 {
				_ = st.Close()
				continue
			}
			ab := make([]byte, alen)
			if _, err := io.ReadFull(st, ab); err != nil {
				_ = st.Close()
				continue
			}
			target, rest, err := DecodeAddr(ab)
			if err != nil || len(rest) != 0 {
				_ = st.Close()
				continue
			}
			if _, err := io.ReadFull(st, lenBuf[:]); err != nil {
				_ = st.Close()
				continue
			}
			flen := int(binary.BigEndian.Uint16(lenBuf[:]))
			if flen > MaxPayload {
				_ = st.Close()
				continue
			}
			var first []byte
			if flen > 0 {
				first = make([]byte, flen)
				if _, err := io.ReadFull(st, first); err != nil {
					_ = st.Close()
					continue
				}
				qs.DownBytes.Add(uint64(flen))
			}
			qs.streams.Add(1)
			wrapped := &QUICStream{qs: st, target: target, sess: qs}
			if h != nil {
				go h(wrapped, target, first)
			} else {
				_ = wrapped.Close()
			}
		default:
			_ = st.Close()
		}
	}
}
