package client

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ghostframe/internal/gft"
)

// LocalMgmtHandler handles loopback-only management API calls under /_gft/* routes.
type LocalMgmtHandler func(method, path string, body []byte) (statusCode int, contentType string, respBody []byte)

var (
	localMgmtMu      sync.RWMutex
	localMgmtHandler LocalMgmtHandler
)

// SetLocalMgmtHandler registers an in-process management handler for loopback /_gft/* requests.
func SetLocalMgmtHandler(fn LocalMgmtHandler) {
	localMgmtMu.Lock()
	localMgmtHandler = fn
	localMgmtMu.Unlock()
}

// HTTPProxyServer handles incoming HTTP and HTTPS (CONNECT) proxy requests.
type HTTPProxyServer struct {
	addr         string
	engine       *Engine
	listener     net.Listener
	closed       chan struct{}
	mu           sync.Mutex
	lastDisLogNs atomic.Int64
}

func (s *HTTPProxyServer) logDisconnectedThrottled() {
	now := time.Now().UnixNano()
	prev := s.lastDisLogNs.Load()
	if now-prev >= int64(5*time.Second) && s.lastDisLogNs.CompareAndSwap(prev, now) {
		st := s.engine.Status()
		stateStr, _ := st["state"].(string)
		errStr, _ := st["last_err"].(string)
		if len(errStr) > 120 {
			errStr = errStr[:120] + "..."
		}
		if errStr != "" {
			s.engine.Logf("[HTTP Proxy] Request rejected (state=%s, err=%s)", stateStr, errStr)
		} else {
			s.engine.Logf("[HTTP Proxy] Waiting for connection (state=%s): local requests paused until connected", stateStr)
		}
	}
}

// NewHTTPProxyServer creates a new HTTP proxy server instance.
func NewHTTPProxyServer(addr string, eng *Engine) *HTTPProxyServer {
	return &HTTPProxyServer{
		addr:   addr,
		engine: eng,
		closed: make(chan struct{}),
	}
}

// Start begins listening and serving connections.
func (s *HTTPProxyServer) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-s.closed:
					return
				default:
					time.Sleep(50 * time.Millisecond)
					continue
				}
			}
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
			}
			go s.handleConn(c)
		}
	}()
	return nil
}

// Addr returns the listener address.
func (s *HTTPProxyServer) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Close stops the HTTP proxy server.
func (s *HTTPProxyServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closed:
		return nil
	default:
		close(s.closed)
	}
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *HTTPProxyServer) handleConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method != http.MethodConnect && req.URL.Scheme == "" && req.URL.Host == "" && strings.HasPrefix(req.URL.Path, "/_gft/") {
		localMgmtMu.RLock()
		fn := localMgmtHandler
		localMgmtMu.RUnlock()
		if fn != nil && isLoopbackRemote(c.RemoteAddr()) {
			s.serveLocalMgmt(c, req, fn)
			return
		}
	}

	if !s.engine.IsConnected() {
		s.logDisconnectedThrottled()
		resp := "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nGhostFrame not connected to server\r\n"
		_, _ = c.Write([]byte(resp))
		return
	}

	if req.Method == http.MethodConnect {
		target := req.Host
		if !strings.Contains(target, ":") {
			target += ":443"
		}
		var sniffConn net.Conn = c
		if br.Buffered() > 0 {
			buffered := make([]byte, br.Buffered())
			n, _ := br.Read(buffered)
			sniffConn = &bufferedConn{Conn: c, pre: buffered[:n]}
		}
		sendOK := func() error {
			_, werr := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			return werr
		}
		st, act, rc, ackSent, err := s.engine.OpenStreamWithOptionalSNISniff(sniffConn, target, sendOK)
		if err != nil {
			if act == ActionProxy {
				s.engine.Logf("[HTTP Proxy] CONNECT %s failed: %v", target, err)
			}
			if !ackSent {
				if act == ActionReject {
					_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"))
				} else {
					_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
				}
			}
			return
		}
		defer st.Close()

		if !ackSent {
			if err := sendOK(); err != nil {
				return
			}
		}
		_ = c.SetDeadline(time.Time{})
		gft.Relay(st, rc, 15*time.Minute)
		return
	}

	target := req.Host
	if !strings.Contains(target, ":") {
		target += ":80"
	}
	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	var reqBuf bytes.Buffer
	if err := req.Write(&reqBuf); err != nil {
		return
	}

	st, act, err := s.engine.OpenTargetStream(target, reqBuf.Bytes())
	if err != nil {
		if act == ActionProxy {
			s.engine.Logf("[HTTP Proxy] %s %s failed: %v", req.Method, target, err)
		}
		if act == ActionReject {
			_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"))
		} else {
			_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		}
		return
	}
	defer st.Close()

	_ = c.SetDeadline(time.Time{})
	gft.Relay(st, c, 15*time.Minute)
}

func isLoopbackRemote(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *HTTPProxyServer) serveLocalMgmt(c net.Conn, req *http.Request, fn LocalMgmtHandler) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(req.Body, 64*1024))
		_ = req.Body.Close()
	}
	status, contentType, respBody := fn(req.Method, req.URL.Path, body)
	if status <= 0 {
		status = http.StatusOK
	}
	if strings.TrimSpace(contentType) == "" {
		contentType = "application/json; charset=utf-8"
	}
	statusText := http.StatusText(status)
	if statusText == "" {
		statusText = "OK"
	}
	var hdr strings.Builder
	hdr.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", status, statusText))
	hdr.WriteString("Content-Type: " + contentType + "\r\n")
	hdr.WriteString("Content-Length: " + strconv.Itoa(len(respBody)) + "\r\n")
	hdr.WriteString("Cache-Control: no-store\r\n")
	hdr.WriteString("Connection: close\r\n\r\n")
	_, _ = c.Write([]byte(hdr.String()))
	if len(respBody) > 0 {
		_, _ = c.Write(respBody)
	}
}

type bufferedConn struct {
	net.Conn
	pre []byte
	off int
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	if b.off < len(b.pre) {
		n := copy(p, b.pre[b.off:])
		b.off += n
		if b.off >= len(b.pre) {
			b.pre = nil
			b.off = 0
		}
		return n, nil
	}
	return b.Conn.Read(p)
}

func (b *bufferedConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
