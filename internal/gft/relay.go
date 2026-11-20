package gft

import (
	"io"
	"net"
	"sync"
	"time"
)

// CopyBuf copies src to dst using a pooled buffer (no per-call allocation).
func CopyBuf(dst io.Writer, src io.Reader, onN func(int)) error {
	bp := GetBuf()
	defer PutBuf(bp)
	chunk := 32 * 1024
	if IsLowMemMode() {
		chunk = 16 * 1024
	}
	buf := (*bp)[:chunk]
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if onN != nil {
				onN(n)
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

type deadliner struct {
	c    net.Conn
	idle time.Duration
}

func (d deadliner) Read(p []byte) (int, error) {
	if d.idle > 0 {
		_ = d.c.SetReadDeadline(time.Now().Add(d.idle))
	}
	return d.c.Read(p)
}

type writeDeadliner struct {
	c    net.Conn
	idle time.Duration
}

func (w writeDeadliner) Write(p []byte) (int, error) {
	if w.idle > 0 {
		_ = w.c.SetWriteDeadline(time.Now().Add(w.idle))
	}
	return w.c.Write(p)
}

// Relay pipes a DataStream and a TCP-like connection in both directions until both finish.
// idle is the per-I/O idle timeout applied on the TCP connection (defaults to 120s if <= 0).
func Relay(st DataStream, c net.Conn, idle time.Duration) {
	if idle <= 0 {
		idle = 120 * time.Second
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // stream -> conn
		defer wg.Done()
		err := CopyBuf(writeDeadliner{c, idle}, st, nil)
		if cw, ok := c.(interface{ CloseWrite() error }); ok && err == nil {
			_ = cw.CloseWrite()
		} else {
			_ = c.Close()
		}
	}()
	go func() { // conn -> stream
		defer wg.Done()
		err := CopyBuf(st, deadliner{c, idle}, nil)
		if err == nil {
			_ = st.CloseWrite()
		} else {
			_ = st.Close()
		}
	}()
	wg.Wait()
	_ = c.Close()
	_ = st.Close()
}
