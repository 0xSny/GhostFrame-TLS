package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"ghostframe/internal/gft"
	"ghostframe/internal/server"
)

func startLocalServerWithTransport(t *testing.T, transport string) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	sec, err := server.InitWithOptions(server.InitOptions{
		ConfDir:      filepath.Join(dir, "conf"),
		StateDir:     filepath.Join(dir, "state"),
		Host:         "127.0.0.1",
		Listen:       "127.0.0.1:0",
		SNI:          "localhost",
		CertMode:     "self_signed_90d",
		FallbackMode: "builtin",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := server.LoadConfig(filepath.Join(dir, "conf", "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.DisableQUIC = transport == "tcp"
	cfg.DisableRTC = transport == "tcp"
	srv, err := server.New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Run(ctx)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a := srv.TCPAddr(); a != nil {
			if transport != "rtc" || srv.UDPAddr() != nil {
				l, perr := gft.ParseLink(sec.Link)
				if perr != nil {
					cancel()
					<-done
					t.Fatal(perr)
				}
				_, pStr, _ := net.SplitHostPort(a.String())
				fmt.Sscanf(pStr, "%d", &l.Port)
				l.Transport = transport
				l.Remark = "HTTPProxy-" + transport
				return l.Encode(), func() {
					cancel()
					<-done
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatalf("local test server (%s) did not start", transport)
	return "", nil
}

func TestHTTPProxyNonConnectStreamingUploads(t *testing.T) {
	SetNoSysProxy(true)
	prevAllowPrivate := server.AllowPrivateTargets
	server.AllowPrivateTargets = true
	t.Cleanup(func() {
		server.AllowPrivateTargets = prevAllowPrivate
		gft.SetLowMemMode(false)
	})

	// Local upstream HTTP server on 127.0.0.2 (distinct from 127.0.0.1 node host to avoid anti-loop).
	upLn, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	firstChunkSeen := make(chan struct{}, 16)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream-check" {
			buf := make([]byte, 4096)
			n, _ := r.Body.Read(buf)
			if n > 0 {
				select {
				case firstChunkSeen <- struct{}{}:
				default:
				}
			}
			h := sha256.New()
			h.Write(buf[:n])
			total := int64(n)
			copied, err := io.Copy(h, r.Body)
			total += copied
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_, _ = fmt.Fprintf(w, "%d:%x", total, h.Sum(nil))
			return
		}
		h := sha256.New()
		n, err := io.Copy(h, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintf(w, "%d:%x", n, h.Sum(nil))
	}))
	upstream.Listener = upLn
	upstream.Start()
	defer upstream.Close()
	upURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	targetURL := "http://127.0.0.2:" + upURL.Port()

	modes := []struct {
		name      string
		transport string
		lowMem    bool
		direct    bool
	}{
		{name: "direct", direct: true},
		{name: "single_tcp", transport: "tcp", lowMem: true},
		{name: "bonded_tcp", transport: "tcp", lowMem: false},
		{name: "rtc", transport: "rtc", lowMem: false},
	}

	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			gft.SetLowMemMode(m.lowMem)
			eng, err := NewEngine(filepath.Join(t.TempDir(), "client.json"))
			if err != nil {
				t.Fatal(err)
			}
			defer eng.Close()
			eng.OverrideListenAddrs("127.0.0.1:0", "127.0.0.1:0")

			if m.direct {
				if err := eng.SetRouteMode(RouteRule); err != nil {
					t.Fatal(err)
				}
				if err := eng.SetCustomRules([]string{"IP-CIDR,127.0.0.2/32,DIRECT"}); err != nil {
					t.Fatal(err)
				}
			} else {
				uri, stopSrv := startLocalServerWithTransport(t, m.transport)
				defer stopSrv()
				link, err := gft.ParseLink(uri)
				if err != nil {
					t.Fatal(err)
				}
				if err := eng.SetRouteMode(RouteGlobal); err != nil {
					t.Fatal(err)
				}
				if err := eng.SetLink(link); err != nil {
					t.Fatal(err)
				}
				if err := eng.Connect(); err != nil {
					t.Fatalf("Connect(%s) failed: %v", m.name, err)
				}
			}
			if err := eng.StartServers(); err != nil {
				t.Fatal(err)
			}

			proxyURL, err := url.Parse("http://" + eng.httpSrv.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			hc := &http.Client{
				Timeout: 20 * time.Second,
				Transport: &http.Transport{
					Proxy:             http.ProxyURL(proxyURL),
					DisableKeepAlives: true,
				},
			}

			// 1. Content-Length uploads across small, ~64KB boundary, >64KB, and 2MB payloads
			for _, sz := range []int{1024, 65500, 128 * 1024, 2 << 20} {
				payload := make([]byte, sz)
				_, _ = rand.Read(payload)
				wantSum := sha256.Sum256(payload)
				wantResp := fmt.Sprintf("%d:%x", sz, wantSum)

				resp, err := hc.Post(targetURL+"/upload", "application/octet-stream", bytes.NewReader(payload))
				if err != nil {
					t.Fatalf("%s size=%d POST failed: %v", m.name, sz, err)
				}
				gotBytes, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK || string(gotBytes) != wantResp {
					t.Fatalf("%s size=%d mismatch: status=%d got=%q want=%q", m.name, sz, resp.StatusCode, string(gotBytes), wantResp)
				}
			}

			// 2. Chunked Transfer-Encoding upload (ContentLength == -1) + true streaming check
			for len(firstChunkSeen) > 0 {
				<-firstChunkSeen
			}
			pr, pw := io.Pipe()
			part1 := make([]byte, 8192)
			part2 := make([]byte, 120*1024)
			_, _ = rand.Read(part1)
			_, _ = rand.Read(part2)
			var combined []byte
			combined = append(combined, part1...)
			combined = append(combined, part2...)
			wantChunked := fmt.Sprintf("%d:%x", len(combined), sha256.Sum256(combined))

			req, err := http.NewRequest(http.MethodPost, targetURL+"/stream-check", pr)
			if err != nil {
				t.Fatal(err)
			}
			req.ContentLength = -1

			type httpRes struct {
				resp *http.Response
				err  error
			}
			resCh := make(chan httpRes, 1)
			go func() {
				r, doErr := hc.Do(req)
				resCh <- httpRes{r, doErr}
			}()

			if _, err := pw.Write(part1); err != nil {
				t.Fatalf("pipe write part1 failed: %v", err)
			}
			select {
			case <-firstChunkSeen:
			case <-time.After(5 * time.Second):
				_ = pw.Close()
				t.Fatalf("%s: upstream did not receive initial streamed chunk before body EOF (buffering regression)", m.name)
			}
			if _, err := pw.Write(part2); err != nil {
				t.Fatalf("pipe write part2 failed: %v", err)
			}
			_ = pw.Close()

			res := <-resCh
			if res.err != nil {
				t.Fatalf("%s chunked POST failed: %v", m.name, res.err)
			}
			gotChunked, _ := io.ReadAll(res.resp.Body)
			res.resp.Body.Close()
			if res.resp.StatusCode != http.StatusOK || string(gotChunked) != wantChunked {
				t.Fatalf("%s chunked mismatch: status=%d got=%q want=%q", m.name, res.resp.StatusCode, string(gotChunked), wantChunked)
			}
		})
	}
}
