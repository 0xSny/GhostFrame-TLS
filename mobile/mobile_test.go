package mobile

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"ghostframe/internal/gft"
	"ghostframe/internal/netbind"
)

func TestInitCoreGuardrails(t *testing.T) {
	tmp := t.TempDir()

	InitCore(tmp, true)
	if !gft.IsLowMemMode() {
		t.Fatal("expected LowMemMode=true for PacketTunnel extension")
	}
	if netbind.DirectBindEnabled() {
		t.Fatal("expected DirectBindEnabled=false inside PacketTunnel extension")
	}
	if got := gft.EffectiveUDPSocketBuffer(); got != 512*1024 {
		t.Fatalf("expected 512KB UDP socket buffer in tunnel ext mode, got %d", got)
	}

	InitCore(tmp, false)
	t.Cleanup(func() { netbind.SetDirectBindEnabled(true) })
	if gft.IsLowMemMode() {
		t.Fatal("expected LowMemMode=false for Companion single-process mode")
	}
	if !netbind.DirectBindEnabled() {
		t.Fatal("expected DirectBindEnabled=true in Companion single-process mode")
	}
	if got := gft.EffectiveUDPSocketBuffer(); got != 8*1024*1024 {
		t.Fatalf("expected 8MB UDP socket buffer in companion mode, got %d", got)
	}
}

func TestParseLinkJSONAndEnvelope(t *testing.T) {
	link := &gft.Link{
		V:         3,
		Host:      "198.51.100.10",
		Port:      443,
		SNI:       "cdn.example.net",
		PSK:       strings.Repeat("ab", 32),
		Verify:    "ca",
		FP:        "ios",
		Transport: "auto",
		HopRange:  "20000-20099",
		UpMbps:    50,
		DownMbps:  200,
		Remark:    "Edge-Test",
	}
	uri := link.Encode()

	raw, err := ParseLinkJSON(uri)
	if err != nil {
		t.Fatalf("ParseLinkJSON failed: %v", err)
	}
	var parsed parsedLinkInfo
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("unmarshal parsed link failed: %v", err)
	}
	if parsed.Host != "198.51.100.10" || parsed.Port != 443 || parsed.HopRange != "20000-20099" || parsed.Remark != "Edge-Test" {
		t.Fatalf("unexpected parsed link fields: %+v", parsed)
	}

	envRaw := ParseLinkEnvelopeJSON("not-a-valid-uri")
	var env jsonEnvelope
	if err := json.Unmarshal([]byte(envRaw), &env); err != nil {
		t.Fatalf("unmarshal error envelope failed: %v", err)
	}
	if env.OK || env.Error == "" {
		t.Fatalf("expected error envelope, got %+v", env)
	}
}

func TestBuildShadowrocketAddURL(t *testing.T) {
	got := BuildShadowrocketAddURL(10808, "HK Edge 01")
	if !strings.HasPrefix(got, "shadowrocket://add/socks://") {
		t.Fatalf("unexpected scheme prefix: %s", got)
	}
	rest := strings.TrimPrefix(got, "shadowrocket://add/socks://")
	u, err := url.Parse("http://dummy/" + rest)
	if err != nil {
		t.Fatalf("parse URL tail failed: %v", err)
	}
	b64Part := strings.TrimPrefix(u.Path, "/")
	decoded, err := base64.StdEncoding.DecodeString(b64Part)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	if string(decoded) != ":@127.0.0.1:10808" {
		t.Fatalf("unexpected decoded SOCKS payload: %q", string(decoded))
	}
	if u.Query().Get("udp") != "1" {
		t.Fatalf("expected udp=1 query param, got %q", u.RawQuery)
	}
	if u.Query().Get("remarks") != "HK Edge 01" {
		t.Fatalf("expected remark 'HK Edge 01', got %q", u.Query().Get("remarks"))
	}
}

func TestBuildBypassRule(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"198.51.100.10", "IP-CIDR,198.51.100.10/32,DIRECT"},
		{"198.51.100.10:443", "IP-CIDR,198.51.100.10/32,DIRECT"},
		{"2001:db8::1", "IP-CIDR6,2001:db8::1/128,DIRECT"},
		{"edge.example.com:443", "DOMAIN,edge.example.com,DIRECT"},
		{"  ", ""},
	}
	for _, tc := range cases {
		if got := BuildBypassRule(tc.in); got != tc.want {
			t.Fatalf("BuildBypassRule(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIdleLifecycleAndStatusJSON(t *testing.T) {
	InitCore(t.TempDir(), false)
	OnNetworkChanged("pdp_ip0")
	t.Cleanup(func() { netbind.SetPreferredInterface("") })

	statusRaw := GetStatusJSON()
	var m map[string]any
	if err := json.Unmarshal([]byte(statusRaw), &m); err != nil {
		t.Fatalf("GetStatusJSON invalid JSON: %v", err)
	}
	if m["state"] != "disconnected" {
		t.Fatalf("expected disconnected state, got %v", m["state"])
	}
	if diag := GetDiagnosticSnapshot(); !strings.Contains(diag, "Kestrel Mobile Diagnostic") {
		t.Fatalf("unexpected idle diagnostic snapshot: %s", diag)
	}

	if err := StartEngine(`{}`); err == nil {
		t.Fatal("expected StartEngine with empty link_uri to fail")
	}
	if env := StartEngineJSON(`bad-json`); !strings.Contains(env, `"ok":false`) {
		t.Fatalf("expected ok:false JSON envelope, got %s", env)
	}
	if err := StopEngine(); err != nil {
		t.Fatalf("StopEngine while idle failed: %v", err)
	}

	link := &gft.Link{
		V:         3,
		Host:      "127.0.0.1",
		Port:      1,
		SNI:       "cdn.example.net",
		PSK:       strings.Repeat("cd", 32),
		Verify:    "ca",
		FP:        "ios",
		Transport: "tcp",
		Remark:    "AsyncStartTest",
	}
	asyncCfg, err := json.Marshal(mobileStartConfig{
		LinkURI:      link.Encode(),
		SocksPort:    29081,
		HTTPPort:     29082,
		RouteMode:    "rule",
		AsyncConnect: true,
	})
	if err != nil {
		t.Fatalf("marshal async config failed: %v", err)
	}
	if err := StartEngine(string(asyncCfg)); err != nil {
		t.Fatalf("expected async StartEngine to bind local servers without blocking on tunnel dial, got: %v", err)
	}
	t.Cleanup(func() { _ = StopEngine() })

	hc := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
	}
	pingResp, err := hc.Get("http://127.0.0.1:29082/_ksl/ping")
	if err != nil {
		t.Fatalf("GET /_ksl/ping failed: %v", err)
	}
	pingBody, _ := io.ReadAll(pingResp.Body)
	pingResp.Body.Close()
	if pingResp.StatusCode != http.StatusOK || !strings.Contains(string(pingBody), `"pong":true`) {
		t.Fatalf("unexpected /_ksl/ping response (%d): %s", pingResp.StatusCode, string(pingBody))
	}

	statusResp, err := hc.Get("http://127.0.0.1:29082/_ksl/status")
	if err != nil {
		t.Fatalf("GET /_ksl/status failed: %v", err)
	}
	statusBody, _ := io.ReadAll(statusResp.Body)
	statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected /_ksl/status status code %d: %s", statusResp.StatusCode, string(statusBody))
	}
	var snap map[string]any
	if err := json.Unmarshal(statusBody, &snap); err != nil {
		t.Fatalf("invalid JSON from /_ksl/status: %v (%s)", err, string(statusBody))
	}
	if _, ok := snap["netbind_enabled"]; !ok {
		t.Fatalf("expected netbind_enabled in /_ksl/status payload, got: %v", snap)
	}

	if err := StopEngine(); err != nil {
		t.Fatalf("StopEngine after async StartEngine failed: %v", err)
	}
}
