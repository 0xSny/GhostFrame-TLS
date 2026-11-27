package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ghostframe/internal/gft"
)

func TestAuditFlushRetryAndConcurrentRecord(t *testing.T) {
	dir := t.TempDir()
	// Make audit path point inside a file-blocked parent so first Flush fails.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(blocker, "audit.json")
	a := NewAudit(auditPath)
	a.Record("203.0.113.10", "pre_tls_probe")
	if err := a.Flush(); err == nil {
		t.Fatal("expected Flush to fail when parent path is a file")
	}
	// dirtyVer must remain ahead of flushedVer so a later Flush retries without new events.
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(blocker, 0o755); err != nil {
		t.Fatal(err)
	}
	a.Record("203.0.113.11", "bad_auth")
	if err := a.Flush(); err != nil {
		t.Fatalf("expected retry Flush to succeed: %v", err)
	}
	b, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("203.0.113.10")) || !bytes.Contains(b, []byte("203.0.113.11")) {
		t.Fatalf("missing audit entries after retry Flush: %s", string(b))
	}
}

func TestPanelUpdateParamsReportsPersistenceError(t *testing.T) {
	dir := t.TempDir()
	_, err := InitWithOptions(InitOptions{
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
	cfg, err := LoadConfig(filepath.Join(dir, "conf", "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	panel := &Panel{srv: srv}

	// Make params.json a directory so saveParams fails.
	paramsDir := filepath.Join(cfg.StateDir, "params.json")
	if err := os.MkdirAll(paramsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	p := gft.DefaultParams()
	body, _ := json.Marshal(p)
	req := httptest.NewRequest(http.MethodPost, "/api/params", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	panel.handleUpdateParams(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when params persistence fails, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"runtime_applied":true`) || !strings.Contains(rec.Body.String(), `"persisted":false`) {
		t.Fatalf("expected runtime_applied/persisted distinction in error JSON: %s", rec.Body.String())
	}
}
