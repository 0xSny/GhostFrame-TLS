package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildSourceManifestAndServeEndpoints(t *testing.T) {
	dir := t.TempDir()
	if err := ensureRepoIcons(dir); err != nil {
		t.Fatalf("ensureRepoIcons failed: %v", err)
	}
	vpnPayload := bytes.Repeat([]byte("V"), 4096)
	compPayload := bytes.Repeat([]byte("C"), 2048)
	if err := os.WriteFile(filepath.Join(dir, vpnIPAFileName), vpnPayload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, compIPAFileName), compPayload, 0o644); err != nil {
		t.Fatal(err)
	}
	meta := buildMetadata(defaultRepo, defaultWorkflow, 999999, 42, "abcdef1234567", "feat: ios rule upgrade", "2026-11-20T06:30:00Z", "", int64(len(vpnPayload)), int64(len(compPayload)))
	if err := saveMetadata(dir, meta); err != nil {
		t.Fatal(err)
	}

	h := newRepoHandler(dir, "192.168.1.7", "18080")

	// 1. Check /source.json schema compatibility (ESign flat fields + AltStore versions[])
	req := httptest.NewRequest(http.MethodGet, "http://192.168.1.7:18080/source.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/source.json status=%d", rec.Code)
	}
	var got SourceManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode source.json: %v", err)
	}
	if got.SourceURL != "http://192.168.1.7:18080/source.json" || len(got.Apps) != 2 {
		t.Fatalf("unexpected manifest header: %+v", got)
	}
	if got.Apps[0].Version != "4.0.0.42" || got.Apps[0].Size != int64(len(vpnPayload)) || len(got.Apps[0].Versions) != 1 {
		t.Fatalf("unexpected VPN app entry: %+v", got.Apps[0])
	}
	if got.Apps[1].BundleIdentifier != "com.ghostframe.companion" || got.Apps[1].Size != int64(len(compPayload)) {
		t.Fatalf("unexpected Companion app entry: %+v", got.Apps[1])
	}

	// 2. Check browser fallback page /
	reqHTML := httptest.NewRequest(http.MethodGet, "http://192.168.1.7:18080/", nil)
	recHTML := httptest.NewRecorder()
	h.ServeHTTP(recHTML, reqHTML)
	if recHTML.Code != http.StatusOK || !strings.Contains(recHTML.Body.String(), "4.0.0.42") || !strings.Contains(recHTML.Body.String(), vpnIPAFileName) {
		t.Fatalf("unexpected HTML root page status=%d", recHTML.Code)
	}

	// 3. Check IPA static download with Range support
	reqRange := httptest.NewRequest(http.MethodGet, "http://192.168.1.7:18080/"+vpnIPAFileName, nil)
	reqRange.Header.Set("Range", "bytes=0-15")
	recRange := httptest.NewRecorder()
	h.ServeHTTP(recRange, reqRange)
	if recRange.Code != http.StatusPartialContent || recRange.Body.Len() != 16 {
		t.Fatalf("expected 206 partial content 16 bytes, got status=%d len=%d", recRange.Code, recRange.Body.Len())
	}
}

func TestExtractIPAFromZipAndRedirectHeaderStrip(t *testing.T) {
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	fw, err := zw.Create("nested/GhostFrame-VPN-Unsigned.ipa")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("PK-ipa-payload-123456")
	_, _ = fw.Write(want)
	_ = zw.Close()

	dst := filepath.Join(t.TempDir(), "GhostFrame-VPN-Unsigned.ipa")
	n, err := extractIPAFromZip(zbuf.Bytes(), dst)
	if err != nil || n != int64(len(want)) {
		t.Fatalf("extractIPAFromZip failed: n=%d err=%v", n, err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("extracted bytes mismatch")
	}

	// Verify cross-host redirect strips Authorization header
	client := buildHTTPClient(nil)
	first, _ := http.NewRequest(http.MethodGet, "https://api.github.com/repos/a/b/actions/artifacts/1/zip", nil)
	second, _ := http.NewRequest(http.MethodGet, "https://pipelinesghubeus1.actions.githubusercontent.com/blob?sig=1", nil)
	second.Header.Set("Authorization", "Bearer secret-token")
	if err := client.CheckRedirect(second, []*http.Request{first}); err != nil {
		t.Fatal(err)
	}
	if second.Header.Get("Authorization") != "" {
		t.Fatalf("expected Authorization stripped on cross-host redirect")
	}

	if ip := detectLANIPv4(); ip == "" {
		t.Fatalf("detectLANIPv4 returned empty string")
	}
	if !isVirtualInterfaceName("VMware Network Adapter VMnet8") || isVirtualInterfaceName("网线") {
		t.Fatalf("unexpected virtual interface classification")
	}

	if got := parseGitHubRepoFromRemoteURL("https://github.com/Spittingjiu/GhostFrame-iOS.git\n"); got != "Spittingjiu/GhostFrame-iOS" {
		t.Fatalf("unexpected HTTPS remote slug: %q", got)
	}
	if got := parseGitHubRepoFromRemoteURL("git@github.com:Spittingjiu/GhostFrame-TLS.git"); got != "Spittingjiu/GhostFrame-TLS" {
		t.Fatalf("unexpected SSH remote slug: %q", got)
	}
}
