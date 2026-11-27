package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v4.2.6", "v4.2.5", 1},
		{"4.2.6", "v4.2.6", 0},
		{"v4.2.5", "v4.2.10", -1},
		{"v4.3.0", "v4.2.99", 1},
		{"v4.2.6-beta", "v4.2.6", -1},
	}
	for _, tc := range cases {
		if got := CompareVersions(tc.a, tc.b); got != tc.want {
			t.Fatalf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCheckAndDownloadClientUpdate(t *testing.T) {
	SetNoSysProxy(true)
	eng, err := NewEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	// Create a valid dummy >1MB Windows PE binary starting with MZ
	fakeExe := make([]byte, 1200*1024)
	fakeExe[0] = 'M'
	fakeExe[1] = 'Z'
	sum := sha256.Sum256(fakeExe)
	sumHex := hex.EncodeToString(sum[:])

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/repos/Spittingjiu/Ghost/releases":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"tag_name":     "v4.2.6",
					"published_at": "2026-11-27T12:00:00Z",
					"body":         "- Windows installer\n- Check for updates",
					"html_url":     ts.URL + "/Spittingjiu/Ghost/releases/tag/v4.2.6",
					"assets": []map[string]any{
						{"name": ClientWindowsAssetName, "size": len(fakeExe), "browser_download_url": ts.URL + "/dl/" + ClientWindowsAssetName},
						{"name": "checksums.txt", "size": 120, "browser_download_url": ts.URL + "/dl/checksums.txt"},
					},
				},
				{
					"tag_name": "v4.2.4",
					"assets": []map[string]any{
						{"name": ClientWindowsAssetName, "size": 10, "browser_download_url": ts.URL + "/old"},
						{"name": "checksums.txt", "size": 10, "browser_download_url": ts.URL + "/oldsum"},
					},
				},
			})
		case "/dl/checksums.txt":
			_, _ = fmt.Fprintf(w, "%s  %s\n", sumHex, ClientWindowsAssetName)
		case "/dl/" + ClientWindowsAssetName:
			_, _ = w.Write(fakeExe)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	opts := UpdateCheckOptions{
		Repo:           "Spittingjiu/Ghost",
		CurrentVersion: "v4.2.5",
		APIBaseURL:     ts.URL + "/api",
		WebBaseURL:     ts.URL,
		HTTPClient:     ts.Client(),
	}
	info, err := eng.CheckClientUpdate(context.Background(), opts)
	if err != nil {
		t.Fatalf("CheckClientUpdate failed: %v", err)
	}
	if !info.HasUpdate || info.TagName != "v4.2.6" {
		t.Fatalf("unexpected release info: %+v", info)
	}

	dest := filepath.Join(t.TempDir(), ClientWindowsAssetName)
	var lastProg int64
	err = eng.DownloadAndVerifyClientUpdate(context.Background(), info, dest, opts, func(dl, tot int64) {
		lastProg = dl
	})
	if err != nil {
		t.Fatalf("DownloadAndVerifyClientUpdate failed: %v", err)
	}
	if lastProg != int64(len(fakeExe)) {
		t.Fatalf("expected final progress=%d, got %d", len(fakeExe), lastProg)
	}
	gotBytes, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(gotBytes, fakeExe) {
		t.Fatalf("downloaded binary mismatch: err=%v len=%d", err, len(gotBytes))
	}

	// Verify 302 redirect fallback when API is rate-limited (HTTP 403).
	var tsFallback *httptest.Server
	tsFallback = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/repos/Spittingjiu/Ghost/releases", "/api/repos/Spittingjiu/Ghost/releases/latest":
			http.Error(w, "rate limited", http.StatusForbidden)
		case "/Spittingjiu/Ghost/releases/latest":
			http.Redirect(w, r, tsFallback.URL+"/Spittingjiu/Ghost/releases/tag/v4.2.7", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer tsFallback.Close()

	fbInfo, err := eng.CheckClientUpdate(context.Background(), UpdateCheckOptions{
		CurrentVersion: "v4.2.6",
		APIBaseURL:     tsFallback.URL + "/api",
		WebBaseURL:     tsFallback.URL,
		HTTPClient:     tsFallback.Client(),
	})
	if err != nil {
		t.Fatalf("redirect fallback check failed: %v", err)
	}
	if !fbInfo.HasUpdate || fbInfo.TagName != "v4.2.7" {
		t.Fatalf("unexpected fallback release info: %+v", fbInfo)
	}
}

func TestDownloadVerifiedBinaryChunkedMZ(t *testing.T) {
	payload := make([]byte, 1024*1024+128)
	payload[0] = 'M'
	payload[1] = 'Z'
	sum := sha256.Sum256(payload)
	wantSHA := hex.EncodeToString(sum[:])

	for _, tc := range []struct {
		name       string
		firstChunk int
		corruptMZ  bool
		badSHA     bool
		wantErr    bool
	}{
		{name: "first_read_1_byte", firstChunk: 1},
		{name: "first_read_2_bytes", firstChunk: 2},
		{name: "normal_chunked", firstChunk: 32 * 1024},
		{name: "bad_magic_rejected", firstChunk: 1, corruptMZ: true, wantErr: true},
		{name: "bad_sha_rejected", firstChunk: 1, badSHA: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := append([]byte(nil), payload...)
			if tc.corruptMZ {
				data[0] = 'X'
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fl, _ := w.(http.Flusher)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(data[:tc.firstChunk])
				if fl != nil {
					fl.Flush()
				}
				_, _ = w.Write(data[tc.firstChunk:])
			}))
			defer srv.Close()

			dest := filepath.Join(t.TempDir(), "Kestrel-Pro.exe")
			sha := wantSHA
			if tc.badSHA {
				sha = "0000000000000000000000000000000000000000000000000000000000000000"
			}
			err := downloadVerifiedBinary(context.Background(), srv.Client(), srv.URL, dest, sha, int64(len(data)), "v4.2.6", nil)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got, rerr := os.ReadFile(dest)
			if rerr != nil || !bytes.Equal(got, data) {
				t.Fatalf("downloaded file mismatch: err=%v len=%d", rerr, len(got))
			}
		})
	}
}
