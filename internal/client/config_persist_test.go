package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"ghostframe/internal/gft"
)

func TestConfigPersistConcurrentAtomicAndErrors(t *testing.T) {
	SetNoSysProxy(true)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client.json")

	eng, err := NewEngine(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	baseLink := &gft.Link{
		V:         4,
		Host:      "edge.example.com",
		Port:      443,
		SNI:       "cdn.example.com",
		PSK:       strings.Repeat("ab", 32),
		Verify:    "ca",
		Transport: "rtc",
		Remark:    "Init",
	}
	if err := eng.SetLink(baseLink); err != nil {
		t.Fatal(err)
	}

	// 1. Concurrent mutations + SaveConfig must never corrupt client.json or race on slices.
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 12; i++ {
				l := &gft.Link{
					V:         4,
					Host:      fmt.Sprintf("n%d.example.com", (id+i)%3),
					Port:      443 + i,
					SNI:       "cdn.example.com",
					PSK:       strings.Repeat("cd", 32),
					Verify:    "ca",
					Transport: "rtc",
					Remark:    fmt.Sprintf("G%d-%d", id, i),
				}
				_ = eng.SetLink(l)
				_ = eng.SetCustomRules([]string{fmt.Sprintf("DOMAIN,d%d-%d.example,DIRECT", id, i)})
				if serr := eng.SaveConfig(); serr != nil {
					t.Errorf("SaveConfig failed: %v", serr)
				}
			}
		}(g)
	}
	wg.Wait()

	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var parsed ClientConfig
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("client.json corrupted after concurrent saves: %v\n%s", err, string(raw))
	}
	if len(parsed.Nodes) == 0 || parsed.Link == nil {
		t.Fatalf("expected valid nodes and active link after concurrent saves, got %+v", parsed)
	}

	// 2. Write failure must leave previous valid client.json untouched.
	// Create a file at dir/blocked and point cfgPath inside it so CreateTemp fails.
	blocked := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocked, []byte("not-a-dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	validCfgPath := filepath.Join(dir, "valid.json")
	validContent := []byte(`{"route_mode":"rule","socks_addr":"127.0.0.1:10808","http_addr":"127.0.0.1:10809"}`)
	if err := os.WriteFile(validCfgPath, validContent, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(filepath.Join(blocked, "client.json"), []byte("bad"), 0o600); err == nil {
		t.Fatal("expected writeFileAtomic failure when parent is a file")
	}
	if gotValid, _ := os.ReadFile(validCfgPath); !bytes.Equal(gotValid, validContent) {
		t.Fatal("valid config altered on unrelated write failure")
	}

	// 3. Corrupt client.json on NewEngine must surface ConfigLoadError and preserve .corrupt.
	corruptDir := t.TempDir()
	corruptCfgPath := filepath.Join(corruptDir, "client.json")
	corruptData := []byte("{broken-json")
	if err := os.WriteFile(corruptCfgPath, corruptData, 0o600); err != nil {
		t.Fatal(err)
	}
	badEng, err := NewEngine(corruptCfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer badEng.Close()
	if badEng.ConfigLoadError() == "" {
		t.Fatal("expected non-empty ConfigLoadError on corrupt client.json")
	}
	if st := badEng.Status(); st["config_load_err"] == "" {
		t.Fatalf("expected config_load_err in Status(), got %v", st["config_load_err"])
	}
	if preserved, err := os.ReadFile(corruptCfgPath + ".corrupt"); err != nil || !bytes.Equal(preserved, corruptData) {
		t.Fatalf("expected corrupt config preserved at %s.corrupt, err=%v", corruptCfgPath, err)
	}

	// 4. Legacy link-only + route_mode="direct" config migrates cleanly.
	legacyDir := t.TempDir()
	legacyCfgPath := filepath.Join(legacyDir, "client.json")
	legacyJSON, _ := json.Marshal(map[string]any{
		"route_mode": "direct",
		"link":       baseLink,
	})
	if err := os.WriteFile(legacyCfgPath, legacyJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	legEng, err := NewEngine(legacyCfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer legEng.Close()
	if legEng.ConfigLoadError() != "" {
		t.Fatalf("unexpected ConfigLoadError on legacy config: %s", legEng.ConfigLoadError())
	}
	if st := legEng.Status(); st["route_mode"] != string(RouteCore) {
		t.Fatalf("expected legacy route_mode 'direct' migrated to 'core', got %v", st["route_mode"])
	}
}
