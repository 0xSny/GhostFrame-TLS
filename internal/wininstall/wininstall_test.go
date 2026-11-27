//go:build windows

package wininstall

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateShortcutAndVersionFormat(t *testing.T) {
	if got := cleanVersionDisplay("v4.2.6"); got != "4.2.6" {
		t.Fatalf("cleanVersionDisplay(v4.2.6) = %q", got)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	lnk := filepath.Join(t.TempDir(), "Kestrel Pro.lnk")
	if err := CreateShortcut(lnk, exe, "-tray", filepath.Dir(exe), exe, "Kestrel Pro Test", AppUserModelID); err != nil {
		t.Fatalf("CreateShortcut failed: %v", err)
	}
	info, err := os.Stat(lnk)
	if err != nil || info.Size() < 100 {
		t.Fatalf("expected valid non-empty .lnk shortcut, err=%v size=%v", err, info)
	}
}

func TestMigrateLegacyClientConfig(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("USERPROFILE", fakeHome)
	legacyDir := t.TempDir()
	legacyCfg := filepath.Join(legacyDir, "client.json")
	if err := os.WriteFile(legacyCfg, []byte(`{"route_mode":"rule"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	MigrateLegacyClientConfig(legacyDir)
	migrated := filepath.Join(fakeHome, ".kestrel", "client.json")
	b, err := os.ReadFile(migrated)
	if err != nil || string(b) != `{"route_mode":"rule"}` {
		t.Fatalf("expected migrated config in %s, err=%v got=%q", migrated, err, string(b))
	}
}
