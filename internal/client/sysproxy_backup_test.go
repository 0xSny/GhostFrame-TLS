package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSystemProxyBackupWriteFailureLeavesOSUnchanged(t *testing.T) {
	SetNoSysProxy(true)
	t.Cleanup(func() { applyMockSystemProxySnapshot(ProxySnapshot{}) })
	orig := ProxySnapshot{Enabled: true, Server: "corp.proxy.local:8080", Override: "*.corp.local"}
	applyMockSystemProxySnapshot(orig)

	// Point backupPath at an existing directory so writeFileAtomic fails.
	badBackup := filepath.Join(t.TempDir(), "existing_dir")
	if err := os.MkdirAll(badBackup, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := EnableSystemProxyWithBackup("127.0.0.1:10809", badBackup); err == nil {
		t.Fatal("expected EnableSystemProxyWithBackup to fail when backupPath is a directory")
	}
	got := queryMockSystemProxy()
	if got != orig {
		t.Fatalf("OS proxy mutated on backup failure: got=%+v want=%+v", got, orig)
	}
}

func TestSystemProxyCorruptBackupPreservedAndOSUnchanged(t *testing.T) {
	SetNoSysProxy(true)
	orig := ProxySnapshot{Enabled: true, Server: "127.0.0.1:7890", Override: "<local>"}
	applyMockSystemProxySnapshot(orig)

	backupPath := filepath.Join(t.TempDir(), "sysproxy_backup.json")
	if err := os.WriteFile(backupPath, []byte("{corrupt-json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := DisableAndRestoreSystemProxy(backupPath); err == nil {
		t.Fatal("expected DisableAndRestoreSystemProxy to fail on corrupt backup")
	}
	if _, err := os.Stat(backupPath + ".corrupt"); err != nil {
		t.Fatalf("expected corrupt backup preserved at %s.corrupt: %v", backupPath, err)
	}
	got := queryMockSystemProxy()
	if got != orig {
		t.Fatalf("OS proxy must remain untouched when backup is corrupt: got=%+v want=%+v", got, orig)
	}
}

func TestSystemProxyThirdPartyLoopbackAndManualChange(t *testing.T) {
	SetNoSysProxy(true)
	t.Cleanup(func() { applyMockSystemProxySnapshot(ProxySnapshot{}) })

	// 1. Late-starting third-party loopback proxy (closed port 127.0.0.1:7890) must be preserved.
	thirdParty := ProxySnapshot{Enabled: true, Server: "127.0.0.1:7890", Override: "localhost;<local>"}
	applyMockSystemProxySnapshot(thirdParty)

	backupPath := filepath.Join(t.TempDir(), "sysproxy_backup.json")
	if err := EnableSystemProxyWithBackup("127.0.0.1:10809", backupPath); err != nil {
		t.Fatalf("EnableSystemProxyWithBackup failed: %v", err)
	}
	if got := queryMockSystemProxy(); !got.Enabled || got.Server != "127.0.0.1:10809" {
		t.Fatalf("expected Kestrel proxy applied, got %+v", got)
	}

	// Port swap updates live HTTPAddr; DisableAndRestoreSystemProxyFor verifies ownership against current addr.
	if err := SetSystemProxy("127.0.0.1:10819", true); err != nil {
		t.Fatal(err)
	}
	if err := DisableAndRestoreSystemProxyFor(backupPath, "127.0.0.1:10819"); err != nil {
		t.Fatalf("DisableAndRestoreSystemProxyFor failed: %v", err)
	}
	if got := queryMockSystemProxy(); got != thirdParty {
		t.Fatalf("expected third-party loopback proxy restored field-for-field: got=%+v want=%+v", got, thirdParty)
	}
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("expected backup file removed after clean restore, stat err=%v", err)
	}

	// 2. Without backup, RecoverSystemProxyIfDirtyFor must NOT clear unrelated loopback proxy.
	recovered, err := RecoverSystemProxyIfDirtyFor(backupPath, "127.0.0.1:10809")
	if err != nil || recovered {
		t.Fatalf("must not clear unrelated third-party loopback proxy: recovered=%v err=%v", recovered, err)
	}
	if got := queryMockSystemProxy(); got != thirdParty {
		t.Fatalf("third-party proxy altered: got=%+v", got)
	}

	// 3. If user manually changes OS proxy during session, DisableAndRestoreSystemProxy must preserve user's change.
	applyMockSystemProxySnapshot(ProxySnapshot{Enabled: false})
	if err := EnableSystemProxyWithBackup("127.0.0.1:10809", backupPath); err != nil {
		t.Fatal(err)
	}
	userManual := ProxySnapshot{Enabled: true, Server: "manual.corp:3128", Override: "*.internal"}
	applyMockSystemProxySnapshot(userManual)

	if err := DisableAndRestoreSystemProxy(backupPath); err != nil {
		t.Fatalf("DisableAndRestoreSystemProxy failed: %v", err)
	}
	if got := queryMockSystemProxy(); got != userManual {
		t.Fatalf("manual proxy overwritten on disable: got=%+v want=%+v", got, userManual)
	}
}
