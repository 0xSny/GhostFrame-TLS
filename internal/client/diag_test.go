package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ghostframe/internal/gft"
)

func TestDiagnosticSnapshotAnonymizesTargetsByDefault(t *testing.T) {
	SetNoSysProxy(true)
	dir := t.TempDir()
	eng, err := NewEngine(filepath.Join(dir, "client.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	link := &gft.Link{
		V:         4,
		Host:      "vps.secret-node.example",
		Port:      443,
		SNI:       "cdn.secret-sni.example",
		PSK:       strings.Repeat("ab", 32),
		Pin:       "sha256/secretpin123456",
		Verify:    "ca",
		Transport: "rtc",
		Remark:    "SecretNode",
	}
	if err := eng.SetLink(link); err != nil {
		t.Fatal(err)
	}
	shareURI := link.Encode()

	// Record synthetic targets: domain, IPv4, IPv6, node host, and a log line with a share link.
	eng.RecordTargetTraffic("private.bank.example:443", 4096, 8192)
	eng.RecordTargetTraffic("203.0.113.77:8443", 2048, 1024)
	eng.RecordTargetTraffic("[2001:db8:abcd::42]:443", 1024, 512)
	eng.RecordTargetTraffic("vps.secret-node.example:443", 512, 256)
	eng.Logf("Dialing %s via 203.0.113.77 and 2001:db8:abcd::42", shareURI)

	outPath, _, text, err := eng.ExportDiagnosticSnapshot(0)
	if err != nil {
		t.Fatalf("ExportDiagnosticSnapshot failed: %v", err)
	}
	fileBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile diag snapshot failed: %v", err)
	}
	for _, sample := range []string{text, string(fileBytes)} {
		for _, secret := range []string{
			"private.bank.example",
			"203.0.113.77",
			"2001:db8:abcd::42",
			"vps.secret-node.example",
			"cdn.secret-sni.example",
			link.PSK,
			"secretpin123456",
			"ksl4://secret",
		} {
			if strings.Contains(sample, secret) {
				t.Fatalf("diagnostic snapshot leaked %q:\n%s", secret, sample)
			}
		}
		if !strings.Contains(sample, "target-01") {
			t.Fatalf("expected anonymized target-01 alias in default snapshot:\n%s", sample)
		}
	}

	// Opt-in raw targets shows non-node destination targets when explicitly requested.
	rawSnap := eng.BuildDiagnosticSnapshotWithOptions(DiagnosticOptions{IncludeRawTargets: true})
	if !strings.Contains(rawSnap, "private.bank.example") {
		t.Fatalf("expected raw target when IncludeRawTargets=true:\n%s", rawSnap)
	}
	if strings.Contains(rawSnap, "vps.secret-node.example") {
		t.Fatalf("node host must still be masked when IncludeRawTargets=true:\n%s", rawSnap)
	}
}
