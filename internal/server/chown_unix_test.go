//go:build !windows

package server

import "testing"

func TestResolveDesiredOwnerPrefersNonRootDirWhenClobbered(t *testing.T) {
	// Normal existing non-root file keeps its uid/gid
	uid, gid, ok := resolveDesiredOwnerFromStats(998, 998, true, 998, 998, true)
	if !ok || uid != 998 || gid != 998 {
		t.Fatalf("expected file uid/gid 998/998, got %d/%d ok=%v", uid, gid, ok)
	}

	// File previously clobbered to root (0:0) inside gft:gft dir (998:998) heals to 998:998
	uid2, gid2, ok2 := resolveDesiredOwnerFromStats(0, 0, true, 998, 998, true)
	if !ok2 || uid2 != 998 || gid2 != 998 {
		t.Fatalf("expected dir uid/gid 998/998 to heal root-clobbered file, got %d/%d ok=%v", uid2, gid2, ok2)
	}

	// Brand-new .bak file (fileOK=false) inside gft:gft dir inherits 998:998
	uid3, gid3, ok3 := resolveDesiredOwnerFromStats(0, 0, false, 998, 998, true)
	if !ok3 || uid3 != 998 || gid3 != 998 {
		t.Fatalf("expected new file to inherit dir uid/gid 998/998, got %d/%d ok=%v", uid3, gid3, ok3)
	}

	// Root-owned dir + root-owned file does not chown
	_, _, ok4 := resolveDesiredOwnerFromStats(0, 0, true, 0, 0, true)
	if ok4 {
		t.Fatalf("expected shouldChown=false when both file and dir are root")
	}
}
