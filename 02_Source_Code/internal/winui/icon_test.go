//go:build windows

package winui

import (
	"testing"

	"ghostframe/internal/client"
)

func TestCreateVectorIconAllStates(t *testing.T) {
	states := []client.ConnState{
		client.StateDisconnected,
		client.StateConnecting,
		client.StateConnected,
		client.StateError,
	}
	for _, st := range states {
		h := CreateVectorIcon(st)
		if h == 0 {
			t.Fatalf("CreateVectorIcon(%s) returned 0", st)
		}
		_, _, _ = pDestroyIcon.Call(h)
	}
}
