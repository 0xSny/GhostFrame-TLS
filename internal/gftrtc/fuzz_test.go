package gftrtc

import (
	"testing"
	"time"
)

func FuzzSTUNBindingReqAndPreScreen(f *testing.F) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	var cid [8]byte
	if req, _, _, err := BuildClientBindingReq(psk, cid, 0, 0, time.Now()); err == nil {
		f.Add(req)
	}
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42})
	guard := NewReplayGuard()
	now := time.Now()
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = PreScreenClientBindingReq(data, psk)
		_, _ = ParseClientBindingReq(data, psk, guard, now)
	})
}

func FuzzRTPAndFrameDecode(f *testing.F) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	var cid [8]byte
	now := time.Now()
	req, cliPriv, txID, err := BuildClientBindingReq(psk, cid, 0, 0, now)
	if err != nil {
		f.Fatal(err)
	}
	parsed, ok := ParseClientBindingReq(req, psk, NewReplayGuard(), now)
	if !ok {
		f.Fatal("seed parse failed")
	}
	resp, _, err := BuildServerBindingResp(psk, parsed, nil, 777, 0, 0, nil)
	if err != nil {
		f.Fatal(err)
	}
	_, keys, ok := ParseServerBindingResp(resp, psk, cliPriv, txID)
	if !ok {
		f.Fatal("seed resp parse failed")
	}
	sess := newRTCSession(false, 777, cid, "", 0, keys, 0, nil, nil)
	if bp, err := SealRTPPhase(nil, keys.C2SAEAD, keys.C2SIV, keys.C2SMask, 0, 777, 1, 100, PTVideoData, true, 1, []byte{0, 0, 0, 1, 0, 0, FramePing, 0, 0, 0, 0, 0, 0, 0, 1}); err == nil {
		f.Add(bp)
	}
	if rp, err := SealRTCPMimic(nil, keys.C2SAEAD, keys.C2SIV, keys.C2SMask, 0, 777, 1, nil); err == nil {
		f.Add(rp)
	}
	f.Add([]byte{0x80, PTVideoData, 0, 1})
	f.Add([]byte{FrameStreamOpen, 0, 0, 0, 1, 5, 'a'})

	var dst [MaxUDPPayload]byte
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = IsRTCPMimic(data)
		_ = IsRTPPacket(data)
		_, _, _, _, _, _ = OpenRTPPhase(dst[:0], data, keys.C2SAEAD, keys.C2SIV, keys.C2SMask)
		_, _ = OpenRTCPMimic(dst[:0], data, keys.C2SAEAD, keys.C2SIV, keys.C2SMask)
		_ = sess.dispatchFrames(data, now)
	})
}
