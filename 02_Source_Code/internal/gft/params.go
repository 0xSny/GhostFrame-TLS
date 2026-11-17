package gft

import (
	"encoding/json"
	"errors"
	"math/rand/v2"
	"sync"
	"sync/atomic"
)

// Params are the tunable obfuscation and keepalive parameters for GFT v2.
type Params struct {
	PadMin  int `json:"pmin"`  // min small-packet perturbation padding (0..64)
	PadMax  int `json:"pmax"`  // max small-packet perturbation padding (0..512)
	PadProb int `json:"pprob"` // probability % for small-packet perturbation after frame 8 (0..100)
	HbMinMs int `json:"hbmin"` // min idle-aware noise heartbeat interval (ms)
	HbMaxMs int `json:"hbmax"` // max idle-aware noise heartbeat interval (ms)
}

// DefaultParams returns the v2 production defaults.
func DefaultParams() Params {
	return Params{PadMin: 0, PadMax: 64, PadProb: 35, HbMinMs: 25000, HbMaxMs: 55000}
}

func (p Params) Validate() error {
	if p.PadMin < 0 || p.PadMax > 512 || p.PadMin > p.PadMax {
		return errors.New("pmin/pmax must satisfy 0<=pmin<=pmax<=512")
	}
	if p.PadProb < 0 || p.PadProb > 100 {
		return errors.New("pprob must be 0..100")
	}
	if p.HbMinMs < 1000 || p.HbMaxMs < p.HbMinMs || p.HbMaxMs > 600000 {
		return errors.New("hbmin>=1000, hbmax>=hbmin, hbmax<=600000 (ms)")
	}
	return nil
}

// ParamStore holds hot-swappable obfuscation params.
type ParamStore struct{ v atomic.Pointer[Params] }

func NewParamStore(p Params) *ParamStore { s := &ParamStore{}; s.v.Store(&p); return s }
func (s *ParamStore) Get() Params        { return *s.v.Load() }
func (s *ParamStore) Set(p Params)       { s.v.Store(&p) }

func MarshalParams(p Params) []byte { b, _ := json.Marshal(p); return b }

func randRange(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	return lo + rand.IntN(hi-lo+1)
}

// fillRandom fills b with cheap pseudo-random bytes without allocating.
func fillRandom(b []byte) {
	i := 0
	for ; i+8 <= len(b); i += 8 {
		v := rand.Uint64()
		b[i] = byte(v)
		b[i+1] = byte(v >> 8)
		b[i+2] = byte(v >> 16)
		b[i+3] = byte(v >> 24)
		b[i+4] = byte(v >> 32)
		b[i+5] = byte(v >> 40)
		b[i+6] = byte(v >> 48)
		b[i+7] = byte(v >> 56)
	}
	if i < len(b) {
		v := rand.Uint64()
		for ; i < len(b); i++ {
			b[i] = byte(v)
			v >>= 8
		}
	}
}

const frameBufSize = 8 + 65535 + 512

var (
	bufPool    = sync.Pool{New: func() any { b := make([]byte, frameBufSize); return &b }}
	lowMemPool = make(chan *[]byte, 12)
)

// GetBuf returns a pooled frame-sized buffer.
func GetBuf() *[]byte {
	if IsLowMemMode() {
		select {
		case b := <-lowMemPool:
			return b
		default:
			b := make([]byte, frameBufSize)
			return &b
		}
	}
	return bufPool.Get().(*[]byte)
}

// PutBuf returns a buffer to the pool (bounded to 12 buffers in LowMemMode).
func PutBuf(b *[]byte) {
	if b == nil {
		return
	}
	if IsLowMemMode() {
		select {
		case lowMemPool <- b:
		default:
		}
		return
	}
	bufPool.Put(b)
}
