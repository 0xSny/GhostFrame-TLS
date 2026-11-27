//go:build setup_embed

package main

import (
	"bytes"
	"compress/zlib"
	_ "embed"
	"io"
)

//go:embed Kestrel-Pro.payload.zlib
var embeddedPayloadZlib []byte

func openSetupPayload() (io.ReadCloser, error) {
	zr, err := zlib.NewReader(bytes.NewReader(embeddedPayloadZlib))
	if err != nil {
		return nil, err
	}
	return zr, nil
}
