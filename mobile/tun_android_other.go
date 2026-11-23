//go:build !android

package mobile

import "errors"

// StartTUNWithFD is supported only on Android VpnService file descriptors.
func StartTUNWithFD(fd int, mtu int) error {
	return errors.New("mobile: StartTUNWithFD is only supported on Android")
}

// StartTUNWithFDJSON wraps StartTUNWithFD into a JSON envelope.
func StartTUNWithFDJSON(fd int, mtu int) string {
	return marshalEnvelope(StartTUNWithFD(fd, mtu), nil)
}
