//go:build !windows

package client

// SetSystemProxy updates in-memory mock state when sandboxed; no-op on non-Windows.
func SetSystemProxy(addr string, enable bool) error {
	if IsMockSysProxy() {
		setMockSystemProxy(addr, enable)
	}
	return nil
}

// GetSystemProxy returns mock state when sandboxed.
func GetSystemProxy() (bool, string, error) {
	if IsMockSysProxy() {
		return getMockSystemProxy()
	}
	return false, "", nil
}

// QueryFullSystemProxy returns mock snapshot when sandboxed.
func QueryFullSystemProxy() (ProxySnapshot, error) {
	if IsMockSysProxy() {
		return queryMockSystemProxy(), nil
	}
	return ProxySnapshot{}, nil
}

// ApplySystemProxySnapshot applies mock snapshot when sandboxed.
func ApplySystemProxySnapshot(snap ProxySnapshot) error {
	if IsMockSysProxy() {
		applyMockSystemProxySnapshot(snap)
	}
	return nil
}
