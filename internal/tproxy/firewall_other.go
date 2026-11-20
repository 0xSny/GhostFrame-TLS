//go:build !linux

package tproxy

func DetectLANEnvironment() (ifaceName, lanIP, gatewayIP string) {
	return "", "", ""
}

func HasNFTTProxy() bool                        { return false }
func CalibrateKernel(lanIface string)           {}
func ApplyFirewall(spec FirewallSpec) (string, error) { return "none (non-linux)", nil }
func CleanupFirewall(tproxyMark, routeTable int) {}
func ReadSystemStats() (memUsedMB, memTotalMB, cpuPct float64) { return 0, 0, 0 }
