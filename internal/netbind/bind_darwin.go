//go:build darwin

package netbind

import (
	"net"
	"syscall"
)

const (
	ipBoundIF   = 25  // IP_BOUND_IF on Darwin <netinet/in.h>
	ipv6BoundIF = 125 // IPV6_BOUND_IF on Darwin <netinet6/in6.h>
)

// DetectPhysicalInterface enumerates live interfaces on Darwin/iOS and picks the primary
// non-tunnel physical interface (preferring preferred iface, then en0, then pdp_ip*).
func DetectPhysicalInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	candidates := make([]InterfaceCandidate, 0, len(ifaces))
	for _, iface := range ifaces {
		candidates = append(candidates, InterfaceCandidate{
			Name:       iface.Name,
			Up:         iface.Flags&net.FlagUp != 0,
			Loopback:   iface.Flags&net.FlagLoopback != 0,
			HasUnicast: interfaceHasValidUnicast(iface),
		})
	}
	return SelectBestInterface(candidates, PreferredInterface())
}

func resolveTargetInterface() (*net.Interface, bool) {
	if pref := PreferredInterface(); pref != "" && !IsExcludedInterfaceName(pref) {
		if iface, err := net.InterfaceByName(pref); err == nil &&
			iface.Index > 0 &&
			iface.Flags&net.FlagUp != 0 &&
			iface.Flags&net.FlagLoopback == 0 &&
			interfaceHasValidUnicast(*iface) {
			return iface, true
		}
	}
	ifName := DetectPhysicalInterface()
	if ifName == "" {
		return nil, false
	}
	iface, err := net.InterfaceByName(ifName)
	if err != nil || iface.Index <= 0 {
		return nil, false
	}
	return iface, true
}

func interfaceHasRoutableFamily(iface *net.Interface, wantV4 bool) bool {
	if iface == nil {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if !isRoutableUnicastIP(ip) {
			continue
		}
		if wantV4 && ip.To4() != nil {
			return true
		}
		if !wantV4 && ip.To4() == nil {
			return true
		}
	}
	return false
}

// Control implements net.Dialer.Control and net.ListenConfig.Control on Darwin/iOS.
// When direct binding is enabled (e.g., Companion app running alongside an external utun),
// it best-effort pins outbound sockets to the physical interface carrying the matching IP family.
// Inside iOS NEPacketTunnelProvider (DirectBindEnabled == false), it leaves routing to the OS
// so 4G/5G cellular (including NAT64/CLAT46) and Wi-Fi work seamlessly without EPERM/blackholes.
func Control(network, address string, c syscall.RawConn) error {
	if !DirectBindEnabled() || isLoopbackAddress(address) {
		return nil
	}
	iface, ok := resolveTargetInterface()
	if !ok {
		return nil
	}
	hasV4 := interfaceHasRoutableFamily(iface, true)
	hasV6 := interfaceHasRoutableFamily(iface, false)
	if !hasV4 && !hasV6 {
		return nil
	}

	var hostIP net.IP
	if host, _, splitErr := net.SplitHostPort(address); splitErr == nil {
		hostIP = net.ParseIP(host)
	}

	_ = c.Control(func(fd uintptr) {
		switch network {
		case "tcp4", "udp4":
			if hasV4 {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIF, iface.Index)
			}
		case "tcp6", "udp6":
			if hasV6 {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6BoundIF, iface.Index)
			}
		default:
			if hostIP != nil {
				if hostIP.To4() != nil {
					if hasV4 {
						_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIF, iface.Index)
					}
				} else if hasV6 {
					_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6BoundIF, iface.Index)
				}
				return
			}
			if hasV4 {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIF, iface.Index)
			}
			if hasV6 {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6BoundIF, iface.Index)
			}
		}
	})
	return nil
}
