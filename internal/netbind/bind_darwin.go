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

func init() {
	isPureIPv6PhysicalFn = isPureIPv6PhysicalDarwin
	physicalFamiliesFn = physicalInterfaceFamiliesDarwin
}

func physicalInterfaceFamiliesDarwin() (bool, bool) {
	iface, ok := resolveTargetInterface()
	if !ok {
		return true, false
	}
	hasV4 := interfaceHasRoutableFamily(iface, true)
	hasV6 := interfaceHasRoutableFamily(iface, false)
	if !hasV4 && !hasV6 {
		return true, false
	}
	return hasV4, hasV6
}

func isPureIPv6PhysicalDarwin() bool {
	iface, ok := resolveTargetInterface()
	if !ok {
		return false
	}
	return !interfaceHasRoutableFamily(iface, true) && interfaceHasRoutableFamily(iface, false)
}

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

// Control implements net.Dialer.Control and net.ListenConfig.Control on Darwin/iOS.
// When DirectBindEnabled() is true (including inside NEPacketTunnelProvider when pinning
// direct and proxy sockets around utun), it binds non-loopback sockets to the active
// physical interface via IP_BOUND_IF/IPV6_BOUND_IF and rejects Fake-IP targets to block loops.
func Control(network, address string, c syscall.RawConn) error {
	if isLoopbackAddress(address) {
		return nil
	}
	hostIP := parseAddressIP(address)
	if IsFakeIP(hostIP) {
		return syscall.EADDRNOTAVAIL
	}
	if !DirectBindEnabled() {
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
