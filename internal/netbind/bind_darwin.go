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
			iface.Flags&net.FlagLoopback == 0 {
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
// It pins outbound sockets directly to the physical interface via IP_BOUND_IF / IPV6_BOUND_IF
// so traffic inside PacketTunnel / utun never loops back into the virtual VPN interface.
func Control(network, address string, c syscall.RawConn) error {
	if isLoopbackAddress(address) {
		return nil
	}
	iface, ok := resolveTargetInterface()
	if !ok {
		return nil
	}

	var hostIP net.IP
	if host, _, splitErr := net.SplitHostPort(address); splitErr == nil {
		hostIP = net.ParseIP(host)
	}

	var sockErr error
	ctrlErr := c.Control(func(fd uintptr) {
		switch network {
		case "tcp4", "udp4":
			sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIF, iface.Index)
		case "tcp6", "udp6":
			sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6BoundIF, iface.Index)
		default:
			if hostIP != nil {
				if hostIP.To4() != nil {
					sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIF, iface.Index)
				} else {
					sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6BoundIF, iface.Index)
				}
				return
			}
			// Unqualified dual-stack network with unspecified/wildcard host (e.g., ListenConfig ":0").
			err4 := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIF, iface.Index)
			err6 := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6BoundIF, iface.Index)
			if err4 != nil && err6 != nil {
				sockErr = err4
			}
		}
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	return sockErr
}
