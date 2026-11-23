//go:build darwin && cgo

package netbind

/*
#include <dns_sd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>

extern void ghostNetbindDNSAddrInfoCB(
	DNSServiceRef sdRef,
	DNSServiceFlags flags,
	uint32_t interfaceIndex,
	DNSServiceErrorType errorCode,
	const char *hostname,
	const struct sockaddr *address,
	uint32_t ttl,
	void *context
);
*/
import "C"

import (
	"context"
	"errors"
	"net"
	"runtime/cgo"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const dnsSDLookupTimeout = 1500 * time.Millisecond

type dnsSDAddrState struct {
	ips     []net.IP
	errCode C.DNSServiceErrorType
	done    bool
}

func init() {
	lookupIPv6Fn = darwinDNSServiceLookupIPv6
}

//export ghostNetbindDNSAddrInfoCB
func ghostNetbindDNSAddrInfoCB(
	_ C.DNSServiceRef,
	flags C.DNSServiceFlags,
	_ C.uint32_t,
	errorCode C.DNSServiceErrorType,
	_ *C.char,
	address *C.struct_sockaddr,
	_ C.uint32_t,
	contextPtr unsafe.Pointer,
) {
	if contextPtr == nil {
		return
	}
	h := cgo.Handle(*(*C.uintptr_t)(contextPtr))
	state, ok := h.Value().(*dnsSDAddrState)
	if !ok || state == nil {
		return
	}
	if errorCode != C.kDNSServiceErr_NoError {
		state.errCode = errorCode
		state.done = true
		return
	}
	if address != nil && address.sa_family == C.AF_INET6 {
		addr6 := (*C.struct_sockaddr_in6)(unsafe.Pointer(address))
		raw := C.GoBytes(unsafe.Pointer(&addr6.sin6_addr), 16)
		ip := net.IP(raw)
		if !IsFakeIP(ip) && !ip.IsUnspecified() {
			state.ips = append(state.ips, ip)
		}
	}
	if flags&C.kDNSServiceFlagsMoreComing == 0 {
		state.done = true
	}
}

// darwinDNSServiceLookupIPv6 resolves AAAA records via Apple's <dns_sd.h> DNSServiceGetAddrInfo
// pinned to the active physical interface index (bypassing utun DNS interception inside NE).
func darwinDNSServiceLookupIPv6(ctx context.Context, host string) ([]net.IP, error) {
	h := strings.TrimSpace(strings.Trim(host, "[]"))
	if h == "" {
		return nil, errors.New("netbind: empty host for DNSServiceGetAddrInfo")
	}

	iface, ok := resolveTargetInterface()
	if !ok || iface.Index <= 0 {
		return defaultLookupIPv6(ctx, h)
	}

	ctxPtr := C.malloc(C.size_t(unsafe.Sizeof(C.uintptr_t(0))))
	if ctxPtr == nil {
		return nil, errors.New("netbind: failed to allocate dns_sd context")
	}
	defer C.free(ctxPtr)

	state := &dnsSDAddrState{}
	handle := cgo.NewHandle(state)
	defer handle.Delete()
	*(*C.uintptr_t)(ctxPtr) = C.uintptr_t(handle)

	cHost := C.CString(h)
	defer C.free(unsafe.Pointer(cHost))

	var sdRef C.DNSServiceRef
	errCode := C.DNSServiceGetAddrInfo(
		&sdRef,
		0,
		C.uint32_t(iface.Index),
		C.kDNSServiceProtocol_IPv6,
		cHost,
		(C.DNSServiceGetAddrInfoReply)(C.ghostNetbindDNSAddrInfoCB),
		ctxPtr,
	)
	if errCode != C.kDNSServiceErr_NoError || sdRef == nil {
		return nil, errors.New("netbind: DNSServiceGetAddrInfo failed")
	}
	defer C.DNSServiceRefDeallocate(sdRef)

	fd := int(C.DNSServiceRefSockFD(sdRef))
	if fd < 0 {
		return nil, errors.New("netbind: invalid DNSServiceRef socket fd")
	}

	deadline := time.Now().Add(dnsSDLookupTimeout)
	if ctx != nil {
		if ctxDeadline, hasDeadline := ctx.Deadline(); hasDeadline && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
	}

	pollFds := []unix.PollFd{{
		Fd:     int32(fd),
		Events: unix.POLLIN,
	}}

	for !state.done {
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			return nil, context.DeadlineExceeded
		}
		waitMs := int(rem.Milliseconds())
		if waitMs < 1 {
			waitMs = 1
		}
		n, perr := unix.Poll(pollFds, waitMs)
		if perr == unix.EINTR {
			continue
		}
		if perr != nil {
			return nil, perr
		}
		if n == 0 {
			return nil, context.DeadlineExceeded
		}
		if procErr := C.DNSServiceProcessResult(sdRef); procErr != C.kDNSServiceErr_NoError {
			if len(state.ips) > 0 {
				return state.ips, nil
			}
			return nil, errors.New("netbind: DNSServiceProcessResult failed")
		}
	}

	if len(state.ips) == 0 {
		return nil, errors.New("netbind: DNSServiceGetAddrInfo returned no IPv6 addresses")
	}
	return state.ips, nil
}
