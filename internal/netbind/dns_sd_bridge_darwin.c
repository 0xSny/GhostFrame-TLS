//go:build darwin && cgo

#include <dns_sd.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include "_cgo_export.h"

static void DNSSD_API ghostDNSAddrInfoReply(
	DNSServiceRef sdRef,
	DNSServiceFlags flags,
	uint32_t interfaceIndex,
	DNSServiceErrorType errorCode,
	const char *hostname,
	const struct sockaddr *address,
	uint32_t ttl,
	void *context
) {
	(void)sdRef;
	(void)interfaceIndex;
	(void)hostname;
	(void)ttl;

	int32_t more = (flags & kDNSServiceFlagsMoreComing) ? 1 : 0;
	int32_t fam = 0;
	void *addr6 = NULL;
	if (address != NULL) {
		fam = (int32_t)address->sa_family;
		if (address->sa_family == AF_INET6) {
			addr6 = (void *)&((const struct sockaddr_in6 *)address)->sin6_addr;
		}
	}
	ghostNetbindOnAddrInfo((int32_t)errorCode, more, fam, addr6, context);
}

DNSServiceErrorType ghostStartDNSGetAddrInfo(
	DNSServiceRef *sdRef,
	uint32_t interfaceIndex,
	const char *hostname,
	void *ctxPtr
) {
	return DNSServiceGetAddrInfo(
		sdRef,
		0,
		interfaceIndex,
		kDNSServiceProtocol_IPv6,
		hostname,
		ghostDNSAddrInfoReply,
		ctxPtr
	);
}
