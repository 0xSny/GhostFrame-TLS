import Foundation
import GhostMobile
import Network
import NetworkExtension
import WidgetKit

private final class PacketFlowTunWriter: NSObject, MobileTunPacketWriterProtocol {
    private weak var flow: NEPacketTunnelFlow?

    init(flow: NEPacketTunnelFlow) {
        self.flow = flow
        super.init()
    }

    func writePacket(_ pkt: Data?, family: Int) {
        autoreleasepool {
            guard let data = pkt, !data.isEmpty, let flow = self.flow else { return }
            let pktVersion = data[data.startIndex] >> 4
            let proto: Int32 = (pktVersion == 6) ? AF_INET6 : AF_INET
            flow.writePackets([data], withProtocols: [NSNumber(value: proto)])
        }
    }

    func writePacketBatch(_ concat: Data?, lens: Data?, count: Int, family: Int) {
        autoreleasepool {
            guard let data = concat, let lenBytes = lens, count > 0, lenBytes.count >= count * 2, let flow = self.flow else {
                return
            }
            var packets: [Data] = []
            var protos: [NSNumber] = []
            packets.reserveCapacity(count)
            protos.reserveCapacity(count)

            let v4Num = NSNumber(value: AF_INET)
            let v6Num = NSNumber(value: AF_INET6)
            var offset = 0
            for i in 0..<count {
                let hi = Int(lenBytes[i * 2])
                let lo = Int(lenBytes[i * 2 + 1])
                let pktLen = (hi << 8) | lo
                guard pktLen > 0, offset + pktLen <= data.count else { break }
                let pkt = data.subdata(in: offset..<(offset + pktLen))
                let pktVersion = pkt[pkt.startIndex] >> 4
                packets.append(pkt)
                protos.append(pktVersion == 6 ? v6Num : v4Num)
                offset += pktLen
            }
            if !packets.isEmpty {
                flow.writePackets(packets, withProtocols: protos)
            }
        }
    }
}

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var pathMonitor: NWPathMonitor?
    private let monitorQueue = DispatchQueue(label: "com.kestrel.duo.tunnel.pathmonitor")
    private let reloadQueue = DispatchQueue(label: "com.kestrel.duo.tunnel.reload")
    private var lastPhysicalIface: String = ""
    private var lastPathSignature: String = ""
    private var pathDebounceWorkItem: DispatchWorkItem?
    private var currentHTTPPort: Int = 10809
    private var currentServerHost: String = ""
    private var currentRouteMode: String = "rule"
    private var currentEnableIPv6: Bool = false
    private var tunWriter: PacketFlowTunWriter?
    private let tunLock = NSLock()
    private var tunReading: Bool = false

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let providerCfg = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        let configJSON = (providerCfg?["configJSON"] as? String)
            ?? (options?["configJSON"] as? String)
            ?? ""

        guard !configJSON.isEmpty else {
            let err = NSError(
                domain: "com.kestrel.duo.tunnel",
                code: 1001,
                userInfo: [NSLocalizedDescriptionKey: "Missing NETunnelProviderProtocol.providerConfiguration[\"configJSON\"]"]
            )
            completionHandler(err)
            return
        }

        let decodedCfg = GhostEngineConfig.decode(from: configJSON)
        var serverHost = (providerCfg?["serverHost"] as? String) ?? ""
        if serverHost.isEmpty, let linkURI = decodedCfg?.linkURI {
            if case .success(let node) = GhostMobileBridge.parseLink(uri: linkURI) {
                serverHost = node.host
            }
        }
        let httpPort = (providerCfg?["httpPort"] as? Int) ?? decodedCfg?.httpPort ?? 10809
        let routeMode = (decodedCfg?.routeMode ?? "rule").lowercased()
        let enableIPv6 = decodedCfg?.enableIPv6 ?? false

        let startConfigJSON: String
        if var cfg = decodedCfg {
            cfg.asyncConnect = true
            startConfigJSON = cfg.toJSONString()
        } else {
            startConfigJSON = configJSON
        }

        let supportDir = GhostNetworkHelper.appSupportDirectory(subdir: "KestrelTunnel")
        GhostMobileBridge.initCore(dataDir: supportDir, isTunnelExt: true)
        let initialIface = startNetworkMonitorAndDetectInitialInterface(timeout: 0.35)
        if !initialIface.isEmpty {
            GhostMobileBridge.onNetworkChanged(ifaceName: initialIface)
        }

        switch GhostMobileBridge.startEngine(configJSON: startConfigJSON) {
        case .failure(let err):
            stopNetworkMonitor()
            completionHandler(err)
            return
        case .success:
            break
        }

        currentHTTPPort = httpPort
        currentServerHost = serverHost
        currentRouteMode = routeMode
        currentEnableIPv6 = enableIPv6

        let settings = buildNetworkSettings(httpPort: httpPort, serverHost: serverHost, routeMode: routeMode, enableIPv6: enableIPv6)
        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                _ = GhostMobileBridge.stopEngine()
                self?.stopNetworkMonitor()
                completionHandler(error)
                return
            }
            if let self = self {
                if routeMode != "core" {
                    if case .failure(let tunErr) = self.startTUNForwarding(mtu: 1400) {
                        _ = GhostMobileBridge.stopEngine()
                        self.stopNetworkMonitor()
                        completionHandler(tunErr)
                        return
                    }
                }
                self.notifyControlCenterReload()
            }
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        stopTUNForwarding()
        stopNetworkMonitor()
        _ = GhostMobileBridge.stopEngine()
        notifyControlCenterReload()
        completionHandler()
    }

    private func startTUNForwarding(mtu: Int) -> Result<Void, Error> {
        let writer = PacketFlowTunWriter(flow: self.packetFlow)
        self.tunWriter = writer
        switch GhostMobileBridge.startTUN(writer: writer, mtu: mtu) {
        case .failure(let err):
            return .failure(err)
        case .success:
            break
        }

        tunLock.lock()
        let alreadyReading = tunReading
        tunReading = true
        tunLock.unlock()

        if !alreadyReading {
            readPacketsLoop()
        }
        return .success(())
    }

    private func stopTUNForwarding() {
        tunLock.lock()
        tunReading = false
        tunLock.unlock()
        GhostMobileBridge.stopTUN()
        tunWriter = nil
    }

    private func readPacketsLoop() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }
            self.tunLock.lock()
            let active = self.tunReading
            self.tunLock.unlock()
            guard active else { return }

            autoreleasepool {
                var totalBytes = 0
                var validCount = 0
                for (idx, pkt) in packets.enumerated() {
                    if idx < protocols.count && (protocols[idx].int32Value == AF_INET || protocols[idx].int32Value == AF_INET6) && pkt.count > 0 && pkt.count <= 0xFFFF {
                        totalBytes += pkt.count
                        validCount += 1
                    }
                }
                if validCount > 0 {
                    var concat = Data(capacity: totalBytes)
                    var lens = Data(capacity: validCount * 2)
                    for (idx, pkt) in packets.enumerated() {
                        if idx < protocols.count && (protocols[idx].int32Value == AF_INET || protocols[idx].int32Value == AF_INET6) && pkt.count > 0 && pkt.count <= 0xFFFF {
                            let n = pkt.count
                            lens.append(UInt8((n >> 8) & 0xFF))
                            lens.append(UInt8(n & 0xFF))
                            concat.append(pkt)
                        }
                    }
                    GhostMobileBridge.pushTunPacketBatch(concat, lens: lens, count: validCount)
                }
            }
            self.readPacketsLoop()
        }
    }

    private func notifyControlCenterReload() {
        if #available(iOS 18.0, *) {
            ControlCenter.shared.reloadControls(ofKind: "KestrelDuoControlToggle")
            ControlCenter.shared.reloadAllControls()
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func wake() {
        GhostMobileBridge.onNetworkChanged(ifaceName: lastPhysicalIface)
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let req = try? JSONDecoder().decode(TunnelIPCRequest.self, from: messageData) else {
            replyIPC(TunnelIPCResponse(ok: false, payload: nil, error: "Invalid IPC request JSON"), completionHandler: completionHandler)
            return
        }

        if req.action == "ping" {
            replyIPC(TunnelIPCResponse(ok: true, payload: "pong", error: nil), completionHandler: completionHandler)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else {
                completionHandler?(nil)
                return
            }

            switch req.action {
            case "status":
                self.replyIPC(TunnelIPCResponse(ok: true, payload: GhostMobileBridge.getStatusJSON(), error: nil), completionHandler: completionHandler)

            case "diag":
                self.replyIPC(TunnelIPCResponse(ok: true, payload: GhostMobileBridge.getDiagnosticSnapshot(), error: nil), completionHandler: completionHandler)

            case "clearLogs":
                GhostMobileBridge.clearLogs()
                self.replyIPC(TunnelIPCResponse(ok: true, payload: nil, error: nil), completionHandler: completionHandler)

            case "updateRules":
                let raw = GhostMobileBridge.updateRuleBundleRaw(url: req.configJSON ?? "")
                switch GhostMobileBridge.decodeRuleStats(fromJSON: raw) {
                case .success:
                    self.replyIPC(TunnelIPCResponse(ok: true, payload: raw, error: nil), completionHandler: completionHandler)
                case .failure(let err):
                    self.replyIPC(TunnelIPCResponse(ok: false, payload: raw, error: err.localizedDescription), completionHandler: completionHandler)
                }

            case "networkWake":
                GhostMobileBridge.onNetworkChanged(ifaceName: req.iface ?? self.lastPhysicalIface)
                self.replyIPC(TunnelIPCResponse(ok: true, payload: nil, error: nil), completionHandler: completionHandler)

            case "reload":
                guard let cfgJSON = req.configJSON, !cfgJSON.isEmpty else {
                    self.replyIPC(TunnelIPCResponse(ok: false, payload: nil, error: "Missing configJSON for reload"), completionHandler: completionHandler)
                    return
                }
                self.reloadQueue.async { [weak self] in
                    guard let self = self else {
                        completionHandler?(nil)
                        return
                    }
                    let decodedCfg = GhostEngineConfig.decode(from: cfgJSON)
                    var serverHost = ""
                    if let linkURI = decodedCfg?.linkURI, case .success(let node) = GhostMobileBridge.parseLink(uri: linkURI) {
                        serverHost = node.host
                    }
                    let newHTTPPort = decodedCfg?.httpPort ?? self.currentHTTPPort
                    let newRouteMode = (decodedCfg?.routeMode ?? self.currentRouteMode).lowercased()
                    let newEnableIPv6 = decodedCfg?.enableIPv6 ?? self.currentEnableIPv6
                    let startConfigJSON: String
                    if var cfg = decodedCfg {
                        cfg.asyncConnect = true
                        startConfigJSON = cfg.toJSONString()
                    } else {
                        startConfigJSON = cfgJSON
                    }

                    self.stopTUNForwarding()
                    _ = GhostMobileBridge.stopEngine()
                    switch GhostMobileBridge.startEngine(configJSON: startConfigJSON) {
                    case .failure(let err):
                        self.replyIPC(TunnelIPCResponse(ok: false, payload: nil, error: err.localizedDescription), completionHandler: completionHandler)
                    case .success:
                        if newHTTPPort != self.currentHTTPPort || serverHost != self.currentServerHost || newRouteMode != self.currentRouteMode || newEnableIPv6 != self.currentEnableIPv6 {
                            self.currentHTTPPort = newHTTPPort
                            self.currentServerHost = serverHost
                            self.currentRouteMode = newRouteMode
                            self.currentEnableIPv6 = newEnableIPv6
                            let settings = self.buildNetworkSettings(httpPort: newHTTPPort, serverHost: serverHost, routeMode: newRouteMode, enableIPv6: newEnableIPv6)
                            let applySem = DispatchSemaphore(value: 0)
                            self.setTunnelNetworkSettings(settings) { [weak self] err in
                                if let err = err {
                                    self?.replyIPC(TunnelIPCResponse(ok: false, payload: nil, error: err.localizedDescription), completionHandler: completionHandler)
                                } else {
                                    if newRouteMode != "core" {
                                        _ = self?.startTUNForwarding(mtu: 1400)
                                    }
                                    self?.replyIPC(TunnelIPCResponse(ok: true, payload: GhostMobileBridge.getStatusJSON(), error: nil), completionHandler: completionHandler)
                                }
                                applySem.signal()
                            }
                            _ = applySem.wait(timeout: .now() + 6)
                            return
                        }
                        if newRouteMode != "core" {
                            _ = self.startTUNForwarding(mtu: 1400)
                        }
                        self.replyIPC(TunnelIPCResponse(ok: true, payload: GhostMobileBridge.getStatusJSON(), error: nil), completionHandler: completionHandler)
                    }
                }

            default:
                self.replyIPC(TunnelIPCResponse(ok: false, payload: nil, error: "Unknown IPC action: \(req.action)"), completionHandler: completionHandler)
            }
        }
    }

    private func replyIPC(_ resp: TunnelIPCResponse, completionHandler: ((Data?) -> Void)?) {
        let data = try? JSONEncoder().encode(resp)
        completionHandler?(data)
    }

    private func buildNetworkSettings(httpPort: Int, serverHost: String, routeMode: String, enableIPv6: Bool) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.18.0.1")
        settings.mtu = 1400

        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.2"], subnetMasks: ["255.255.255.0"])
        if routeMode == "core" {
            // Port-only mode: keep local SOCKS5/HTTP listeners without system-wide TUN/proxy interception.
            ipv4.includedRoutes = []
            ipv4.excludedRoutes = [NEIPv4Route.default()]
            settings.ipv4Settings = ipv4
            return settings
        }

        // True TUN L3/L4 intercept (0.0.0.0/0) so Telegram MTProto, raw TCP/UDP apps & games
        // are captured automatically alongside the hybrid HTTP proxy fast-path.
        ipv4.includedRoutes = [NEIPv4Route.default()]

        var excluded: [NEIPv4Route] = [
            NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"),
            NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "169.254.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "224.0.0.0", subnetMask: "240.0.0.0"),
            NEIPv4Route(destinationAddress: "255.255.255.255", subnetMask: "255.255.255.255")
        ]
        var resolvedRemoteIPs: (v4: [String], v6: [String])? = nil
        if !serverHost.isEmpty {
            let cleanServerHost = serverHost.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            if isValidIPv4(cleanServerHost) {
                excluded.append(NEIPv4Route(destinationAddress: cleanServerHost, subnetMask: "255.255.255.255"))
            } else if !isValidIPv6(cleanServerHost) {
                let res = GhostMobileBridge.resolveHostIPs(host: cleanServerHost)
                resolvedRemoteIPs = res
                for resolvedIP in res.v4 {
                    excluded.append(NEIPv4Route(destinationAddress: resolvedIP, subnetMask: "255.255.255.255"))
                }
            }
        }
        ipv4.excludedRoutes = excluded
        settings.ipv4Settings = ipv4

        // Capture IPv6 default route into TUN in both modes:
        // - enableIPv6 == true : dual-stack Fake-IP (fd18:c612::/64) + AAAA proxy/direct routing
        // - enableIPv6 == false: AAAA NODATA + gVisor 0ms RST / Port Unreachable (anti-IPv6 leak without stalls)
        let ipv6 = NEIPv6Settings(addresses: ["fd18:c612::2"], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        var excluded6: [NEIPv6Route] = [
            NEIPv6Route(destinationAddress: "::1", networkPrefixLength: 128),
            NEIPv6Route(destinationAddress: "fe80::", networkPrefixLength: 10),
            NEIPv6Route(destinationAddress: "fc00::", networkPrefixLength: 7),
            NEIPv6Route(destinationAddress: "ff00::", networkPrefixLength: 8),
            NEIPv6Route(destinationAddress: "64:ff9b::", networkPrefixLength: 96)
        ]
        if !serverHost.isEmpty {
            let cleanServerHost = serverHost.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            if isValidIPv6(cleanServerHost) {
                excluded6.append(NEIPv6Route(destinationAddress: cleanServerHost, networkPrefixLength: 128))
            } else if !isValidIPv4(cleanServerHost) {
                let res = resolvedRemoteIPs ?? GhostMobileBridge.resolveHostIPs(host: cleanServerHost)
                for resolvedIP6 in res.v6 {
                    excluded6.append(NEIPv6Route(destinationAddress: resolvedIP6, networkPrefixLength: 128))
                }
            }
        }
        ipv6.excludedRoutes = excluded6
        settings.ipv6Settings = ipv6

        // Route all TUN DNS queries into the virtual Fake-IP DNS gateway (198.18.0.1 / optional fd18:c612::1).
        let dnsServers = enableIPv6 ? ["198.18.0.1", "fd18:c612::1"] : ["198.18.0.1"]
        let dns = NEDNSSettings(servers: dnsServers)
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        // Hybrid HTTP proxy fast-path keeps heavy Safari/YouTube streams on native kernel TCP
        // to stay comfortably below iOS's 50MB PacketTunnel memory ceiling.
        let proxy = NEProxySettings()
        proxy.httpEnabled = true
        proxy.httpServer = NEProxyServer(address: "127.0.0.1", port: httpPort)
        proxy.httpsEnabled = true
        proxy.httpsServer = NEProxyServer(address: "127.0.0.1", port: httpPort)
        proxy.matchDomains = [""]
        proxy.excludeSimpleHostnames = true

        var exceptions = [
            "localhost",
            "127.0.0.1",
            "::1",
            "*.local",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "fc00::/7",
            "fe80::/10"
        ]
        if !serverHost.isEmpty {
            exceptions.append(serverHost)
        }
        proxy.exceptionList = exceptions
        settings.proxySettings = proxy

        return settings
    }

    private func isValidIPv4(_ host: String) -> Bool {
        var addr = in_addr()
        return host.withCString { inet_pton(AF_INET, $0, &addr) == 1 }
    }

    private func isValidIPv6(_ host: String) -> Bool {
        var addr = in6_addr()
        return host.withCString { inet_pton(AF_INET6, $0, &addr) == 1 }
    }

    private func startNetworkMonitorAndDetectInitialInterface(timeout: TimeInterval) -> String {
        stopNetworkMonitor()
        let monitor = NWPathMonitor()
        let sem = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var initialIface = ""
        var initialSig = ""
        var signaled = false
        var timedOut = false

        monitor.pathUpdateHandler = { [weak self] path in
            let iface = GhostNetworkHelper.preferredPhysicalInterface(from: path)
            let sig = Self.buildPathSignature(path: path, iface: iface)

            lock.lock()
            if !signaled {
                initialIface = iface
                initialSig = sig
                signaled = true
                let wasTimedOut = timedOut
                lock.unlock()
                sem.signal()
                if !wasTimedOut {
                    return
                }
                guard let self = self else { return }
                if !sig.isEmpty {
                    self.lastPathSignature = sig
                }
                if !iface.isEmpty {
                    self.lastPhysicalIface = iface
                    GhostMobileBridge.onNetworkChanged(ifaceName: iface)
                }
                return
            }
            lock.unlock()

            guard let self = self else { return }
            guard !sig.isEmpty, sig != self.lastPathSignature else { return }
            self.lastPathSignature = sig
            if !iface.isEmpty {
                self.lastPhysicalIface = iface
            }

            // Debounce rapid iOS NWPath churn (300ms) during Wi-Fi <-> 4G/5G handoffs or IP refresh.
            self.pathDebounceWorkItem?.cancel()
            let targetIface = iface.isEmpty ? self.lastPhysicalIface : iface
            let work = DispatchWorkItem { [weak self] in
                guard self != nil else { return }
                GhostMobileBridge.onNetworkChanged(ifaceName: targetIface)
            }
            self.pathDebounceWorkItem = work
            self.monitorQueue.asyncAfter(deadline: .now() + 0.30, execute: work)
        }
        monitor.start(queue: monitorQueue)
        pathMonitor = monitor
        _ = sem.wait(timeout: .now() + timeout)
        lock.lock()
        if !signaled {
            timedOut = true
        }
        let resolved = initialIface
        let resolvedSig = initialSig
        lock.unlock()
        if !resolved.isEmpty {
            lastPhysicalIface = resolved
        }
        if !resolvedSig.isEmpty {
            lastPathSignature = resolvedSig
        }
        return resolved
    }

    private func stopNetworkMonitor() {
        pathDebounceWorkItem?.cancel()
        pathDebounceWorkItem = nil
        pathMonitor?.cancel()
        pathMonitor = nil
    }

    private static func buildPathSignature(path: Network.NWPath, iface: String) -> String {
        let statusStr: String
        switch path.status {
        case .satisfied: statusStr = "satisfied"
        case .unsatisfied: statusStr = "unsatisfied"
        case .requiresConnection: statusStr = "requiresConnection"
        @unknown default: statusStr = "unknown"
        }
        let ips = iface.isEmpty ? "" : interfaceAddressList(ifaceName: iface)
        return "\(statusStr)|\(iface)|\(ips)|v4=\(path.supportsIPv4)|v6=\(path.supportsIPv6)"
    }

    private static func interfaceAddressList(ifaceName: String) -> String {
        var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrPtr) == 0, let first = ifaddrPtr else { return "" }
        defer { freeifaddrs(ifaddrPtr) }

        var addrs: [String] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            defer { cursor = current.pointee.ifa_next }
            guard let addr = current.pointee.ifa_addr else { continue }
            let name = String(cString: current.pointee.ifa_name)
            guard name == ifaceName else { continue }
            let family = Int32(addr.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }

            var hostBuf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let len = socklen_t(addr.pointee.sa_len)
            if getnameinfo(addr, len, &hostBuf, socklen_t(hostBuf.count), nil, 0, NI_NUMERICHOST) == 0 {
                addrs.append(String(cString: hostBuf))
            }
        }
        return addrs.sorted().joined(separator: ",")
    }
}
