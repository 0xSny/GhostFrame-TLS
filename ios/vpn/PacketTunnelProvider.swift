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
        guard let data = pkt, !data.isEmpty, let flow = self.flow else { return }
        flow.writePackets([data], withProtocols: [NSNumber(value: family)])
    }
}

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var pathMonitor: NWPathMonitor?
    private let monitorQueue = DispatchQueue(label: "com.ghostframe.tunnel.pathmonitor")
    private var lastPhysicalIface: String = ""
    private var currentHTTPPort: Int = 10809
    private var currentServerHost: String = ""
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
                domain: "com.ghostframe.tunnel",
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

        let startConfigJSON: String
        if var cfg = decodedCfg {
            cfg.asyncConnect = true
            startConfigJSON = cfg.toJSONString()
        } else {
            startConfigJSON = configJSON
        }

        let supportDir = GhostNetworkHelper.appSupportDirectory(subdir: "GhostFrameTunnel")
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

        let settings = buildNetworkSettings(httpPort: httpPort, serverHost: serverHost)
        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                _ = GhostMobileBridge.stopEngine()
                self?.stopNetworkMonitor()
                completionHandler(error)
                return
            }
            if let self = self {
                if case .failure(let tunErr) = self.startTUNForwarding(mtu: 1400) {
                    _ = GhostMobileBridge.stopEngine()
                    self.stopNetworkMonitor()
                    completionHandler(tunErr)
                    return
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

            for (idx, pkt) in packets.enumerated() {
                if idx < protocols.count && protocols[idx].int32Value == AF_INET {
                    GhostMobileBridge.pushTunPacket(pkt)
                }
            }
            self.readPacketsLoop()
        }
    }

    private func notifyControlCenterReload() {
        if #available(iOS 18.0, *) {
            ControlCenter.shared.reloadControls(ofKind: "GhostFrameVPNControlToggle")
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

            case "networkWake":
                GhostMobileBridge.onNetworkChanged(ifaceName: req.iface ?? self.lastPhysicalIface)
                self.replyIPC(TunnelIPCResponse(ok: true, payload: nil, error: nil), completionHandler: completionHandler)

            case "reload":
                guard let cfgJSON = req.configJSON, !cfgJSON.isEmpty else {
                    self.replyIPC(TunnelIPCResponse(ok: false, payload: nil, error: "Missing configJSON for reload"), completionHandler: completionHandler)
                    return
                }
                let decodedCfg = GhostEngineConfig.decode(from: cfgJSON)
                var serverHost = ""
                if let linkURI = decodedCfg?.linkURI, case .success(let node) = GhostMobileBridge.parseLink(uri: linkURI) {
                    serverHost = node.host
                }
                let newHTTPPort = decodedCfg?.httpPort ?? self.currentHTTPPort
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
                    if newHTTPPort != self.currentHTTPPort || serverHost != self.currentServerHost {
                        self.currentHTTPPort = newHTTPPort
                        self.currentServerHost = serverHost
                        let settings = self.buildNetworkSettings(httpPort: newHTTPPort, serverHost: serverHost)
                        self.setTunnelNetworkSettings(settings) { [weak self] err in
                            if let err = err {
                                self?.replyIPC(TunnelIPCResponse(ok: false, payload: nil, error: err.localizedDescription), completionHandler: completionHandler)
                            } else {
                                _ = self?.startTUNForwarding(mtu: 1400)
                                self?.replyIPC(TunnelIPCResponse(ok: true, payload: GhostMobileBridge.getStatusJSON(), error: nil), completionHandler: completionHandler)
                            }
                        }
                        return
                    }
                    _ = self.startTUNForwarding(mtu: 1400)
                    self.replyIPC(TunnelIPCResponse(ok: true, payload: GhostMobileBridge.getStatusJSON(), error: nil), completionHandler: completionHandler)
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

    private func buildNetworkSettings(httpPort: Int, serverHost: String) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.18.0.1")
        settings.mtu = 1400

        // True TUN L3/L4 intercept (0.0.0.0/0) so Telegram MTProto, raw TCP/UDP apps & games
        // are captured automatically alongside the hybrid HTTP proxy fast-path.
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.2"], subnetMasks: ["255.255.255.0"])
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
        if !serverHost.isEmpty && isValidIPv4(serverHost) {
            excluded.append(NEIPv4Route(destinationAddress: serverHost, subnetMask: "255.255.255.255"))
        }
        ipv4.excludedRoutes = excluded
        settings.ipv4Settings = ipv4

        // Route all TUN DNS queries into the virtual Fake-IP DNS gateway (198.18.0.1:53).
        let dns = NEDNSSettings(servers: ["198.18.0.1"])
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
            "*.local",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16"
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

    private func startNetworkMonitorAndDetectInitialInterface(timeout: TimeInterval) -> String {
        stopNetworkMonitor()
        let monitor = NWPathMonitor()
        let sem = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var initialIface = ""
        var signaled = false

        monitor.pathUpdateHandler = { [weak self] path in
            let iface = GhostNetworkHelper.preferredPhysicalInterface(from: path)
            lock.lock()
            if !signaled {
                initialIface = iface
                signaled = true
                lock.unlock()
                sem.signal()
            } else {
                lock.unlock()
            }

            guard let self = self else { return }
            if !iface.isEmpty && iface != self.lastPhysicalIface {
                self.lastPhysicalIface = iface
                GhostMobileBridge.onNetworkChanged(ifaceName: iface)
            }
        }
        monitor.start(queue: monitorQueue)
        pathMonitor = monitor
        _ = sem.wait(timeout: .now() + timeout)
        lock.lock()
        let resolved = initialIface
        if !resolved.isEmpty {
            lastPhysicalIface = resolved
        }
        lock.unlock()
        return resolved
    }

    private func stopNetworkMonitor() {
        pathMonitor?.cancel()
        pathMonitor = nil
    }
}
