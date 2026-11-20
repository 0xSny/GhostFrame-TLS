import Foundation
import Network
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var pathMonitor: NWPathMonitor?
    private let monitorQueue = DispatchQueue(label: "com.ghostframe.tunnel.pathmonitor")
    private var lastPhysicalIface: String = ""
    private var currentHTTPPort: Int = 10809
    private var currentServerHost: String = ""

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

        let supportDir = GhostNetworkHelper.appSupportDirectory(subdir: "GhostFrameTunnel")
        GhostMobileBridge.initCore(dataDir: supportDir, isTunnelExt: true)
        startNetworkMonitor()

        switch GhostMobileBridge.startEngine(configJSON: configJSON) {
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
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        stopNetworkMonitor()
        _ = GhostMobileBridge.stopEngine()
        completionHandler()
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

        switch req.action {
        case "status":
            replyIPC(TunnelIPCResponse(ok: true, payload: GhostMobileBridge.getStatusJSON(), error: nil), completionHandler: completionHandler)

        case "diag":
            replyIPC(TunnelIPCResponse(ok: true, payload: GhostMobileBridge.getDiagnosticSnapshot(), error: nil), completionHandler: completionHandler)

        case "clearLogs":
            GhostMobileBridge.clearLogs()
            replyIPC(TunnelIPCResponse(ok: true, payload: nil, error: nil), completionHandler: completionHandler)

        case "networkWake":
            GhostMobileBridge.onNetworkChanged(ifaceName: req.iface ?? lastPhysicalIface)
            replyIPC(TunnelIPCResponse(ok: true, payload: nil, error: nil), completionHandler: completionHandler)

        case "reload":
            guard let cfgJSON = req.configJSON, !cfgJSON.isEmpty else {
                replyIPC(TunnelIPCResponse(ok: false, payload: nil, error: "Missing configJSON for reload"), completionHandler: completionHandler)
                return
            }
            let decodedCfg = GhostEngineConfig.decode(from: cfgJSON)
            var serverHost = ""
            if let linkURI = decodedCfg?.linkURI, case .success(let node) = GhostMobileBridge.parseLink(uri: linkURI) {
                serverHost = node.host
            }
            let newHTTPPort = decodedCfg?.httpPort ?? currentHTTPPort

            _ = GhostMobileBridge.stopEngine()
            switch GhostMobileBridge.startEngine(configJSON: cfgJSON) {
            case .failure(let err):
                replyIPC(TunnelIPCResponse(ok: false, payload: nil, error: err.localizedDescription), completionHandler: completionHandler)
            case .success:
                if newHTTPPort != currentHTTPPort || serverHost != currentServerHost {
                    currentHTTPPort = newHTTPPort
                    currentServerHost = serverHost
                    let settings = buildNetworkSettings(httpPort: newHTTPPort, serverHost: serverHost)
                    setTunnelNetworkSettings(settings) { [weak self] err in
                        if let err = err {
                            self?.replyIPC(TunnelIPCResponse(ok: false, payload: nil, error: err.localizedDescription), completionHandler: completionHandler)
                        } else {
                            self?.replyIPC(TunnelIPCResponse(ok: true, payload: GhostMobileBridge.getStatusJSON(), error: nil), completionHandler: completionHandler)
                        }
                    }
                    return
                }
                replyIPC(TunnelIPCResponse(ok: true, payload: GhostMobileBridge.getStatusJSON(), error: nil), completionHandler: completionHandler)
            }

        default:
            replyIPC(TunnelIPCResponse(ok: false, payload: nil, error: "Unknown IPC action: \(req.action)"), completionHandler: completionHandler)
        }
    }

    private func replyIPC(_ resp: TunnelIPCResponse, completionHandler: ((Data?) -> Void)?) {
        let data = try? JSONEncoder().encode(resp)
        completionHandler?(data)
    }

    private func buildNetworkSettings(httpPort: Int, serverHost: String) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.18.0.1")
        settings.mtu = 1400

        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: "198.18.0.0", subnetMask: "255.255.0.0")]
        if !serverHost.isEmpty && isValidIPv4(serverHost) {
            ipv4.excludedRoutes = [NEIPv4Route(destinationAddress: serverHost, subnetMask: "255.255.255.255")]
        }
        settings.ipv4Settings = ipv4

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

    private func startNetworkMonitor() {
        stopNetworkMonitor()
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }
            let iface = GhostNetworkHelper.preferredPhysicalInterface(from: path)
            if !iface.isEmpty && iface != self.lastPhysicalIface {
                self.lastPhysicalIface = iface
                GhostMobileBridge.onNetworkChanged(ifaceName: iface)
            }
        }
        monitor.start(queue: monitorQueue)
        pathMonitor = monitor
    }

    private func stopNetworkMonitor() {
        pathMonitor?.cancel()
        pathMonitor = nil
    }
}
