import Foundation
import NetworkExtension

@MainActor
final class VPNManager: GhostBackend {
    var onStateChange: (() -> Void)?
    var onStatusUpdate: ((GhostStatusSnapshot) -> Void)?
    var onErrorReport: ((GhostTunnelErrorReport) -> Void)?
    var onLogMessage: ((String) -> Void)?

    private(set) var detectedExtensionBundleID: String = ""
    let keepAliveActive: Bool = false

    private(set) var isConnected: Bool = false
    private(set) var isTransitioning: Bool = false
    private(set) var backendStateLabel: String = "VPN 待机"

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var pollTimer: Timer?
    private var hasAttemptedConnect: Bool = false
    private var userInitiatedDisconnect: Bool = false
    private var connectAttemptToken: UInt64 = 0
    private var lastObservedStatus: NEVPNStatus?
    private var lastDisconnectErrorText: String = ""
    private var lastIPCLogAt: Date = .distantPast
    private var currentHTTPPort: Int = 10809
    private var telemetryChannel: String = "pending"
    private var loggedHTTPTelemetry: Bool = false
    private let directSession: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.connectionProxyDictionary = [:]
        cfg.timeoutIntervalForRequest = 2.0
        cfg.timeoutIntervalForResource = 3.0
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: cfg)
    }()

    init() {
        detectedExtensionBundleID = Self.resolveTunnelProviderBundleIdentifier()
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let self = self,
                  let conn = notification.object as? NEVPNConnection else { return }
            Task { @MainActor in
                if let current = self.manager, current.connection !== conn {
                    return
                }
                self.updateVPNStatus(conn.status, connection: conn)
            }
        }
        loadExistingManager(completion: nil)
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        pollTimer?.invalidate()
    }

    static func resolveTunnelProviderBundleIdentifier() -> String {
        if let plugInsURL = Bundle.main.builtInPlugInsURL,
           let items = try? FileManager.default.contentsOfDirectory(at: plugInsURL, includingPropertiesForKeys: nil) {
            let appexBundles = items
                .filter { $0.pathExtension.lowercased() == "appex" }
                .compactMap { Bundle(url: $0) }

            for bundle in appexBundles {
                if let extDict = bundle.infoDictionary?["NSExtension"] as? [String: Any],
                   let pointID = extDict["NSExtensionPointIdentifier"] as? String,
                   pointID == "com.apple.networkextension.packet-tunnel",
                   let bid = bundle.bundleIdentifier,
                   !bid.isEmpty {
                    return bid
                }
            }
            if let firstID = appexBundles.first?.bundleIdentifier, !firstID.isEmpty {
                return firstID
            }
        }
        let mainID = Bundle.main.bundleIdentifier ?? "com.ghostframe.vpn"
        return mainID + ".tunnel"
    }

    func connect(config: GhostEngineConfig, node: GhostNode) {
        hasAttemptedConnect = false
        userInitiatedDisconnect = false
        lastDisconnectErrorText = ""
        currentHTTPPort = config.httpPort
        telemetryChannel = "pending"
        loggedHTTPTelemetry = false
        connectAttemptToken &+= 1
        let attemptToken = connectAttemptToken

        isTransitioning = true
        backendStateLabel = "准备配置..."
        onStateChange?()
        onLogMessage?("VPN: loading preferences (ext=\(resolveAndCacheExtensionID()))")

        loadOrCreateManager { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .failure(let err):
                self.handleError(err, stage: "加载 VPN 配置失败")
            case .success(let mgr):
                self.saveAndStart(manager: mgr, config: config, node: node, attemptToken: attemptToken)
            }
        }
    }

    func disconnect() {
        userInitiatedDisconnect = true
        hasAttemptedConnect = false
        connectAttemptToken &+= 1
        stopPolling()
        onLogMessage?("VPN: stopVPNTunnel requested")
        manager?.connection.stopVPNTunnel()
        isConnected = false
        isTransitioning = false
        backendStateLabel = "VPN 已断开"
        onStateChange?()
    }

    func applyLiveConfig(config: GhostEngineConfig, node: GhostNode) {
        currentHTTPPort = config.httpPort
        loadOrCreateManager { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .failure(let err):
                self.handleError(err, stage: "更新 VPN 配置失败")
            case .success(let mgr):
                self.writeProviderConfiguration(on: mgr, config: config, node: node)
                mgr.saveToPreferences { [weak self] saveErr in
                    Task { @MainActor in
                        guard let self = self else { return }
                        if let saveErr = saveErr {
                            self.handleError(saveErr, stage: "保存 providerConfiguration 失败")
                            return
                        }
                        let cfgJSON = config.toJSONString()
                        self.sendIPC(action: "reload", configJSON: cfgJSON) { [weak self] resp in
                            Task { @MainActor in
                                guard let self = self else { return }
                                if let resp = resp {
                                    if !resp.ok, let msg = resp.error {
                                        self.onLogMessage?("Live reload error: \(msg)")
                                    } else {
                                        self.pollStatusOnce()
                                    }
                                } else if let body = cfgJSON.data(using: .utf8) {
                                    self.fetchLoopbackHTTP(method: "POST", path: "/_gft/reload", body: body) { [weak self] data, _ in
                                        Task { @MainActor in
                                            if data != nil {
                                                self?.pollStatusOnce()
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    func fetchDiagnostic(completion: @escaping (String) -> Void) {
        if isConnected || isTransitioning {
            sendIPC(action: "diag", configJSON: nil) { [weak self] resp in
                if let resp = resp, resp.ok, let payload = resp.payload, !payload.isEmpty {
                    completion(payload)
                    return
                }
                Task { @MainActor in
                    guard let self = self else {
                        completion("VPN manager unavailable")
                        return
                    }
                    self.fetchLoopbackHTTP(method: "GET", path: "/_gft/diag", body: nil) { data, _ in
                        Task { @MainActor in
                            if let data = data, let text = String(data: data, encoding: .utf8), !text.isEmpty {
                                completion(text)
                            } else {
                                completion(self.localFallbackDiagnostic())
                            }
                        }
                    }
                }
            }
            return
        }
        completion(localFallbackDiagnostic())
    }

    func clearLogs() {
        sendIPC(action: "clearLogs", configJSON: nil) { _ in }
        fetchLoopbackHTTP(method: "POST", path: "/_gft/clear-logs", body: nil) { _, _ in }
    }

    private func localFallbackDiagnostic() -> String {
        let mainID = Bundle.main.bundleIdentifier ?? "unknown"
        let neStatus = Self.statusName(manager?.connection.status ?? .invalid)
        let lastErr = lastDisconnectErrorText.isEmpty ? "none" : lastDisconnectErrorText
        return """
        GhostFrame VPN App Diagnostic (v4.0.0-LTS)
        MainBundleID: \(mainID)
        ResolvedExtensionBundleID: \(detectedExtensionBundleID)
        VPNState: \(backendStateLabel) (NEVPNStatus=\(neStatus))
        TelemetryChannel: \(telemetryChannel) (HTTP=127.0.0.1:\(currentHTTPPort))
        LastDisconnectError: \(lastErr)
        ConfigDelivery: NETunnelProviderProtocol.providerConfiguration (Zero App Group)
        IPCChannel: NETunnelProviderSession.sendProviderMessage + Loopback /_gft/*
        """
    }

    private func loadExistingManager(completion: ((NETunnelProviderManager?) -> Void)?) {
        let extBundleID = resolveAndCacheExtensionID()
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, _ in
            Task { @MainActor in
                guard let self = self else { return }
                let matched = managers?.first(where: {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == extBundleID
                }) ?? managers?.first
                if let mgr = matched {
                    self.manager = mgr
                    if let hp = (mgr.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["httpPort"] as? Int, hp > 0 {
                        self.currentHTTPPort = hp
                    }
                    self.updateVPNStatus(mgr.connection.status, connection: mgr.connection)
                }
                completion?(matched)
            }
        }
    }

    private func loadOrCreateManager(completion: @escaping (Result<NETunnelProviderManager, Error>) -> Void) {
        let extBundleID = resolveAndCacheExtensionID()
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            Task { @MainActor in
                if let error = error {
                    completion(.failure(error))
                    return
                }
                let mgr = managers?.first(where: {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == extBundleID
                }) ?? managers?.first ?? NETunnelProviderManager()
                self?.manager = mgr
                completion(.success(mgr))
            }
        }
    }

    private func writeProviderConfiguration(on mgr: NETunnelProviderManager, config: GhostEngineConfig, node: GhostNode) {
        let extBundleID = resolveAndCacheExtensionID()
        let proto = (mgr.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = extBundleID
        proto.serverAddress = "\(node.host):\(node.port)"
        proto.providerConfiguration = [
            "configJSON": config.toJSONString(),
            "serverHost": node.host,
            "socksPort": config.socksPort,
            "httpPort": config.httpPort,
            "routeMode": config.routeMode,
            "transport": config.transport
        ]
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = "GhostFrame VPN (\(node.remark))"
        mgr.isEnabled = true
    }

    private func saveAndStart(manager mgr: NETunnelProviderManager, config: GhostEngineConfig, node: GhostNode, attemptToken: UInt64) {
        writeProviderConfiguration(on: mgr, config: config, node: node)
        onLogMessage?("VPN: saving profile (server=\(node.host):\(node.port), http=\(config.httpPort))")

        mgr.saveToPreferences { [weak self] saveError in
            Task { @MainActor in
                guard let self = self else { return }
                if let saveError = saveError {
                    self.handleError(saveError, stage: "写入系统 VPN Profile 失败")
                    return
                }
                self.onLogMessage?("VPN: saveToPreferences ok, reloading...")
                mgr.loadFromPreferences { [weak self] loadError in
                    Task { @MainActor in
                        guard let self = self else { return }
                        if let loadError = loadError {
                            self.handleError(loadError, stage: "重载系统 VPN Profile 失败")
                            return
                        }
                        self.manager = mgr
                        self.hasAttemptedConnect = true
                        self.onLogMessage?("VPN: calling startVPNTunnel...")
                        do {
                            if let session = mgr.connection as? NETunnelProviderSession {
                                try session.startVPNTunnel(options: [
                                    "configJSON": config.toJSONString() as NSObject
                                ])
                            } else {
                                try mgr.connection.startVPNTunnel()
                            }
                            let cur = mgr.connection.status
                            self.onLogMessage?("VPN: startVPNTunnel returned (status=\(Self.statusName(cur)))")
                            if cur == .connected || cur == .connecting || cur == .reasserting {
                                self.updateVPNStatus(cur, connection: mgr.connection)
                            } else {
                                // iOS updates NEVPNStatus asynchronously after startVPNTunnel returns;
                                // do not prematurely clear isTransitioning while nesessionmanager launches .appex.
                                self.isTransitioning = true
                                self.backendStateLabel = "正在拉起扩展..."
                                self.onStateChange?()
                            }
                            self.startPolling()

                            DispatchQueue.main.asyncAfter(deadline: .now() + 3.5) { [weak self] in
                                guard let self = self else { return }
                                guard self.connectAttemptToken == attemptToken,
                                      self.hasAttemptedConnect,
                                      !self.userInitiatedDisconnect else { return }
                                let st = self.manager?.connection.status ?? .disconnected
                                if st == .disconnected || st == .invalid {
                                    self.onLogMessage?("VPN: session stayed \(Self.statusName(st)) after 3.5s; fetching system error...")
                                    self.inspectDisconnectError(connection: self.manager?.connection, triggerReport: true)
                                }
                            }
                        } catch {
                            self.handleError(error, stage: "拉起 PacketTunnel 扩展失败")
                        }
                    }
                }
            }
        }
    }

    private func resolveAndCacheExtensionID() -> String {
        let id = Self.resolveTunnelProviderBundleIdentifier()
        detectedExtensionBundleID = id
        return id
    }

    private func updateVPNStatus(_ status: NEVPNStatus, connection: NEVPNConnection?) {
        if lastObservedStatus != status {
            lastObservedStatus = status
            onLogMessage?("VPN status -> \(Self.statusName(status))")
        }

        switch status {
        case .connected:
            lastDisconnectErrorText = ""
            isConnected = true
            isTransitioning = false
            backendStateLabel = "VPN 已连接"
            startPolling()
            pollStatusOnce()
        case .connecting, .reasserting:
            isConnected = false
            isTransitioning = true
            backendStateLabel = (status == .reasserting) ? "VPN 重连中..." : "VPN 连接中..."
            startPolling()
        case .disconnecting:
            isConnected = false
            isTransitioning = true
            backendStateLabel = "正在断开..."
        case .disconnected, .invalid:
            isConnected = false
            isTransitioning = false
            backendStateLabel = (status == .invalid) ? "VPN 配置无效" : "VPN 待机"
            stopPolling()
            if hasAttemptedConnect && !userInitiatedDisconnect {
                let triggerPopup = (status == .invalid || lastObservedStatus == .disconnected)
                hasAttemptedConnect = false
                inspectDisconnectError(connection: connection, triggerReport: triggerPopup)
            }
        @unknown default:
            isConnected = false
            isTransitioning = false
            backendStateLabel = "未知状态"
        }
        onStateChange?()
    }

    private func inspectDisconnectError(connection: NEVPNConnection?, triggerReport: Bool) {
        if #available(iOS 16.0, *), let conn = connection {
            conn.fetchLastDisconnectError { [weak self] err in
                Task { @MainActor in
                    guard let self = self else { return }
                    let liveStatus = self.manager?.connection.status ?? .invalid
                    if liveStatus == .connected || liveStatus == .connecting || liveStatus == .reasserting {
                        return
                    }
                    if let nsErr = err as NSError? {
                        let summary = "[\(nsErr.domain):\(nsErr.code)] \(nsErr.localizedDescription)"
                        self.lastDisconnectErrorText = summary
                        self.onLogMessage?("VPN system error: \(summary)")
                        if triggerReport {
                            self.handleError(nsErr, stage: "系统终止 PacketTunnel 会话")
                        }
                    } else {
                        self.onLogMessage?("VPN system error: none (NEVPNConnection returned nil)")
                        if triggerReport {
                            let fallbackErr = NSError(
                                domain: "com.ghostframe.vpn",
                                code: -2,
                                userInfo: [NSLocalizedDescriptionKey: "系统未拉起或立即终止了 PacketTunnel 扩展（无附加系统错误码）。若个人证书或重签工具未真正授予扩展 Network Extensions 权限，请切换同批次产出的 GhostFrame-Companion 伴侣版。"]
                            )
                            self.handleError(fallbackErr, stage: "PacketTunnel 扩展未能保持运行")
                        }
                    }
                }
            }
            return
        }
        if triggerReport {
            let err = NSError(
                domain: "com.ghostframe.vpn",
                code: -2,
                userInfo: [NSLocalizedDescriptionKey: "PacketTunnel 状态回落至未连接，当前系统版本不支持 fetchLastDisconnectError。"]
            )
            handleError(err, stage: "PacketTunnel 启动未成功")
        }
    }

    private static func statusName(_ status: NEVPNStatus) -> String {
        switch status {
        case .invalid: return "invalid"
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .reasserting: return "reasserting"
        case .disconnecting: return "disconnecting"
        @unknown default: return "unknown(\(status.rawValue))"
        }
    }

    private func startPolling() {
        guard pollTimer == nil else { return }
        pollTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.pollStatusOnce()
            }
        }
    }

    private func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
    }

    private func pollStatusOnce() {
        if loggedHTTPTelemetry {
            fetchStatusViaHTTP()
            return
        }
        sendIPC(action: "status", configJSON: nil) { [weak self] resp in
            if let resp = resp, resp.ok, let json = resp.payload {
                let snapshot = GhostMobileBridge.decodeStatus(from: json)
                Task { @MainActor in
                    self?.telemetryChannel = "IPC"
                    self?.onStatusUpdate?(snapshot)
                }
                return
            }

            Task { @MainActor in
                self?.fetchStatusViaHTTP()
            }
        }
    }

    private func fetchStatusViaHTTP() {
        fetchLoopbackHTTP(method: "GET", path: "/_gft/status", body: nil) { [weak self] data, err in
            Task { @MainActor in
                guard let self = self else { return }
                if let data = data, let json = String(data: data, encoding: .utf8) {
                    let snapshot = GhostMobileBridge.decodeStatus(from: json)
                    self.telemetryChannel = "HTTP(127.0.0.1:\(self.currentHTTPPort))"
                    if !self.loggedHTTPTelemetry {
                        self.loggedHTTPTelemetry = true
                        self.onLogMessage?("VPN telemetry: connected via 127.0.0.1:\(self.currentHTTPPort)/_gft/status")
                    }
                    self.onStatusUpdate?(snapshot)
                } else if let err = err {
                    self.loggedHTTPTelemetry = false
                    self.logIPCWarningThrottled("VPN HTTP fallback failed (:\(self.currentHTTPPort)): \(err.localizedDescription)")
                }
            }
        }
    }

    private func fetchLoopbackHTTP(method: String, path: String, body: Data?, completion: @escaping (Data?, Error?) -> Void) {
        guard let url = URL(string: "http://127.0.0.1:\(currentHTTPPort)\(path)") else {
            completion(nil, nil)
            return
        }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.timeoutInterval = 2.0
        if let body = body {
            req.httpBody = body
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        directSession.dataTask(with: req) { data, response, error in
            if let error = error {
                completion(nil, error)
                return
            }
            if let http = response as? HTTPURLResponse, http.statusCode != 200 {
                let err = NSError(
                    domain: "com.ghostframe.http",
                    code: http.statusCode,
                    userInfo: [NSLocalizedDescriptionKey: "HTTP \(http.statusCode)"]
                )
                completion(nil, err)
                return
            }
            completion(data, nil)
        }.resume()
    }

    private func sendIPC(action: String, configJSON: String?, completion: @escaping (TunnelIPCResponse?) -> Void) {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            completion(nil)
            return
        }
        let req = TunnelIPCRequest(action: action, configJSON: configJSON, iface: nil)
        guard let reqData = try? JSONEncoder().encode(req) else {
            completion(nil)
            return
        }
        do {
            try session.sendProviderMessage(reqData) { [weak self] responseData in
                guard let responseData = responseData else {
                    Task { @MainActor in
                        self?.logIPCWarningThrottled("VPN IPC: nil response for \(action) (switching to localhost /_gft/*)")
                    }
                    completion(nil)
                    return
                }
                guard let resp = try? JSONDecoder().decode(TunnelIPCResponse.self, from: responseData) else {
                    let count = responseData.count
                    Task { @MainActor in
                        self?.logIPCWarningThrottled("VPN IPC: unreadable response for \(action) (bytes=\(count))")
                    }
                    completion(nil)
                    return
                }
                completion(resp)
            }
        } catch {
            logIPCWarningThrottled("VPN IPC send failed (\(action)): \(error.localizedDescription)")
            completion(nil)
        }
    }

    private func logIPCWarningThrottled(_ msg: String) {
        let now = Date()
        if now.timeIntervalSince(lastIPCLogAt) >= 10.0 {
            lastIPCLogAt = now
            onLogMessage?(msg)
        }
    }

    private func handleError(_ error: Error, stage: String) {
        hasAttemptedConnect = false
        connectAttemptToken &+= 1
        stopPolling()
        isConnected = false
        isTransitioning = false
        backendStateLabel = "VPN 启动失败"

        let nsErr = error as NSError
        lastDisconnectErrorText = "[\(nsErr.domain):\(nsErr.code)] \(nsErr.localizedDescription)"
        let hint: String
        if nsErr.domain == NEVPNErrorDomain && (nsErr.code == NEVPNError.configurationInvalid.rawValue || nsErr.code == NEVPNError.configurationReadWriteFailed.rawValue) {
            hint = "系统返回 NEVPNError (Code \(nsErr.code))。如果个人证书实际无 Network Extensions 高权或全能签未保留 packet-tunnel-provider 权限，请改用同包产出的 GhostFrame-Companion 伴侣版。"
        } else {
            hint = "请检查全能签重签配置是否保留了 packet-tunnel-provider 权限，或查看下方扩展 Bundle ID 是否一致。"
        }

        let report = GhostTunnelErrorReport(
            title: stage,
            domain: nsErr.domain,
            code: nsErr.code,
            message: nsErr.localizedDescription,
            mainBundleID: Bundle.main.bundleIdentifier ?? "unknown",
            extensionBundleID: detectedExtensionBundleID,
            hint: hint
        )
        onStateChange?()
        onErrorReport?(report)
    }
}
