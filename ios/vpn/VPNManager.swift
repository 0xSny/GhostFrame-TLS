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
                        self.sendIPC(action: "reload", configJSON: config.toJSONString()) { resp in
                            Task { @MainActor in
                                if let resp = resp, !resp.ok, let msg = resp.error {
                                    self.onLogMessage?("Live reload error: \(msg)")
                                } else {
                                    self.pollStatusOnce()
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
                } else {
                    Task { @MainActor in
                        completion(self?.localFallbackDiagnostic() ?? "Extension IPC unavailable")
                    }
                }
            }
            return
        }
        completion(localFallbackDiagnostic())
    }

    func clearLogs() {
        sendIPC(action: "clearLogs", configJSON: nil) { _ in }
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
        LastDisconnectError: \(lastErr)
        ConfigDelivery: NETunnelProviderProtocol.providerConfiguration (Zero App Group)
        IPCChannel: NETunnelProviderSession.sendProviderMessage
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
        sendIPC(action: "status", configJSON: nil) { [weak self] resp in
            guard let resp = resp, resp.ok, let json = resp.payload else { return }
            let snapshot = GhostMobileBridge.decodeStatus(from: json)
            Task { @MainActor in
                self?.onStatusUpdate?(snapshot)
            }
        }
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
                guard let responseData = responseData,
                      let resp = try? JSONDecoder().decode(TunnelIPCResponse.self, from: responseData) else {
                    Task { @MainActor in
                        self?.logIPCWarningThrottled("VPN IPC: empty/unreadable response for \(action)")
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
