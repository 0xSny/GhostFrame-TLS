import Foundation
import Combine

@MainActor
protocol GhostBackend: AnyObject {
    var detectedExtensionBundleID: String { get }
    var keepAliveActive: Bool { get }
    var isConnected: Bool { get }
    var isTransitioning: Bool { get }
    var backendStateLabel: String { get }

    var onStateChange: (() -> Void)? { get set }
    var onStatusUpdate: ((GhostStatusSnapshot) -> Void)? { get set }
    var onErrorReport: ((GhostTunnelErrorReport) -> Void)? { get set }
    var onLogMessage: ((String) -> Void)? { get set }

    func connect(config: GhostEngineConfig, node: GhostNode)
    func disconnect()
    func applyLiveConfig(config: GhostEngineConfig, node: GhostNode)
    func fetchDiagnostic(completion: @escaping (String) -> Void)
    func clearLogs()
}

@MainActor
final class GhostAppViewModel: ObservableObject {
    let edition: GhostEdition
    private let backend: GhostBackend

    @Published var nodes: [GhostNode] = []
    @Published var selectedNodeID: String = ""
    @Published var routeMode: GhostRouteMode = .rule
    @Published var transportMode: GhostTransportMode = .auto
    @Published var upMbpsText: String = "0"
    @Published var downMbpsText: String = "0"
    @Published var socksPortText: String = "10808"
    @Published var httpPortText: String = "10809"
    @Published var customRulesText: String = ""

    @Published var status: GhostStatusSnapshot = .empty
    @Published var isConnected: Bool = false
    @Published var isTransitioning: Bool = false
    @Published var backendStateLabel: String = "Standby"
    @Published var detectedExtensionBundleID: String = ""
    @Published var keepAliveActive: Bool = false

    @Published var localLogs: [GhostLogEntry] = []
    @Published var diagnosticText: String = ""
    @Published var errorBanner: String = ""
    @Published var tunnelErrorReport: GhostTunnelErrorReport?
    @Published var toastMessage: String = ""

    private let defaults = UserDefaults.standard
    private let storageKeyNodes: String
    private let storageKeySelectedID: String
    private let storageKeyRouteMode: String
    private let storageKeyTransport: String
    private let storageKeyUpMbps: String
    private let storageKeyDownMbps: String
    private let storageKeySocksPort: String
    private let storageKeyHttpPort: String
    private let storageKeyCustomRules: String

    private var toastClearTask: DispatchWorkItem?

    init(edition: GhostEdition, backend: GhostBackend) {
        self.edition = edition
        self.backend = backend

        let prefix = "ghostframe.\(edition.rawValue)."
        storageKeyNodes = prefix + "nodes"
        storageKeySelectedID = prefix + "selectedNodeID"
        storageKeyRouteMode = prefix + "routeMode"
        storageKeyTransport = prefix + "transportMode"
        storageKeyUpMbps = prefix + "upMbps"
        storageKeyDownMbps = prefix + "downMbps"
        storageKeySocksPort = prefix + "socksPort"
        storageKeyHttpPort = prefix + "httpPort"
        storageKeyCustomRules = prefix + "customRules"

        loadPreferences()
        bindBackend()
        syncFromBackendState()
        appendLocalLog("Kestrel \(edition.title) v4.0.26-LTS initialized")
    }

    var activeNode: GhostNode? {
        if let hit = nodes.first(where: { $0.id == selectedNodeID }) {
            return hit
        }
        return nodes.first
    }

    var effectiveSocksPort: Int {
        let parsed = Int(socksPortText.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 10808
        return (1...65535).contains(parsed) ? parsed : 10808
    }

    var effectiveHttpPort: Int {
        let parsed = Int(httpPortText.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 10809
        if (1...65535).contains(parsed) && parsed != effectiveSocksPort {
            return parsed
        }
        return effectiveSocksPort == 10809 ? 10810 : 10809
    }

    var effectiveUpMbps: Int {
        max(0, Int(upMbpsText.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0)
    }

    var effectiveDownMbps: Int {
        max(0, Int(downMbpsText.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0)
    }

    var combinedLogs: [GhostLogEntry] {
        if status.logs.isEmpty {
            return localLogs
        }
        var merged = localLogs
        var seen = Set(localLogs.map(\.id))
        for entry in status.logs where !seen.contains(entry.id) {
            seen.insert(entry.id)
            merged.append(entry)
        }
        if merged.count > 120 {
            merged.removeFirst(merged.count - 120)
        }
        return merged
    }

    func toggleConnection() {
        errorBanner = ""
        if isConnected || isTransitioning {
            appendLocalLog("Disconnecting tunnel...")
            backend.disconnect()
            return
        }
        guard let node = activeNode else {
            errorBanner = "请先点击右上角「导入」添加节点"
            showToast(errorBanner)
            return
        }
        savePreferences()
        let config = buildEngineConfig(for: node)
        appendLocalLog("Connecting to \(node.host):\(node.port) (transport=\(config.transport), route=\(config.routeMode))")
        backend.connect(config: config, node: node)
    }

    @discardableResult
    func importLink(_ rawURI: String) -> Bool {
        let trimmed = rawURI.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            errorBanner = "请输入有效的 ksl4:// 或 gft3:// 节点链接"
            return false
        }
        switch GhostMobileBridge.parseLink(uri: trimmed) {
        case .success(let parsed):
            if let existingIdx = nodes.firstIndex(where: { $0.uri == parsed.uri || ($0.host == parsed.host && $0.port == parsed.port && $0.sni == parsed.sni) }) {
                var updated = parsed
                updated.id = nodes[existingIdx].id
                nodes[existingIdx] = updated
                selectedNodeID = updated.id
            } else {
                nodes.append(parsed)
                selectedNodeID = parsed.id
            }
            if let t = GhostTransportMode(rawValue: parsed.transport) {
                transportMode = t
            }
            if parsed.upMbps > 0 || parsed.downMbps > 0 {
                upMbpsText = "\(parsed.upMbps)"
                downMbpsText = "\(parsed.downMbps)"
            }
            savePreferences()
            errorBanner = ""
            appendLocalLog("Imported node \(parsed.remark) (\(parsed.host):\(parsed.port))")
            showToast("已导入节点：\(parsed.remark)")
            if isConnected {
                applySettings()
            }
            return true
        case .failure(let err):
            errorBanner = err.localizedDescription
            showToast("解析失败：\(err.localizedDescription)")
            return false
        }
    }

    func selectNode(_ node: GhostNode) {
        selectedNodeID = node.id
        if let t = GhostTransportMode(rawValue: node.transport) {
            transportMode = t
        }
        upMbpsText = "\(node.upMbps)"
        downMbpsText = "\(node.downMbps)"
        savePreferences()
        appendLocalLog("Switched node -> \(node.remark)")
        if isConnected {
            backend.applyLiveConfig(config: buildEngineConfig(for: node), node: node)
            showToast("正在热切换至 \(node.remark)")
        } else {
            showToast("已选择节点：\(node.remark)")
        }
    }

    func deleteNode(_ node: GhostNode) {
        nodes.removeAll { $0.id == node.id }
        if selectedNodeID == node.id {
            selectedNodeID = nodes.first?.id ?? ""
        }
        savePreferences()
        showToast("已删除节点")
    }

    func renameNode(_ node: GhostNode, remark: String) {
        guard let idx = nodes.firstIndex(where: { $0.id == node.id }) else { return }
        let trimmed = remark.trimmingCharacters(in: .whitespacesAndNewlines)
        let clean = trimmed.isEmpty ? "\(node.host):\(node.port)" : String(trimmed.prefix(64))
        var updated = nodes[idx]
        updated.remark = clean
        var baseURI = updated.uri
        if let hashIdx = baseURI.firstIndex(of: "#") {
            baseURI = String(baseURI[..<hashIdx])
        }
        let encoded = clean.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? clean
        updated.uri = "\(baseURI)#\(encoded)"
        nodes[idx] = updated
        savePreferences()
        appendLocalLog("Renamed node -> \(clean)")
        showToast("节点备注已更新：\(clean)")
    }

    func applySettings() {
        socksPortText = "\(effectiveSocksPort)"
        httpPortText = "\(effectiveHttpPort)"
        upMbpsText = "\(effectiveUpMbps)"
        downMbpsText = "\(effectiveDownMbps)"
        savePreferences()

        if let node = activeNode, (isConnected || isTransitioning) {
            let cfg = buildEngineConfig(for: node)
            backend.applyLiveConfig(config: cfg, node: node)
            appendLocalLog("Applied config: transport=\(cfg.transport), route=\(cfg.routeMode), ports=\(cfg.socksPort)/\(cfg.httpPort)")
            showToast("参数已保存并通知内核生效")
        } else {
            showToast("参数已保存")
        }
    }

    func clearLogs() {
        localLogs.removeAll()
        status.logs.removeAll()
        backend.clearLogs()
        showToast("日志已清空")
    }

    func refreshDiagnostic() {
        backend.fetchDiagnostic { [weak self] text in
            Task { @MainActor in
                self?.diagnosticText = text
            }
        }
    }

    func buildShadowrocketURLString() -> String {
        let remark = activeNode?.remark ?? "Kestrel Local"
        return GhostMobileBridge.buildShadowrocketAddURL(socksPort: effectiveSocksPort, remark: remark)
    }

    func buildBypassRuleString() -> String {
        guard let host = activeNode?.host, !host.isEmpty else {
            return ""
        }
        return GhostMobileBridge.buildBypassRule(serverHost: host)
    }

    func showToast(_ message: String) {
        toastMessage = message
        toastClearTask?.cancel()
        let task = DispatchWorkItem { [weak self] in
            if self?.toastMessage == message {
                self?.toastMessage = ""
            }
        }
        toastClearTask = task
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.8, execute: task)
    }

    var parsedCustomRules: [String] {
        customRulesText
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    func quickAddCustomRule(host: String, action: String) {
        let cleanHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            .lowercased()
        let act = action.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard !cleanHost.isEmpty, act == "DIRECT" || act == "PROXY" || act == "REJECT" else { return }

        let ruleLine: String
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        if cleanHost.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            ruleLine = "IP-CIDR,\(cleanHost)/32,\(act)"
        } else if cleanHost.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            ruleLine = "IP-CIDR6,\(cleanHost)/128,\(act)"
        } else {
            ruleLine = "DOMAIN-SUFFIX,\(cleanHost),\(act)"
        }

        let targetType = ruleLine.split(separator: ",").first.map(String.init) ?? ""
        var lines = parsedCustomRules.filter { existing in
            let parts = existing.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            return !(parts.count >= 2 && parts[0] == targetType.lowercased() && parts[1] == cleanHost)
        }
        lines.insert(ruleLine, at: 0)
        customRulesText = lines.joined(separator: "\n")
        applySettings()
        showToast("已追加规则: \(ruleLine)")
    }

    private func buildEngineConfig(for node: GhostNode) -> GhostEngineConfig {
        GhostEngineConfig(
            linkURI: node.uri,
            socksPort: effectiveSocksPort,
            httpPort: effectiveHttpPort,
            routeMode: routeMode.rawValue,
            transport: transportMode.rawValue,
            upMbps: effectiveUpMbps,
            downMbps: effectiveDownMbps,
            asyncConnect: true,
            customRules: parsedCustomRules
        )
    }

    private func bindBackend() {
        backend.onStateChange = { [weak self] in
            self?.syncFromBackendState()
        }
        backend.onStatusUpdate = { [weak self] snap in
            guard let self = self else { return }
            self.status = snap
            if !snap.lastErr.isEmpty && snap.state != "connected" {
                self.errorBanner = snap.lastErr
            } else if snap.state == "connected" {
                self.errorBanner = ""
            }
            self.syncFromBackendState()
        }
        backend.onErrorReport = { [weak self] report in
            guard let self = self else { return }
            self.tunnelErrorReport = report
            self.errorBanner = "[\(report.domain) Code=\(report.code)] \(report.message)"
            self.appendLocalLog("ERROR [\(report.domain):\(report.code)] \(report.message)")
        }
        backend.onLogMessage = { [weak self] line in
            self?.appendLocalLog(line)
        }
    }

    private func syncFromBackendState() {
        isConnected = backend.isConnected
        isTransitioning = backend.isTransitioning
        backendStateLabel = backend.backendStateLabel
        detectedExtensionBundleID = backend.detectedExtensionBundleID
        keepAliveActive = backend.keepAliveActive
    }

    private func appendLocalLog(_ msg: String) {
        let df = DateFormatter()
        df.dateFormat = "HH:mm:ss"
        let entry = GhostLogEntry(time: df.string(from: Date()), message: msg)
        localLogs.append(entry)
        if localLogs.count > 120 {
            localLogs.removeFirst(localLogs.count - 120)
        }
    }

    private func loadPreferences() {
        if let data = defaults.data(forKey: storageKeyNodes),
           let decoded = try? JSONDecoder().decode([GhostNode].self, from: data) {
            nodes = decoded
        }
        selectedNodeID = defaults.string(forKey: storageKeySelectedID) ?? nodes.first?.id ?? ""
        if let rmRaw = defaults.string(forKey: storageKeyRouteMode),
           let rm = GhostRouteMode(rawValue: rmRaw) {
            routeMode = rm
        }
        if let tmRaw = defaults.string(forKey: storageKeyTransport),
           let tm = GhostTransportMode(rawValue: tmRaw) {
            transportMode = tm
        }
        if defaults.object(forKey: storageKeyUpMbps) != nil {
            upMbpsText = "\(defaults.integer(forKey: storageKeyUpMbps))"
        }
        if defaults.object(forKey: storageKeyDownMbps) != nil {
            downMbpsText = "\(defaults.integer(forKey: storageKeyDownMbps))"
        }
        if defaults.object(forKey: storageKeySocksPort) != nil {
            let sp = defaults.integer(forKey: storageKeySocksPort)
            if sp > 0 { socksPortText = "\(sp)" }
        }
        if defaults.object(forKey: storageKeyHttpPort) != nil {
            let hp = defaults.integer(forKey: storageKeyHttpPort)
            if hp > 0 { httpPortText = "\(hp)" }
        }
        customRulesText = defaults.string(forKey: storageKeyCustomRules) ?? ""
    }

    private func savePreferences() {
        if let encoded = try? JSONEncoder().encode(nodes) {
            defaults.set(encoded, forKey: storageKeyNodes)
        }
        defaults.set(selectedNodeID, forKey: storageKeySelectedID)
        defaults.set(routeMode.rawValue, forKey: storageKeyRouteMode)
        defaults.set(transportMode.rawValue, forKey: storageKeyTransport)
        defaults.set(effectiveUpMbps, forKey: storageKeyUpMbps)
        defaults.set(effectiveDownMbps, forKey: storageKeyDownMbps)
        defaults.set(effectiveSocksPort, forKey: storageKeySocksPort)
        defaults.set(effectiveHttpPort, forKey: storageKeyHttpPort)
        defaults.set(customRulesText, forKey: storageKeyCustomRules)
    }
}
