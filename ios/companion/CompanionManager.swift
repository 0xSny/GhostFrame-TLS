import Foundation
import Network

@MainActor
final class CompanionManager: GhostBackend {
    var onStateChange: (() -> Void)?
    var onStatusUpdate: ((GhostStatusSnapshot) -> Void)?
    var onErrorReport: ((GhostTunnelErrorReport) -> Void)?
    var onLogMessage: ((String) -> Void)?

    let detectedExtensionBundleID: String = ""

    private(set) var isConnected: Bool = false
    private(set) var isTransitioning: Bool = false
    private(set) var backendStateLabel: String = "伴侣待机"
    private(set) var keepAliveActive: Bool = false

    private let keepAlive = SilentAudioKeepAlive()
    private var pathMonitor: NWPathMonitor?
    private let monitorQueue = DispatchQueue(label: "com.kestrel.air.pathmonitor")
    private var lastPhysicalIface: String = ""
    private var pollTimer: Timer?

    init() {
        let supportDir = GhostNetworkHelper.appSupportDirectory(subdir: "KestrelAir")
        GhostMobileBridge.initCore(dataDir: supportDir, isTunnelExt: false)
        startNetworkMonitor()
    }

    deinit {
        pollTimer?.invalidate()
        pathMonitor?.cancel()
    }

    func connect(config: GhostEngineConfig, node: GhostNode) {
        isTransitioning = true
        backendStateLabel = "启动本地内核..."
        onStateChange?()

        let cfgJSON = config.toJSONString()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let res = GhostMobileBridge.startEngine(configJSON: cfgJSON)
            Task { @MainActor in
                guard let self = self else { return }
                switch res {
                case .success:
                    self.keepAlive.start()
                    self.keepAliveActive = self.keepAlive.isActive
                    self.isTransitioning = false
                    self.isConnected = true
                    self.backendStateLabel = "本地核心运行中"
                    self.startPolling()
                    self.pollStatusOnce()
                    self.onStateChange?()
                case .failure(let err):
                    self.keepAlive.stop()
                    self.keepAliveActive = false
                    self.isTransitioning = false
                    self.isConnected = false
                    self.backendStateLabel = "启动失败"
                    self.onStateChange?()
                    self.onLogMessage?("Start failed: \(err.localizedDescription)")
                    self.onErrorReport?(GhostTunnelErrorReport(
                        title: "启动 Kestrel Air 本地代理失败",
                        domain: "com.kestrel.air",
                        code: -1,
                        message: err.localizedDescription,
                        mainBundleID: Bundle.main.bundleIdentifier ?? "unknown",
                        extensionBundleID: "none (single-process)",
                        hint: "请检查节点链接是否有效，或确认 SOCKS5/HTTP 端口未被占用。"
                    ))
                }
            }
        }
    }

    func disconnect() {
        stopPolling()
        keepAlive.stop()
        keepAliveActive = false
        isTransitioning = false
        isConnected = false
        backendStateLabel = "伴侣已停止"
        onStateChange?()

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            _ = GhostMobileBridge.stopEngine()
            let snap = GhostMobileBridge.getStatus()
            Task { @MainActor in
                self?.onStatusUpdate?(snap)
            }
        }
    }

    func applyLiveConfig(config: GhostEngineConfig, node: GhostNode) {
        connect(config: config, node: node)
    }

    func fetchDiagnostic(completion: @escaping (String) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            let text = GhostMobileBridge.getDiagnosticSnapshot()
            completion(text)
        }
    }

    func clearLogs() {
        GhostMobileBridge.clearLogs()
    }

    func updateRuleBundle(url: String?, completion: @escaping (Result<GhostRuleStats, Error>) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            let raw = GhostMobileBridge.updateRuleBundleRaw(url: url ?? "")
            completion(GhostMobileBridge.decodeRuleStats(fromJSON: raw))
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
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let snap = GhostMobileBridge.getStatus()
            Task { @MainActor in
                guard let self = self else { return }
                self.isConnected = (snap.state == "connected" || snap.state == "connecting")
                self.isTransitioning = (snap.state == "connecting")
                if snap.state == "connected" {
                    self.backendStateLabel = "隧道已建立 · 静音保活"
                } else if snap.state == "connecting" {
                    self.backendStateLabel = "握手中..."
                } else if snap.state == "error" {
                    self.backendStateLabel = "连接异常"
                } else {
                    self.backendStateLabel = "伴侣待机"
                }
                self.onStatusUpdate?(snap)
            }
        }
    }

    private func startNetworkMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }
            let iface = GhostNetworkHelper.preferredPhysicalInterface(from: path)
            guard !iface.isEmpty else { return }
            Task { @MainActor in
                if iface != self.lastPhysicalIface {
                    self.lastPhysicalIface = iface
                    GhostMobileBridge.onNetworkChanged(ifaceName: iface)
                    self.onLogMessage?("Network path changed -> \(iface)")
                }
            }
        }
        monitor.start(queue: monitorQueue)
        pathMonitor = monitor
    }
}
