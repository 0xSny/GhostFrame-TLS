import AppIntents
import Foundation
import NetworkExtension
import WidgetKit

@available(iOS 16.0, *)
enum GhostVPNIntentError: Error, CustomLocalizedStringResourceConvertible {
    case noProfileConfigured

    var localizedStringResource: LocalizedStringResource {
        switch self {
        case .noProfileConfigured:
            return "请先打开 GhostFrame VPN 导入节点并连接一次，完成系统 VPN 授权后再使用控制中心开关。"
        }
    }
}

enum GhostVPNControlBridge {
    static let controlKind = "GhostFrameVPNControlToggle"

    static func loadAllManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { continuation in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: managers ?? [])
                }
            }
        }
    }

    static func savePreferences(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    static func reloadPreferences(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    static func loadPreferredManager() async throws -> NETunnelProviderManager? {
        let managers = try await loadAllManagers()
        guard !managers.isEmpty else { return nil }
        if let matched = managers.first(where: { mgr in
            let desc = (mgr.localizedDescription ?? "").lowercased()
            let bid = ((mgr.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier ?? "").lowercased()
            return desc.contains("ghostframe") || bid.contains("ghost") || bid.hasSuffix(".tunnel")
        }) {
            return matched
        }
        return managers.first
    }

    static func isActiveStatus(_ status: NEVPNStatus) -> Bool {
        switch status {
        case .connected, .connecting, .reasserting:
            return true
        default:
            return false
        }
    }

    static func queryIsTunnelActive() async -> Bool {
        if let mgr = try? await loadPreferredManager() {
            return isActiveStatus(mgr.connection.status)
        }
        guard let url = URL(string: "http://127.0.0.1:10809/_gft/ping") else {
            return false
        }
        let cfg = URLSessionConfiguration.ephemeral
        cfg.connectionProxyDictionary = [:]
        cfg.timeoutIntervalForRequest = 0.4
        cfg.timeoutIntervalForResource = 0.6
        let session = URLSession(configuration: cfg)
        defer { session.invalidateAndCancel() }
        do {
            let (_, resp) = try await session.data(from: url)
            return (resp as? HTTPURLResponse)?.statusCode == 200
        } catch {
            return false
        }
    }

    static func reloadControls() {
        if #available(iOS 18.0, *) {
            ControlCenter.shared.reloadControls(ofKind: controlKind)
            ControlCenter.shared.reloadAllControls()
        }
    }

    static func setVPNEnabled(_ enable: Bool) async throws {
        guard let manager = try await loadPreferredManager() else {
            if #available(iOS 16.0, *) {
                throw GhostVPNIntentError.noProfileConfigured
            }
            throw NSError(
                domain: "com.ghostframe.vpn",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "请先打开 GhostFrame VPN 导入节点并连接一次，完成系统 VPN 授权后再使用控制中心开关。"]
            )
        }

        if enable {
            if !manager.isEnabled {
                manager.isEnabled = true
                try await savePreferences(manager)
                try await reloadPreferences(manager)
            }
            let status = manager.connection.status
            if status == .disconnected || status == .invalid || status == .disconnecting {
                let providerCfg = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
                if let session = manager.connection as? NETunnelProviderSession,
                   let cfgJSON = providerCfg?["configJSON"] as? String,
                   !cfgJSON.isEmpty {
                    try session.startVPNTunnel(options: [
                        "configJSON": cfgJSON as NSObject
                    ])
                } else {
                    try manager.connection.startVPNTunnel()
                }
            }
        } else {
            let status = manager.connection.status
            if status != .disconnected && status != .invalid {
                manager.connection.stopVPNTunnel()
            }
        }

        try? await Task.sleep(nanoseconds: 350_000_000)
        reloadControls()
    }
}

@available(iOS 18.0, *)
struct ToggleGhostVPNIntent: SetValueIntent {
    static var title: LocalizedStringResource = "切换 GhostFrame VPN"
    static var description = IntentDescription("快速开启或关闭 GhostFrame VPN 安全隧道。")
    static var openAppWhenRun: Bool = false
    static var isDiscoverable: Bool = true

    @Parameter(title: "开启 VPN")
    var value: Bool

    init() {}

    init(value: Bool) {
        self.value = value
    }

    func perform() async throws -> some IntentResult {
        try await GhostVPNControlBridge.setVPNEnabled(value)
        return .result()
    }
}

@available(iOS 16.0, *)
struct ConnectGhostVPNIntent: AppIntent {
    static var title: LocalizedStringResource = "开启 GhostFrame VPN"
    static var description = IntentDescription("在后台连接 GhostFrame VPN 安全隧道。")
    static var openAppWhenRun: Bool = false
    static var isDiscoverable: Bool = true

    func perform() async throws -> some IntentResult {
        try await GhostVPNControlBridge.setVPNEnabled(true)
        return .result()
    }
}

@available(iOS 16.0, *)
struct DisconnectGhostVPNIntent: AppIntent {
    static var title: LocalizedStringResource = "关闭 GhostFrame VPN"
    static var description = IntentDescription("断开 GhostFrame VPN 安全隧道。")
    static var openAppWhenRun: Bool = false
    static var isDiscoverable: Bool = true

    func perform() async throws -> some IntentResult {
        try await GhostVPNControlBridge.setVPNEnabled(false)
        return .result()
    }
}
