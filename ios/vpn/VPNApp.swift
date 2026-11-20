import AppIntents
import SwiftUI

@main
struct GhostFrameVPNApp: App {
    @StateObject private var viewModel = GhostAppViewModel(
        edition: .vpn,
        backend: VPNManager()
    )

    var body: some Scene {
        WindowGroup {
            ConsoleView(viewModel: viewModel)
        }
    }
}

@available(iOS 17.0, *)
struct KestrelAppShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: ConnectGhostVPNIntent(),
            phrases: [
                "连接 \(.applicationName)",
                "打开 \(.applicationName)",
                "Connect \(.applicationName)"
            ],
            shortTitle: "连接 Kestrel",
            systemImageName: "lock.shield.fill"
        )
        AppShortcut(
            intent: DisconnectGhostVPNIntent(),
            phrases: [
                "断开 \(.applicationName)",
                "关闭 \(.applicationName)",
                "Disconnect \(.applicationName)"
            ],
            shortTitle: "断开 Kestrel",
            systemImageName: "lock.shield"
        )
    }
}
