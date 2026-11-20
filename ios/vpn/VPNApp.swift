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
