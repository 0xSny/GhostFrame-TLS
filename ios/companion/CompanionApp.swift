import SwiftUI

@main
struct GhostFrameCompanionApp: App {
    @StateObject private var viewModel = GhostAppViewModel(
        edition: .companion,
        backend: CompanionManager()
    )

    var body: some Scene {
        WindowGroup {
            ConsoleView(viewModel: viewModel)
        }
    }
}
