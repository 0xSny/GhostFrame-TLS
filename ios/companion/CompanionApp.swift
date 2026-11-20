import SwiftUI

@main
struct KestrelAirApp: App {
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
