import AppIntents
import SwiftUI
import WidgetKit

@main
struct GhostControlWidgetBundle: WidgetBundle {
    var body: some Widget {
        GhostVPNControlWidget()
    }
}

struct GhostVPNControlWidget: ControlWidget {
    static let kind: String = GhostVPNControlBridge.controlKind

    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(
            kind: Self.kind,
            provider: GhostVPNControlValueProvider()
        ) { isConnected in
            ControlWidgetToggle(
                "Kestrel Duo",
                isOn: isConnected,
                action: ToggleGhostVPNIntent()
            ) { isOn in
                Label(
                    isOn ? "已连接" : "未连接",
                    systemImage: isOn ? "lock.shield.fill" : "lock.shield"
                )
            }
            .tint(.cyan)
        }
        .displayName("Kestrel Duo")
        .description("在控制中心、锁屏或操作按钮一键开启/关闭 Kestrel 隧道。")
    }
}

struct GhostVPNControlValueProvider: ControlValueProvider {
    typealias Value = Bool

    var previewValue: Bool {
        false
    }

    func currentValue() async throws -> Bool {
        await GhostVPNControlBridge.queryIsTunnelActive()
    }
}
