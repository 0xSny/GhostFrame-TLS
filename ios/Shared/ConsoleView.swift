import SwiftUI
import UIKit

private enum KestrelPalette {
    static let background = Color(red: 0.965, green: 0.969, blue: 0.980) // #F6F7FA
    static let card = Color.white                                       // #FFFFFF
    static let cardAlt = Color(red: 0.945, green: 0.961, blue: 0.976)    // #F1F5F9
    static let border = Color(red: 0.886, green: 0.910, blue: 0.941)     // #E2E8F0
    static let brand = Color(red: 0.008, green: 0.518, blue: 0.780)      // #0284C7
    static let emerald = Color(red: 0.020, green: 0.588, blue: 0.412)    // #059669
    static let amber = Color(red: 0.851, green: 0.467, blue: 0.024)      // #D97706
    static let crimson = Color(red: 0.863, green: 0.149, blue: 0.149)    // #DC2626
    static let textPrimary = Color(red: 0.059, green: 0.090, blue: 0.165)// #0F172A
    static let textSecondary = Color(red: 0.392, green: 0.455, blue: 0.545)// #64748B
}

private enum ConsoleMainTab: Hashable {
    case console
    case nodes
    case routingAndLogs
    case settings
}

private enum RouteLogSegment: Int, CaseIterable {
    case routes = 0
    case logs = 1

    var label: String {
        self == .routes ? "分流明细" : "运行日志"
    }
}

struct ConsoleView: View {
    @ObservedObject var viewModel: GhostAppViewModel

    @State private var selectedTab: ConsoleMainTab = .console
    @State private var routeLogSegment: RouteLogSegment = .routes
    @State private var showImportSheet = false
    @State private var showQRScanner = false
    @State private var showDiagnosticSheet = false
    @State private var importURIText = ""
    @State private var renamingNodeID: String?
    @State private var renameDraftText = ""
    @State private var pulseBreath = false

    var body: some View {
        ZStack {
            KestrelPalette.background.ignoresSafeArea()

            VStack(spacing: 0) {
                topBar
                    .padding(.horizontal, 16)
                    .padding(.top, 10)
                    .padding(.bottom, 10)
                    .background(KestrelPalette.card)
                    .overlay(
                        Rectangle()
                            .frame(height: 1)
                            .foregroundColor(KestrelPalette.border),
                        alignment: .bottom
                    )

                TabView(selection: $selectedTab) {
                    consoleTab
                        .tabItem {
                            Label("控制台", systemImage: "bolt.horizontal.circle.fill")
                        }
                        .tag(ConsoleMainTab.console)

                    nodesTab
                        .tabItem {
                            Label("节点", systemImage: "server.rack")
                        }
                        .tag(ConsoleMainTab.nodes)

                    routingAndLogsTab
                        .tabItem {
                            Label("分流与日志", systemImage: "list.bullet.rectangle")
                        }
                        .tag(ConsoleMainTab.routingAndLogs)

                    settingsTab
                        .tabItem {
                            Label("设置", systemImage: "slider.horizontal.3")
                        }
                        .tag(ConsoleMainTab.settings)
                }
                .tint(KestrelPalette.brand)
            }

            if !viewModel.toastMessage.isEmpty {
                VStack {
                    Spacer()
                    toastOverlay(viewModel.toastMessage)
                        .padding(.bottom, 64)
                }
                .frame(maxWidth: .infinity)
                .allowsHitTesting(false)
                .transition(.opacity)
            }
        }
        .preferredColorScheme(.light)
        .onAppear {
            withAnimation(.easeInOut(duration: 1.4).repeatForever(autoreverses: true)) {
                pulseBreath = true
            }
        }
        .sheet(isPresented: $showImportSheet) {
            importNodeSheet
        }
        .sheet(isPresented: $showQRScanner) {
            QRScannerSheetView { scanned in
                showQRScanner = false
                if viewModel.importLink(scanned) {
                    importURIText = ""
                    showImportSheet = false
                } else {
                    importURIText = scanned
                    showImportSheet = true
                }
            }
            .preferredColorScheme(.dark)
        }
        .sheet(isPresented: $showDiagnosticSheet) {
            diagnosticSheet
        }
        .sheet(item: $viewModel.tunnelErrorReport) { report in
            tunnelErrorSheet(report)
        }
    }

    // MARK: - Top Bar

    private var topBar: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(statusColor)
                .frame(width: 10, height: 10)
                .scaleEffect((viewModel.isConnected || viewModel.isTransitioning) && pulseBreath ? 1.22 : 1.0)
                .opacity((viewModel.isConnected || viewModel.isTransitioning) && pulseBreath ? 0.72 : 1.0)

            Text("Kestrel")
                .font(.system(size: 20, weight: .bold, design: .rounded))
                .foregroundColor(KestrelPalette.textPrimary)

            Text(viewModel.edition == .vpn ? "Duo" : "Air")
                .font(.system(size: 11, weight: .bold))
                .foregroundColor(KestrelPalette.brand)
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(KestrelPalette.brand.opacity(0.10))
                .cornerRadius(6)

            Text(dynamicVersionText)
                .font(.system(size: 11, weight: .medium, design: .monospaced))
                .monospacedDigit()
                .foregroundColor(KestrelPalette.textSecondary)
                .lineLimit(1)

            Spacer()

            Button(action: { showQRScanner = true }) {
                Image(systemName: "qrcode.viewfinder")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundColor(KestrelPalette.textPrimary)
                    .frame(width: 34, height: 34)
                    .background(KestrelPalette.cardAlt)
                    .overlay(RoundedRectangle(cornerRadius: 9).stroke(KestrelPalette.border, lineWidth: 1))
                    .cornerRadius(9)
            }

            Button(action: openImportSheetWithClipboardCheck) {
                HStack(spacing: 4) {
                    Image(systemName: "plus")
                        .font(.system(size: 12, weight: .bold))
                    Text("导入")
                        .font(.system(size: 13, weight: .semibold))
                }
                .foregroundColor(.white)
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
                .background(KestrelPalette.brand)
                .cornerRadius(9)
            }
        }
    }

    // MARK: - Tab 1: 控制台

    private var consoleTab: some View {
        ScrollView {
            VStack(spacing: 14) {
                connectionHeroCard
                trafficNumericCard
                quickModeCard
                telemetryGrid
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
        }
        .background(KestrelPalette.background)
    }

    private var connectionHeroCard: some View {
        VStack(spacing: 14) {
            Button(action: { selectedTab = .nodes }) {
                HStack(spacing: 10) {
                    VStack(alignment: .leading, spacing: 3) {
                        if let node = viewModel.activeNode {
                            HStack(spacing: 6) {
                                Text(node.remark)
                                    .font(.system(size: 15, weight: .bold))
                                    .foregroundColor(KestrelPalette.textPrimary)
                                    .lineLimit(1)
                                Spacer()
                                Text(node.transport.uppercased())
                                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                                    .foregroundColor(KestrelPalette.brand)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(KestrelPalette.brand.opacity(0.10))
                                    .cornerRadius(5)
                            }
                            HStack(spacing: 6) {
                                Text("\(node.host):\(String(node.port))")
                                    .font(.system(size: 12, design: .monospaced))
                                    .monospacedDigit()
                                    .foregroundColor(KestrelPalette.textSecondary)
                                    .lineLimit(1)
                                if !node.hopRange.isEmpty {
                                    Text("· Hop \(node.hopRange)")
                                        .font(.system(size: 11, design: .monospaced))
                                        .monospacedDigit()
                                        .foregroundColor(KestrelPalette.textSecondary)
                                        .lineLimit(1)
                                }
                            }
                        } else {
                            Text("尚未配置节点")
                                .font(.system(size: 15, weight: .semibold))
                                .foregroundColor(KestrelPalette.textPrimary)
                            Text("点击选择节点或右上角扫码/导入 ksl4:// 链接")
                                .font(.system(size: 12))
                                .foregroundColor(KestrelPalette.textSecondary)
                        }
                    }

                    Image(systemName: "chevron.right")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(KestrelPalette.textSecondary)
                }
                .padding(12)
                .background(KestrelPalette.cardAlt)
                .overlay(RoundedRectangle(cornerRadius: 11).stroke(KestrelPalette.border, lineWidth: 1))
                .cornerRadius(11)
            }
            .buttonStyle(.plain)

            Button(action: { viewModel.toggleConnection() }) {
                HStack(spacing: 10) {
                    if viewModel.isTransitioning {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                    } else {
                        Image(systemName: viewModel.isConnected ? "stop.circle.fill" : "bolt.fill")
                            .font(.system(size: 18, weight: .bold))
                    }
                    Text(primaryButtonTitle)
                        .font(.system(size: 16, weight: .bold))
                }
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 15)
                .background(primaryButtonColor)
                .cornerRadius(12)
                .shadow(color: primaryButtonColor.opacity(0.24), radius: 8, x: 0, y: 4)
            }

            HStack {
                HStack(spacing: 6) {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 7, height: 7)
                    Text(viewModel.backendStateLabel)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(KestrelPalette.textSecondary)
                }
                Spacer()
                Text("SOCKS :\(String(viewModel.effectiveSocksPort)) · HTTP :\(String(viewModel.effectiveHttpPort))")
                    .font(.system(size: 11, design: .monospaced))
                    .monospacedDigit()
                    .foregroundColor(KestrelPalette.textSecondary)
            }

            if !viewModel.errorBanner.isEmpty {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 13))
                        .foregroundColor(KestrelPalette.crimson)
                        .padding(.top, 1)
                    Text(viewModel.errorBanner)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(KestrelPalette.crimson)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(10)
                .background(KestrelPalette.crimson.opacity(0.08))
                .overlay(RoundedRectangle(cornerRadius: 9).stroke(KestrelPalette.crimson.opacity(0.25), lineWidth: 1))
                .cornerRadius(9)
            }
        }
        .kestrelCard()
    }

    private var trafficNumericCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("实时流量统计")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(KestrelPalette.textPrimary)
                Spacer()
                Text("活跃连接 \(viewModel.status.activeConns) · 流 \(viewModel.status.activeStreams)")
                    .font(.system(size: 11, design: .monospaced))
                    .monospacedDigit()
                    .foregroundColor(KestrelPalette.textSecondary)
            }

            LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)], spacing: 10) {
                numericTrafficCell(
                    label: "实时上行速率",
                    value: "↑ \(GhostByteFormatter.formatRate(viewModel.status.upBps))",
                    accent: KestrelPalette.brand
                )
                numericTrafficCell(
                    label: "实时下行速率",
                    value: "↓ \(GhostByteFormatter.formatRate(viewModel.status.downBps))",
                    accent: KestrelPalette.emerald
                )
                numericTrafficCell(
                    label: "累计上行",
                    value: GhostByteFormatter.formatBytes(viewModel.status.totalUp),
                    accent: KestrelPalette.textPrimary
                )
                numericTrafficCell(
                    label: "累计下行",
                    value: GhostByteFormatter.formatBytes(viewModel.status.totalDown),
                    accent: KestrelPalette.textPrimary
                )
            }
        }
        .kestrelCard()
    }

    private func numericTrafficCell(label: String, value: String, accent: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.system(size: 11))
                .foregroundColor(KestrelPalette.textSecondary)
            Text(value)
                .font(.system(size: 16, weight: .bold, design: .monospaced))
                .monospacedDigit()
                .foregroundColor(accent)
                .lineLimit(1)
                .minimumScaleFactor(0.75)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(KestrelPalette.cardAlt)
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(KestrelPalette.border, lineWidth: 1))
        .cornerRadius(10)
    }

    private var quickModeCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 6) {
                Text("运行模式")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(KestrelPalette.textSecondary)
                Picker("运行模式", selection: $viewModel.routeMode) {
                    ForEach(GhostRouteMode.allCases) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .onChange(of: viewModel.routeMode) { _ in
                    viewModel.applySettingsFromPicker()
                }
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("传输内核")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(KestrelPalette.textSecondary)
                Picker("传输内核", selection: $viewModel.transportMode) {
                    ForEach(GhostTransportMode.allCases) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .onChange(of: viewModel.transportMode) { _ in
                    viewModel.applySettingsFromPicker()
                }
            }

            if viewModel.edition == .companion {
                HStack(spacing: 10) {
                    Button(action: openInShadowrocket) {
                        Label("导入 Shadowrocket", systemImage: "paperplane.fill")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(KestrelPalette.brand)
                            .cornerRadius(9)
                    }

                    Button(action: copyBypassRule) {
                        Label("防回环规则", systemImage: "doc.on.doc")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundColor(KestrelPalette.textPrimary)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(KestrelPalette.cardAlt)
                            .overlay(RoundedRectangle(cornerRadius: 9).stroke(KestrelPalette.border, lineWidth: 1))
                            .cornerRadius(9)
                    }
                }
                .padding(.top, 2)
            }
        }
        .kestrelCard()
    }

    private var telemetryGrid: some View {
        LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)], spacing: 12) {
            telemetryTile(
                title: "延迟 · 协议",
                value: "\(rttText) · \(activeTransportText)",
                subtitle: String(format: "丢包 %.1f%% · FEC %llu", viewModel.status.lossPct, viewModel.status.fecRecovered),
                accent: KestrelPalette.brand
            )
            telemetryTile(
                title: "通道端口 · 跃迁",
                value: "\(hopPortsText)  H\(viewModel.status.hopCount)/R\(viewModel.status.rekeyCount)",
                subtitle: viewModel.status.hopState.isEmpty ? "等待跃迁探测" : viewModel.status.hopState,
                accent: KestrelPalette.emerald
            )
            telemetryTile(
                title: "物理网卡 · 绑定",
                value: viewModel.status.physicalIface.isEmpty ? "自动探测" : viewModel.status.physicalIface,
                subtitle: viewModel.status.netbindEnabled ? "IP_BOUND_IF 已启用" : "系统默认路由",
                accent: viewModel.status.netbindEnabled ? KestrelPalette.emerald : KestrelPalette.amber
            )
            telemetryTile(
                title: "扩展内存",
                value: String(format: "%.1f / 50 MB", viewModel.status.memAllocMB),
                subtitle: viewModel.status.lowMemMode ? "LowMem 守护中" : "标准模式",
                accent: viewModel.status.memAllocMB > 40.0 ? KestrelPalette.crimson : KestrelPalette.textPrimary
            )
        }
    }

    private func telemetryTile(title: String, value: String, subtitle: String, accent: Color) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(KestrelPalette.textSecondary)
            Text(value)
                .font(.system(size: 14, weight: .bold, design: .monospaced))
                .monospacedDigit()
                .foregroundColor(accent)
                .lineLimit(1)
                .minimumScaleFactor(0.75)
            Text(subtitle)
                .font(.system(size: 11))
                .monospacedDigit()
                .foregroundColor(KestrelPalette.textSecondary)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .kestrelCard()
    }

    // MARK: - Tab 2: 节点

    private var nodesTab: some View {
        ScrollView {
            VStack(spacing: 12) {
                if viewModel.nodes.isEmpty {
                    emptyNodesCard
                } else {
                    ForEach(viewModel.nodes) { node in
                        nodeRowCard(node)
                    }
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
        }
        .background(KestrelPalette.background)
    }

    private var emptyNodesCard: some View {
        VStack(spacing: 14) {
            Image(systemName: "antenna.radiowaves.left.and.right")
                .font(.system(size: 34))
                .foregroundColor(KestrelPalette.brand)
            Text("暂无可用节点")
                .font(.system(size: 16, weight: .bold))
                .foregroundColor(KestrelPalette.textPrimary)
            Text("支持扫描节点二维码，或直接粘贴 ksl4://、gft3://、gft2:// 链接导入。")
                .font(.system(size: 13))
                .foregroundColor(KestrelPalette.textSecondary)
                .multilineTextAlignment(.center)

            HStack(spacing: 10) {
                Button(action: { showQRScanner = true }) {
                    Label("扫码导入", systemImage: "qrcode.viewfinder")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 11)
                        .background(KestrelPalette.brand)
                        .cornerRadius(10)
                }

                Button(action: openImportSheetWithClipboardCheck) {
                    Label("粘贴链接", systemImage: "doc.on.clipboard")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(KestrelPalette.textPrimary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 11)
                        .background(KestrelPalette.cardAlt)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(KestrelPalette.border, lineWidth: 1))
                        .cornerRadius(10)
                }
            }
        }
        .padding(.vertical, 20)
        .kestrelCard()
    }

    private func nodeRowCard(_ node: GhostNode) -> some View {
        let isSelected = (viewModel.activeNode?.id == node.id)
        return VStack(alignment: .leading, spacing: 10) {
            if renamingNodeID == node.id {
                HStack(spacing: 8) {
                    TextField("输入新节点名称", text: $renameDraftText)
                        .font(.system(size: 14))
                        .foregroundColor(KestrelPalette.textPrimary)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 8)
                        .background(KestrelPalette.cardAlt)
                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(KestrelPalette.brand, lineWidth: 1))
                        .cornerRadius(8)

                    Button("保存") {
                        viewModel.renameNode(node, remark: renameDraftText)
                        renamingNodeID = nil
                        renameDraftText = ""
                    }
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(KestrelPalette.brand)
                    .cornerRadius(8)

                    Button("取消") {
                        renamingNodeID = nil
                        renameDraftText = ""
                    }
                    .font(.system(size: 13))
                    .foregroundColor(KestrelPalette.textSecondary)
                }
            } else {
                HStack(alignment: .center, spacing: 10) {
                    Button(action: { viewModel.selectNode(node) }) {
                        HStack(spacing: 10) {
                            Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                                .font(.system(size: 18))
                                .foregroundColor(isSelected ? KestrelPalette.brand : KestrelPalette.border)

                            VStack(alignment: .leading, spacing: 3) {
                                HStack(spacing: 6) {
                                    Text(node.remark)
                                        .font(.system(size: 15, weight: .bold))
                                        .foregroundColor(KestrelPalette.textPrimary)
                                        .lineLimit(1)
                                    if isSelected {
                                        Text(viewModel.isConnected ? "当前连接" : "已选中")
                                            .font(.system(size: 10, weight: .bold))
                                            .foregroundColor(viewModel.isConnected ? KestrelPalette.emerald : KestrelPalette.brand)
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background((viewModel.isConnected ? KestrelPalette.emerald : KestrelPalette.brand).opacity(0.12))
                                            .cornerRadius(5)
                                    }
                                }
                                Text("\(node.host):\(String(node.port)) · \(node.transport.uppercased())\(node.hopRange.isEmpty ? "" : " · Hop \(node.hopRange)")")
                                    .font(.system(size: 11, design: .monospaced))
                                    .monospacedDigit()
                                    .foregroundColor(KestrelPalette.textSecondary)
                                    .lineLimit(1)
                            }
                            Spacer()
                        }
                    }
                    .buttonStyle(.plain)

                    Button(action: {
                        renamingNodeID = node.id
                        renameDraftText = node.remark
                    }) {
                        Image(systemName: "pencil")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundColor(KestrelPalette.textSecondary)
                            .frame(width: 30, height: 30)
                            .background(KestrelPalette.cardAlt)
                            .cornerRadius(7)
                    }

                    Button(action: { viewModel.deleteNode(node) }) {
                        Image(systemName: "trash")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundColor(KestrelPalette.crimson)
                            .frame(width: 30, height: 30)
                            .background(KestrelPalette.crimson.opacity(0.08))
                            .cornerRadius(7)
                    }
                }
            }
        }
        .padding(13)
        .background(KestrelPalette.card)
        .overlay(
            RoundedRectangle(cornerRadius: 13)
                .stroke(isSelected ? KestrelPalette.brand : KestrelPalette.border, lineWidth: isSelected ? 1.5 : 1)
        )
        .cornerRadius(13)
        .shadow(color: Color.black.opacity(0.03), radius: 5, x: 0, y: 2)
    }

    // MARK: - Tab 3: 分流与日志

    private var routingAndLogsTab: some View {
        VStack(spacing: 12) {
            HStack(spacing: 10) {
                Picker("视图切换", selection: $routeLogSegment) {
                    ForEach(RouteLogSegment.allCases, id: \.self) { seg in
                        Text(seg.label).tag(seg)
                    }
                }
                .pickerStyle(.segmented)

                Button(action: {
                    viewModel.refreshDiagnostic()
                    showDiagnosticSheet = true
                }) {
                    HStack(spacing: 4) {
                        Image(systemName: "stethoscope")
                            .font(.system(size: 12, weight: .semibold))
                        Text("诊断报告")
                            .font(.system(size: 12, weight: .semibold))
                    }
                    .foregroundColor(KestrelPalette.brand)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 7)
                    .background(KestrelPalette.card)
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(KestrelPalette.border, lineWidth: 1))
                    .cornerRadius(8)
                }
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)

            ScrollView {
                VStack(spacing: 12) {
                    if routeLogSegment == .routes {
                        recentRoutesView
                    } else {
                        runtimeLogsView
                    }
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 16)
            }
        }
        .background(KestrelPalette.background)
    }

    private var recentRoutesView: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                hitCounterBadge(title: "直连命中", count: viewModel.ruleStats.directHits, accent: KestrelPalette.emerald)
                hitCounterBadge(title: "代理命中", count: viewModel.ruleStats.proxyHits, accent: KestrelPalette.brand)
                hitCounterBadge(title: "拦截", count: viewModel.ruleStats.rejectHits, accent: KestrelPalette.crimson)
            }

            let items = viewModel.status.recentRoutes
            if items.isEmpty {
                Text("暂无最近分流记录，连接后发起访问即可查看实时命中明细。")
                    .font(.system(size: 12))
                    .foregroundColor(KestrelPalette.textSecondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .kestrelCard()
            } else {
                VStack(spacing: 8) {
                    ForEach(items) { item in
                        HStack(alignment: .center, spacing: 8) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(item.target.isEmpty ? item.host : item.target)
                                    .font(.system(size: 13, weight: .semibold, design: .monospaced))
                                    .foregroundColor(KestrelPalette.textPrimary)
                                    .lineLimit(1)
                                HStack(spacing: 6) {
                                    Text(item.action.uppercased())
                                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                                        .foregroundColor(routeActionColor(item.action))
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(routeActionColor(item.action).opacity(0.10))
                                        .cornerRadius(4)
                                    Text("\(item.time) · \(item.reason)")
                                        .font(.system(size: 11, design: .monospaced))
                                        .monospacedDigit()
                                        .foregroundColor(KestrelPalette.textSecondary)
                                        .lineLimit(1)
                                }
                            }
                            Spacer()

                            if !item.host.isEmpty {
                                HStack(spacing: 6) {
                                    Button("改代理") {
                                        viewModel.quickAddCustomRule(host: item.host, action: "PROXY")
                                    }
                                    .font(.system(size: 11, weight: .semibold))
                                    .foregroundColor(KestrelPalette.brand)
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 5)
                                    .background(KestrelPalette.brand.opacity(0.10))
                                    .cornerRadius(6)

                                    Button("改直连") {
                                        viewModel.quickAddCustomRule(host: item.host, action: "DIRECT")
                                    }
                                    .font(.system(size: 11, weight: .semibold))
                                    .foregroundColor(KestrelPalette.emerald)
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 5)
                                    .background(KestrelPalette.emerald.opacity(0.10))
                                    .cornerRadius(6)
                                }
                            }
                        }
                        .padding(11)
                        .background(KestrelPalette.card)
                        .overlay(RoundedRectangle(cornerRadius: 11).stroke(KestrelPalette.border, lineWidth: 1))
                        .cornerRadius(11)
                    }
                }
            }
        }
    }

    private func hitCounterBadge(title: String, count: UInt64, accent: Color) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
                .font(.system(size: 11))
                .foregroundColor(KestrelPalette.textSecondary)
            Text("\(count)")
                .font(.system(size: 16, weight: .bold, design: .monospaced))
                .monospacedDigit()
                .foregroundColor(accent)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(KestrelPalette.card)
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(KestrelPalette.border, lineWidth: 1))
        .cornerRadius(10)
        .shadow(color: Color.black.opacity(0.03), radius: 4, x: 0, y: 2)
    }

    private var runtimeLogsView: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("运行日志 (\(viewModel.combinedLogs.count))")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(KestrelPalette.textPrimary)
                    .monospacedDigit()
                Spacer()
                Button("复制全部") {
                    let text = viewModel.combinedLogs.map { "\($0.time) \($0.message)" }.joined(separator: "\n")
                    UIPasteboard.general.string = text
                    viewModel.showToast("已复制运行日志")
                }
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(KestrelPalette.brand)

                Button("清空") {
                    viewModel.clearLogs()
                }
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(KestrelPalette.textSecondary)
                .padding(.leading, 10)
            }

            VStack(alignment: .leading, spacing: 6) {
                let entries = Array(viewModel.combinedLogs.suffix(80).reversed())
                if entries.isEmpty {
                    Text("等待引擎事件...")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(KestrelPalette.textSecondary)
                } else {
                    ForEach(entries) { item in
                        HStack(alignment: .top, spacing: 6) {
                            Text(item.time)
                                .font(.system(size: 10, design: .monospaced))
                                .monospacedDigit()
                                .foregroundColor(KestrelPalette.textSecondary)
                            Text(item.message)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(logColor(for: item.message))
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
            }
            .kestrelCard()
        }
    }

    // MARK: - Tab 4: 设置

    private var settingsTab: some View {
        ScrollView {
            VStack(spacing: 14) {
                VStack(alignment: .leading, spacing: 12) {
                    Text("带宽限速与本地端口")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(KestrelPalette.textPrimary)

                    HStack(spacing: 10) {
                        labeledNumberField(title: "上行限速 (Mbps, 0=自动)", text: $viewModel.upMbpsText)
                        labeledNumberField(title: "下行限速 (Mbps, 0=自动)", text: $viewModel.downMbpsText)
                    }

                    HStack(spacing: 10) {
                        labeledNumberField(title: "SOCKS5 本地端口", text: $viewModel.socksPortText)
                        labeledNumberField(title: "HTTP 本地端口", text: $viewModel.httpPortText)
                    }

                    Toggle(isOn: $viewModel.enableIPv6) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("开启 IPv6 双栈分流")
                                .font(.system(size: 14, weight: .medium))
                                .foregroundColor(KestrelPalette.textPrimary)
                            Text("启用后 TUN 接管并代理 IPv6 流量；关闭时纯 IPv6 蜂窝仍自动走 NAT64。")
                                .font(.system(size: 11))
                                .foregroundColor(KestrelPalette.textSecondary)
                        }
                    }
                    .tint(KestrelPalette.brand)
                }
                .kestrelCard()

                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text("离线 KSLR 规则库")
                            .font(.system(size: 14, weight: .bold))
                            .foregroundColor(KestrelPalette.textPrimary)
                        Spacer()
                        Text(viewModel.ruleStats.rulesetVersion)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(KestrelPalette.brand)
                    }

                    Text("内置域名 \(viewModel.ruleStats.builtinDomains) 条 · CIDR \(viewModel.ruleStats.builtinCidrs) 条 · 自定义 \(viewModel.ruleStats.customRules) 条 · 来源: \(viewModel.ruleStats.rulesSource)")
                        .font(.system(size: 12))
                        .monospacedDigit()
                        .foregroundColor(KestrelPalette.textSecondary)

                    Button(action: { viewModel.updateRuleBundle() }) {
                        HStack(spacing: 8) {
                            if viewModel.isUpdatingRules {
                                ProgressView()
                                    .progressViewStyle(CircularProgressViewStyle(tint: KestrelPalette.brand))
                            } else {
                                Image(systemName: "arrow.triangle.2.circlepath")
                                    .font(.system(size: 13, weight: .semibold))
                            }
                            Text(viewModel.isUpdatingRules ? "正在更新规则库..." : "更新分流规则库")
                                .font(.system(size: 13, weight: .semibold))
                        }
                        .foregroundColor(KestrelPalette.brand)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(KestrelPalette.brand.opacity(0.09))
                        .cornerRadius(9)
                    }
                    .disabled(viewModel.isUpdatingRules)
                }
                .kestrelCard()

                VStack(alignment: .leading, spacing: 10) {
                    Text("自定义规则 (Clash / Surge 格式)")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(KestrelPalette.textPrimary)
                    Text("每行一条，例如：DOMAIN-SUFFIX,baidu.com,DIRECT 或 IP-CIDR,1.1.1.1/32,PROXY")
                        .font(.system(size: 11))
                        .foregroundColor(KestrelPalette.textSecondary)

                    TextEditor(text: $viewModel.customRulesText)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(KestrelPalette.textPrimary)
                        .frame(minHeight: 110)
                        .padding(8)
                        .background(KestrelPalette.cardAlt)
                        .overlay(RoundedRectangle(cornerRadius: 9).stroke(KestrelPalette.border, lineWidth: 1))
                        .cornerRadius(9)

                    Button(action: { viewModel.applySettings() }) {
                        Text("保存并应用参数")
                            .font(.system(size: 15, weight: .bold))
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 13)
                            .background(KestrelPalette.brand)
                            .cornerRadius(10)
                    }
                }
                .kestrelCard()

                VStack(alignment: .leading, spacing: 5) {
                    Text("\(viewModel.edition.title) · \(dynamicVersionText)")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(KestrelPalette.textPrimary)
                    Text("Main Bundle: \(Bundle.main.bundleIdentifier ?? "-")")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(KestrelPalette.textSecondary)
                        .lineLimit(1)
                    if viewModel.edition == .vpn {
                        Text("Tunnel Extension: \(viewModel.detectedExtensionBundleID)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(KestrelPalette.textSecondary)
                            .lineLimit(1)
                    } else {
                        Text(viewModel.keepAliveActive ? "保活状态：16kHz 静音 PCM 后台运行中" : "保活状态：单进程伴侣模式 (零扩展)")
                            .font(.system(size: 11))
                            .foregroundColor(viewModel.keepAliveActive ? KestrelPalette.emerald : KestrelPalette.textSecondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .kestrelCard()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
        }
        .background(KestrelPalette.background)
    }

    // MARK: - Sheets

    private var importNodeSheet: some View {
        NavigationView {
            VStack(alignment: .leading, spacing: 14) {
                Text("粘贴 ksl4://、gft3://、gft2:// 或 gft:// 节点链接")
                    .font(.system(size: 13))
                    .foregroundColor(KestrelPalette.textSecondary)

                TextEditor(text: $importURIText)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(KestrelPalette.textPrimary)
                    .frame(height: 150)
                    .padding(10)
                    .background(KestrelPalette.card)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(KestrelPalette.border, lineWidth: 1))
                    .cornerRadius(10)

                HStack(spacing: 10) {
                    Button("从剪贴板粘贴") {
                        if let clip = UIPasteboard.general.string {
                            importURIText = clip.trimmingCharacters(in: .whitespacesAndNewlines)
                        }
                    }
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(KestrelPalette.textPrimary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 11)
                    .background(KestrelPalette.cardAlt)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(KestrelPalette.border, lineWidth: 1))
                    .cornerRadius(10)

                    Button("解析并导入") {
                        if viewModel.importLink(importURIText) {
                            importURIText = ""
                            showImportSheet = false
                        }
                    }
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 11)
                    .background(KestrelPalette.brand)
                    .cornerRadius(10)
                }
                Spacer()
            }
            .padding(16)
            .background(KestrelPalette.background.ignoresSafeArea())
            .navigationTitle("导入节点链接")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { showImportSheet = false }
                }
            }
        }
        .preferredColorScheme(.light)
    }

    private var diagnosticSheet: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(viewModel.diagnosticText.isEmpty ? "正在采集诊断信息..." : viewModel.diagnosticText)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(KestrelPalette.textPrimary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .background(KestrelPalette.card)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(KestrelPalette.border, lineWidth: 1))
                        .cornerRadius(10)

                    Button("复制诊断报告") {
                        UIPasteboard.general.string = viewModel.diagnosticText
                        viewModel.showToast("已复制诊断报告")
                    }
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(KestrelPalette.brand)
                    .cornerRadius(10)
                }
                .padding(16)
            }
            .background(KestrelPalette.background.ignoresSafeArea())
            .navigationTitle("脱敏诊断报告")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { showDiagnosticSheet = false }
                }
            }
        }
        .preferredColorScheme(.light)
    }

    private func tunnelErrorSheet(_ report: GhostTunnelErrorReport) -> some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(report.title)
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(KestrelPalette.crimson)

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Domain: \(report.domain)")
                        Text("Code: \(report.code)")
                            .monospacedDigit()
                        Text("Main Bundle: \(report.mainBundleID)")
                        Text("Extension Bundle: \(report.extensionBundleID)")
                        Text("Message: \(report.message)")
                    }
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(KestrelPalette.textPrimary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                    .background(KestrelPalette.card)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(KestrelPalette.border, lineWidth: 1))
                    .cornerRadius(10)

                    Text(report.hint)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(KestrelPalette.amber)
                        .padding(12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(KestrelPalette.amber.opacity(0.10))
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(KestrelPalette.amber.opacity(0.25), lineWidth: 1))
                        .cornerRadius(10)

                    Button("复制完整错误详情") {
                        UIPasteboard.general.string = "\(report.title)\nDomain: \(report.domain)\nCode: \(report.code)\nMain: \(report.mainBundleID)\nExt: \(report.extensionBundleID)\nMessage: \(report.message)\nHint: \(report.hint)"
                        viewModel.showToast("已复制系统错误报告")
                    }
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(KestrelPalette.brand)
                    .cornerRadius(10)
                }
                .padding(16)
            }
            .background(KestrelPalette.background.ignoresSafeArea())
            .navigationTitle("NetworkExtension 错误详情")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { viewModel.tunnelErrorReport = nil }
                }
            }
        }
        .preferredColorScheme(.light)
    }

    // MARK: - Helpers

    private func openImportSheetWithClipboardCheck() {
        if let clip = UIPasteboard.general.string?.trimmingCharacters(in: .whitespacesAndNewlines),
           clip.hasPrefix("ksl") || clip.hasPrefix("gft") {
            importURIText = clip
        }
        showImportSheet = true
    }

    private func labeledNumberField(title: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(KestrelPalette.textSecondary)
            TextField("", text: text)
                .keyboardType(.numberPad)
                .font(.system(size: 14, design: .monospaced))
                .monospacedDigit()
                .foregroundColor(KestrelPalette.textPrimary)
                .padding(.horizontal, 10)
                .padding(.vertical, 9)
                .background(KestrelPalette.cardAlt)
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(KestrelPalette.border, lineWidth: 1))
                .cornerRadius(8)
        }
    }

    private func toastOverlay(_ message: String) -> some View {
        Text(message)
            .font(.system(size: 12, weight: .semibold))
            .foregroundColor(KestrelPalette.textPrimary)
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .background(KestrelPalette.card.opacity(0.97))
            .overlay(RoundedRectangle(cornerRadius: 20).stroke(KestrelPalette.brand.opacity(0.6), lineWidth: 1))
            .cornerRadius(20)
            .shadow(color: Color.black.opacity(0.10), radius: 10, x: 0, y: 4)
    }

    private var dynamicVersionText: String {
        let v = viewModel.status.version.trimmingCharacters(in: .whitespacesAndNewlines)
        return v.isEmpty ? GhostStatusSnapshot.bundleVersionLabel : v
    }

    private var statusColor: Color {
        if viewModel.isConnected { return KestrelPalette.emerald }
        if viewModel.isTransitioning { return KestrelPalette.amber }
        if !viewModel.errorBanner.isEmpty { return KestrelPalette.crimson }
        return KestrelPalette.textSecondary
    }

    private var primaryButtonColor: Color {
        if viewModel.isConnected { return KestrelPalette.crimson }
        if viewModel.isTransitioning { return KestrelPalette.amber }
        return KestrelPalette.brand
    }

    private var primaryButtonTitle: String {
        if viewModel.isConnected {
            return "断开安全隧道"
        }
        if viewModel.isTransitioning {
            return "正在建立通道... (点击取消)"
        }
        return "连接 Kestrel"
    }

    private var rttText: String {
        let ms = viewModel.status.srttMs > 0 ? viewModel.status.srttMs : viewModel.status.pingMs
        return ms > 0 ? "\(ms)ms" : "--"
    }

    private var activeTransportText: String {
        if !viewModel.status.activeTransport.isEmpty {
            return viewModel.status.activeTransport.uppercased()
        }
        return viewModel.transportMode.rawValue.uppercased()
    }

    private var hopPortsText: String {
        let nonZero = viewModel.status.rtcPorts.filter { $0 > 0 }
        if !nonZero.isEmpty {
            return nonZero.map(String.init).joined(separator: "/")
        }
        if viewModel.status.rtcPort > 0 {
            return ":\(String(viewModel.status.rtcPort))"
        }
        return "--"
    }

    private func routeActionColor(_ action: String) -> Color {
        switch action.lowercased() {
        case "direct": return KestrelPalette.emerald
        case "reject": return KestrelPalette.crimson
        default: return KestrelPalette.brand
        }
    }

    private func logColor(for msg: String) -> Color {
        let lower = msg.lowercased()
        if lower.contains("error") || lower.contains("fail") || lower.contains("timeout") || lower.contains("rejected") {
            return KestrelPalette.crimson
        }
        if lower.contains("connected") || lower.contains("rekey") || lower.contains("hopped") {
            return KestrelPalette.emerald
        }
        return KestrelPalette.textPrimary
    }

    private func openInShadowrocket() {
        let deepLink = viewModel.buildShadowrocketURLString()
        guard let url = URL(string: deepLink) else {
            viewModel.showToast("生成 Shadowrocket 链接失败")
            return
        }
        UIApplication.shared.open(url) { success in
            if !success {
                UIPasteboard.general.string = deepLink
                viewModel.showToast("未检测到 Shadowrocket，已复制节点导入链接")
            } else {
                viewModel.showToast("已拉起 Shadowrocket 导入本地节点")
            }
        }
    }

    private func copyBypassRule() {
        let rule = viewModel.buildBypassRuleString()
        if rule.isEmpty {
            viewModel.showToast("请先导入并选择一个节点")
            return
        }
        UIPasteboard.general.string = rule
        viewModel.showToast("已复制：\(rule)")
    }
}

private extension View {
    func kestrelCard() -> some View {
        self
            .padding(14)
            .background(KestrelPalette.card)
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(KestrelPalette.border, lineWidth: 1))
            .cornerRadius(14)
            .shadow(color: Color.black.opacity(0.03), radius: 6, x: 0, y: 2)
    }
}
