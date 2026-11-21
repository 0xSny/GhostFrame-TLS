import SwiftUI
import UIKit

private enum GhostPalette {
    static let background = Color(red: 0.043, green: 0.063, blue: 0.125) // #0B1020
    static let card = Color(red: 0.075, green: 0.106, blue: 0.180)       // #131B2E
    static let cardAlt = Color(red: 0.098, green: 0.137, blue: 0.227)    // #19233A
    static let border = Color(red: 0.145, green: 0.200, blue: 0.306)     // #25334E
    static let cyan = Color(red: 0.024, green: 0.714, blue: 0.831)       // #06B6D4
    static let emerald = Color(red: 0.063, green: 0.725, blue: 0.506)    // #10B981
    static let amber = Color(red: 0.961, green: 0.620, blue: 0.043)      // #F59E0B
    static let crimson = Color(red: 0.937, green: 0.267, blue: 0.267)    // #EF4444
    static let textPrimary = Color(red: 0.945, green: 0.961, blue: 0.980)
    static let textMuted = Color(red: 0.580, green: 0.639, blue: 0.722)
}

private enum ActivePanelSheet: String, Identifiable {
    case nodes
    case settings
    case logs
    case diagnostic

    var id: String { rawValue }
}

struct ConsoleView: View {
    @ObservedObject var viewModel: GhostAppViewModel

    @State private var showDrawer = false
    @State private var activeSheet: ActivePanelSheet?
    @State private var showImportSheet = false
    @State private var showQRScanner = false
    @State private var importURIText = ""
    @State private var renamingNodeID: String?
    @State private var renameDraftText = ""

    var body: some View {
        ZStack(alignment: .leading) {
            GhostPalette.background.ignoresSafeArea()

            VStack(spacing: 0) {
                topBar
                    .padding(.horizontal, 14)
                    .padding(.top, 8)
                    .padding(.bottom, 10)

                ScrollView {
                    VStack(spacing: 12) {
                        connectionHeroCard
                        quickModeCard
                        quickNavRow
                    }
                    .padding(.horizontal, 14)
                    .padding(.top, 4)
                    .padding(.bottom, 20)
                }
                .clipped()
            }

            if !viewModel.toastMessage.isEmpty {
                VStack {
                    Spacer()
                    toastOverlay(viewModel.toastMessage)
                        .padding(.bottom, 22)
                }
                .frame(maxWidth: .infinity)
                .allowsHitTesting(false)
                .transition(.opacity)
            }

            if showDrawer {
                Color.black.opacity(0.58)
                    .ignoresSafeArea()
                    .onTapGesture {
                        withAnimation(.easeOut(duration: 0.22)) {
                            showDrawer = false
                        }
                    }

                drawerMenu
                    .transition(.move(edge: .leading))
            }
        }
        .preferredColorScheme(.dark)
        .sheet(item: $activeSheet) { sheet in
            switch sheet {
            case .nodes:
                nodesSheet
            case .settings:
                settingsSheet
            case .logs:
                logsAndWaveformSheet
            case .diagnostic:
                diagnosticSheet
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
        .sheet(item: $viewModel.tunnelErrorReport) { report in
            tunnelErrorSheet(report)
        }
    }

    private var topBar: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Button(action: {
                    withAnimation(.spring(response: 0.28, dampingFraction: 0.86)) {
                        showDrawer.toggle()
                    }
                }) {
                    Image(systemName: "line.3.horizontal")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(GhostPalette.textPrimary)
                        .frame(width: 34, height: 34)
                        .background(GhostPalette.cardAlt)
                        .overlay(RoundedRectangle(cornerRadius: 9).stroke(GhostPalette.border, lineWidth: 1))
                        .cornerRadius(9)
                }

                Circle()
                    .fill(statusColor)
                    .frame(width: 10, height: 10)

                Text("Kestrel")
                    .font(.system(size: 17, weight: .bold))
                    .foregroundColor(GhostPalette.textPrimary)
                    .lineLimit(1)

                Text(viewModel.edition == .vpn ? "Duo" : "Air")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .foregroundColor(GhostPalette.cyan)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(GhostPalette.cyan.opacity(0.15))
                    .cornerRadius(5)
                    .fixedSize()

                Spacer()

                Button(action: { showQRScanner = true }) {
                    Image(systemName: "qrcode.viewfinder")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundColor(GhostPalette.textPrimary)
                        .frame(width: 34, height: 34)
                        .background(GhostPalette.cardAlt)
                        .overlay(RoundedRectangle(cornerRadius: 9).stroke(GhostPalette.border, lineWidth: 1))
                        .cornerRadius(9)
                }

                Button(action: {
                    if let clip = UIPasteboard.general.string, clip.hasPrefix("ksl") || clip.hasPrefix("gft") {
                        importURIText = clip
                    }
                    showImportSheet = true
                }) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                        Text("导入")
                    }
                    .font(.system(size: 12, weight: .bold))
                    .foregroundColor(.black)
                    .padding(.horizontal, 11)
                    .frame(height: 34)
                    .background(GhostPalette.cyan)
                    .cornerRadius(9)
                    .fixedSize()
                }
            }

            HStack(spacing: 8) {
                Text("S5 :\(String(viewModel.effectiveSocksPort)) · HTTP :\(String(viewModel.effectiveHttpPort)) · \(viewModel.backendStateLabel)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(GhostPalette.textMuted)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)

                Spacer()

                if viewModel.isConnected || viewModel.isTransitioning || viewModel.status.state != "disconnected" {
                    Text("内核:\(viewModel.status.state)")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundColor(kernelStateColor)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(kernelStateColor.opacity(0.14))
                        .cornerRadius(5)
                        .fixedSize()
                }
            }
        }
        .padding(12)
        .background(GhostPalette.card)
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(GhostPalette.border, lineWidth: 1))
        .cornerRadius(14)
    }

    private var connectionHeroCard: some View {
        VStack(spacing: 12) {
            Button(action: { activeSheet = .nodes }) {
                HStack(spacing: 10) {
                    Image(systemName: "server.rack")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundColor(viewModel.activeNode == nil ? GhostPalette.amber : GhostPalette.cyan)

                    VStack(alignment: .leading, spacing: 2) {
                        Text(viewModel.activeNode?.remark ?? "尚未选择节点 (点击导入或选择)")
                            .font(.system(size: 14, weight: .bold))
                            .foregroundColor(GhostPalette.textPrimary)
                            .lineLimit(1)

                        if let node = viewModel.activeNode {
                            Text("\(node.host):\(String(node.port)) · \(node.transport.uppercased())")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(GhostPalette.textMuted)
                                .lineLimit(1)
                        }
                    }

                    Spacer()

                    Image(systemName: "chevron.right")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(GhostPalette.textMuted)
                }
                .padding(11)
                .background(GhostPalette.cardAlt)
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(GhostPalette.border, lineWidth: 1))
                .cornerRadius(10)
            }

            Button(action: { viewModel.toggleConnection() }) {
                HStack(spacing: 10) {
                    Image(systemName: viewModel.isConnected ? "stop.fill" : (viewModel.isTransitioning ? "arrow.triangle.2.circlepath" : "play.fill"))
                        .font(.system(size: 15, weight: .bold))
                    Text(primaryButtonTitle)
                        .font(.system(size: 15, weight: .bold))
                }
                .foregroundColor(viewModel.isConnected ? GhostPalette.textPrimary : Color.black)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(
                    viewModel.isConnected
                        ? GhostPalette.crimson.opacity(0.90)
                        : (viewModel.isTransitioning ? GhostPalette.amber : GhostPalette.emerald)
                )
                .cornerRadius(11)
            }

            LazyVGrid(columns: [
                GridItem(.flexible(), spacing: 8),
                GridItem(.flexible(), spacing: 8)
            ], spacing: 8) {
                metricBox(title: "延迟 · 协议", value: "\(rttText) · \(activeTransportText)", accent: GhostPalette.cyan)
                metricBox(title: "双通道端口 · H/R", value: "\(hopPortsText) · H\(viewModel.status.hopCount)", accent: GhostPalette.textPrimary)
                metricBox(title: "实时速率", value: "↑\(GhostByteFormatter.formatRate(viewModel.status.upBps)) ↓\(GhostByteFormatter.formatRate(viewModel.status.downBps))", accent: GhostPalette.emerald)
                metricBox(title: "网卡 · 内存", value: nicAndMemText, accent: GhostPalette.amber)
            }

            if !viewModel.errorBanner.isEmpty {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(GhostPalette.crimson)
                        .font(.system(size: 13))
                    Text(viewModel.errorBanner)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(GhostPalette.crimson)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(10)
                .background(GhostPalette.crimson.opacity(0.12))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(GhostPalette.crimson.opacity(0.4), lineWidth: 1))
                .cornerRadius(8)
            }
        }
        .padding(13)
        .background(GhostPalette.card)
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(GhostPalette.border, lineWidth: 1))
        .cornerRadius(14)
    }

    private var quickModeCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Picker("运行模式", selection: $viewModel.routeMode) {
                ForEach(GhostRouteMode.allCases) { mode in
                    Text(mode.label).tag(mode)
                }
            }
            .pickerStyle(.segmented)
            .onChange(of: viewModel.routeMode) { _ in
                viewModel.applySettings()
            }

            if viewModel.edition == .companion {
                HStack(spacing: 8) {
                    Button(action: openInShadowrocket) {
                        Text("🚀 导入 Shadowrocket")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.black)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 9)
                            .background(GhostPalette.cyan)
                            .cornerRadius(9)
                    }

                    Button(action: copyBypassRule) {
                        Text("📋 防回环规则")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundColor(GhostPalette.textPrimary)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 9)
                            .background(GhostPalette.cardAlt)
                            .overlay(RoundedRectangle(cornerRadius: 9).stroke(GhostPalette.border, lineWidth: 1))
                            .cornerRadius(9)
                    }
                }
            }
        }
        .padding(12)
        .background(GhostPalette.card)
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(GhostPalette.border, lineWidth: 1))
        .cornerRadius(14)
    }

    private var quickNavRow: some View {
        HStack(spacing: 10) {
            quickNavTile(
                icon: "list.bullet.rectangle",
                title: "节点",
                subtitle: "\(viewModel.nodes.count) 个",
                accent: GhostPalette.cyan
            ) {
                activeSheet = .nodes
            }

            quickNavTile(
                icon: "waveform.path.ecg",
                title: "波形与日志",
                subtitle: "\(viewModel.combinedLogs.count) 条",
                accent: GhostPalette.emerald
            ) {
                activeSheet = .logs
            }

            quickNavTile(
                icon: "slider.horizontal.3",
                title: "高级设置",
                subtitle: viewModel.transportMode.rawValue.uppercased(),
                accent: GhostPalette.amber
            ) {
                activeSheet = .settings
            }
        }
    }

    private func quickNavTile(
        icon: String,
        title: String,
        subtitle: String,
        accent: Color,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Image(systemName: icon)
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundColor(accent)
                    Spacer()
                }
                Text(title)
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(GhostPalette.textPrimary)
                    .lineLimit(1)
                Text(subtitle)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(GhostPalette.textMuted)
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(11)
            .background(GhostPalette.card)
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(GhostPalette.border, lineWidth: 1))
            .cornerRadius(12)
        }
    }

    private var drawerMenu: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 10, height: 10)
                    Text(viewModel.edition.title)
                        .font(.system(size: 17, weight: .bold))
                        .foregroundColor(GhostPalette.textPrimary)
                }
                Text("v4.0.0-LTS · \(viewModel.backendStateLabel)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(GhostPalette.cyan)
                Text("SOCKS5 :\(String(viewModel.effectiveSocksPort)) · HTTP :\(String(viewModel.effectiveHttpPort))")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(GhostPalette.textMuted)
            }
            .padding(.horizontal, 18)
            .padding(.top, 20)
            .padding(.bottom, 16)

            Divider().background(GhostPalette.border)

            ScrollView {
                VStack(spacing: 4) {
                    drawerItem(icon: "qrcode.viewfinder", title: "扫码导入节点") {
                        closeDrawerThen { showQRScanner = true }
                    }
                    drawerItem(icon: "link.badge.plus", title: "链接导入节点 (ksl4://)") {
                        closeDrawerThen {
                            if let clip = UIPasteboard.general.string, clip.hasPrefix("ksl") || clip.hasPrefix("gft") {
                                importURIText = clip
                            }
                            showImportSheet = true
                        }
                    }
                    drawerItem(icon: "server.rack", title: "节点管理 (\(viewModel.nodes.count))") {
                        closeDrawerThen { activeSheet = .nodes }
                    }
                    drawerItem(icon: "slider.horizontal.3", title: "传输内核与端口设置") {
                        closeDrawerThen { activeSheet = .settings }
                    }
                    drawerItem(icon: "waveform.path.ecg", title: "实时吞吐与内核日志") {
                        closeDrawerThen { activeSheet = .logs }
                    }
                    drawerItem(icon: "stethoscope", title: "脱敏诊断报告") {
                        closeDrawerThen {
                            viewModel.refreshDiagnostic()
                            activeSheet = .diagnostic
                        }
                    }
                }
                .padding(.vertical, 10)
                .padding(.horizontal, 10)
            }

            Divider().background(GhostPalette.border)

            VStack(alignment: .leading, spacing: 5) {
                if viewModel.edition == .vpn {
                    Text("重签自适应 · 零 App Group")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(GhostPalette.emerald)
                    Text("Main: \(Bundle.main.bundleIdentifier ?? "-")")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(GhostPalette.textMuted)
                        .lineLimit(1)
                    Text("Ext: \(viewModel.detectedExtensionBundleID)")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(GhostPalette.textMuted)
                        .lineLimit(1)
                } else {
                    Text(viewModel.keepAliveActive ? "16kHz 静音 PCM 后台保活中" : "单进程伴侣模式 (零扩展)")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(viewModel.keepAliveActive ? GhostPalette.emerald : GhostPalette.cyan)
                    Text("支持 Shadowrocket 本地 SOCKS5 串联")
                        .font(.system(size: 10))
                        .foregroundColor(GhostPalette.textMuted)
                }
            }
            .padding(16)
        }
        .frame(width: 280)
        .frame(maxHeight: .infinity)
        .background(GhostPalette.card)
        .overlay(Rectangle().frame(width: 1).foregroundColor(GhostPalette.border), alignment: .trailing)
    }

    private func drawerItem(icon: String, title: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundColor(GhostPalette.cyan)
                    .frame(width: 22)
                Text(title)
                    .font(.system(size: 14, weight: .medium))
                    .foregroundColor(GhostPalette.textPrimary)
                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 11)
            .background(Color.clear)
            .cornerRadius(9)
        }
    }

    private func closeDrawerThen(_ block: @escaping () -> Void) {
        withAnimation(.easeOut(duration: 0.18)) {
            showDrawer = false
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.20, execute: block)
    }

    private var nodesSheet: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 10) {
                    if viewModel.nodes.isEmpty {
                        Text("暂无节点，请使用顶部「扫码」或「导入」添加。")
                            .font(.system(size: 13))
                            .foregroundColor(GhostPalette.textMuted)
                            .padding(.top, 28)
                    } else {
                        ForEach(viewModel.nodes) { node in
                            let isSelected = (viewModel.activeNode?.id == node.id)
                            let isRenaming = (renamingNodeID == node.id)
                            VStack(spacing: 8) {
                                HStack(spacing: 10) {
                                    Button(action: {
                                        viewModel.selectNode(node)
                                        activeSheet = nil
                                    }) {
                                        HStack(spacing: 8) {
                                            Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                                                .foregroundColor(isSelected ? GhostPalette.emerald : GhostPalette.textMuted)
                                            VStack(alignment: .leading, spacing: 2) {
                                                Text(node.remark)
                                                    .font(.system(size: 14, weight: .semibold))
                                                    .foregroundColor(GhostPalette.textPrimary)
                                                Text("\(node.host):\(String(node.port)) · \(node.transport.uppercased())\(node.hopRange.isEmpty ? "" : " · Hop \(node.hopRange)")")
                                                    .font(.system(size: 11, design: .monospaced))
                                                    .foregroundColor(GhostPalette.textMuted)
                                            }
                                            Spacer()
                                        }
                                    }

                                    Button(action: {
                                        if isRenaming {
                                            renamingNodeID = nil
                                        } else {
                                            renamingNodeID = node.id
                                            renameDraftText = node.remark
                                        }
                                    }) {
                                        Image(systemName: "square.and.pencil")
                                            .font(.system(size: 13))
                                            .foregroundColor(GhostPalette.cyan.opacity(0.9))
                                            .padding(6)
                                    }

                                    Button(action: {
                                        if isRenaming { renamingNodeID = nil }
                                        viewModel.deleteNode(node)
                                    }) {
                                        Image(systemName: "trash")
                                            .font(.system(size: 13))
                                            .foregroundColor(GhostPalette.crimson.opacity(0.85))
                                            .padding(6)
                                    }
                                }

                                if isRenaming {
                                    HStack(spacing: 8) {
                                        TextField("输入新节点备注", text: $renameDraftText)
                                            .font(.system(size: 13))
                                            .foregroundColor(GhostPalette.textPrimary)
                                            .padding(.horizontal, 10)
                                            .padding(.vertical, 7)
                                            .background(GhostPalette.background)
                                            .cornerRadius(8)
                                        Button("保存") {
                                            viewModel.renameNode(node, remark: renameDraftText)
                                            renamingNodeID = nil
                                        }
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.black)
                                        .padding(.horizontal, 12)
                                        .padding(.vertical, 7)
                                        .background(GhostPalette.emerald)
                                        .cornerRadius(8)
                                    }
                                }
                            }
                            .padding(11)
                            .background(isSelected ? GhostPalette.emerald.opacity(0.10) : GhostPalette.card)
                            .overlay(RoundedRectangle(cornerRadius: 10).stroke(isSelected ? GhostPalette.emerald.opacity(0.6) : GhostPalette.border, lineWidth: 1))
                            .cornerRadius(10)
                        }
                    }
                }
                .padding(16)
            }
            .background(GhostPalette.background.ignoresSafeArea())
            .navigationTitle("节点列表 (\(viewModel.nodes.count))")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { activeSheet = nil }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("导入") {
                        activeSheet = nil
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) {
                            showImportSheet = true
                        }
                    }
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    private var settingsSheet: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("运行模式")
                            .font(.system(size: 12))
                            .foregroundColor(GhostPalette.textMuted)
                        Picker("运行模式", selection: $viewModel.routeMode) {
                            ForEach(GhostRouteMode.allCases) { mode in
                                Text(mode.label).tag(mode)
                            }
                        }
                        .pickerStyle(.segmented)
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        Text("传输内核")
                            .font(.system(size: 12))
                            .foregroundColor(GhostPalette.textMuted)
                        Picker("传输内核", selection: $viewModel.transportMode) {
                            ForEach(GhostTransportMode.allCases) { mode in
                                Text(mode.label).tag(mode)
                            }
                        }
                        .pickerStyle(.segmented)
                    }

                    HStack(spacing: 10) {
                        labeledNumberField(title: "上行 Mbps (0=自动)", text: $viewModel.upMbpsText)
                        labeledNumberField(title: "下行 Mbps (0=自动)", text: $viewModel.downMbpsText)
                    }

                    HStack(spacing: 10) {
                        labeledNumberField(title: "SOCKS5 端口", text: $viewModel.socksPortText)
                        labeledNumberField(title: "HTTP 端口", text: $viewModel.httpPortText)
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("离线紧凑规则库 (\(viewModel.ruleStats.rulesetVersion))")
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundColor(GhostPalette.textPrimary)
                                Text("已加载 \(viewModel.ruleStats.builtinDomains) 条域名 + \(viewModel.ruleStats.builtinCidrs) CN段 (0指针)")
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(GhostPalette.textMuted)
                            }
                            Spacer()
                            Button(action: { viewModel.updateRuleBundle() }) {
                                Text(viewModel.isUpdatingRules ? "更新中..." : "更新分流规则库")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(GhostPalette.cyan)
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 6)
                                    .background(GhostPalette.cardAlt)
                                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(GhostPalette.cyan.opacity(0.6), lineWidth: 1))
                                    .cornerRadius(8)
                            }
                            .disabled(viewModel.isUpdatingRules)
                        }
                    }
                    .padding(10)
                    .background(GhostPalette.card)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(GhostPalette.border, lineWidth: 1))
                    .cornerRadius(10)

                    VStack(alignment: .leading, spacing: 6) {
                        Text("自定义分流规则 (Clash/Surge 格式，一行一条)")
                            .font(.system(size: 12))
                            .foregroundColor(GhostPalette.textMuted)
                        TextEditor(text: $viewModel.customRulesText)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(GhostPalette.textPrimary)
                            .frame(height: 110)
                            .padding(8)
                            .background(GhostPalette.cardAlt)
                            .overlay(RoundedRectangle(cornerRadius: 8).stroke(GhostPalette.border, lineWidth: 1))
                            .cornerRadius(8)
                        Text("示例：DOMAIN-SUFFIX,xxxgame.com,DIRECT 或 DOMAIN-KEYWORD,ads,REJECT")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(GhostPalette.textMuted)
                    }

                    Button(action: {
                        viewModel.applySettings()
                        activeSheet = nil
                    }) {
                        Text("保存并应用参数")
                            .font(.system(size: 14, weight: .bold))
                            .foregroundColor(.black)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 12)
                            .background(GhostPalette.emerald)
                            .cornerRadius(10)
                    }
                }
                .padding(16)
            }
            .background(GhostPalette.background.ignoresSafeArea())
            .navigationTitle("传输与端口设置")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { activeSheet = nil }
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    private var logsAndWaveformSheet: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("60s 实时流量")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(GhostPalette.textPrimary)
                            Spacer()
                            Text("累计 ↑\(GhostByteFormatter.formatBytes(viewModel.status.totalUp)) · ↓\(GhostByteFormatter.formatBytes(viewModel.status.totalDown))")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(GhostPalette.cyan)
                        }
                        TrafficWaveformCanvas(points: viewModel.status.history)
                            .frame(height: 110)
                            .background(GhostPalette.card)
                            .overlay(RoundedRectangle(cornerRadius: 10).stroke(GhostPalette.border, lineWidth: 1))
                            .cornerRadius(10)
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("最近分流明细 (\(viewModel.status.recentRoutes.count))")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(GhostPalette.textPrimary)
                            Spacer()
                            Text("点击域名可一键改规则")
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(GhostPalette.textMuted)
                        }

                        VStack(alignment: .leading, spacing: 6) {
                            let routes = Array(viewModel.status.recentRoutes.prefix(25))
                            if routes.isEmpty {
                                Text("等待连接流量进入...")
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(GhostPalette.textMuted)
                            } else {
                                ForEach(routes) { item in
                                    HStack(spacing: 6) {
                                        Text(item.action)
                                            .font(.system(size: 9, weight: .bold, design: .monospaced))
                                            .foregroundColor(item.action == "DIRECT" ? GhostPalette.emerald : (item.action == "REJECT" ? GhostPalette.crimson : GhostPalette.cyan))
                                            .padding(.horizontal, 5)
                                            .padding(.vertical, 2)
                                            .background(GhostPalette.cardAlt)
                                            .cornerRadius(4)
                                        VStack(alignment: .leading, spacing: 1) {
                                            Text(item.target)
                                                .font(.system(size: 11, design: .monospaced))
                                                .foregroundColor(GhostPalette.textPrimary)
                                                .lineLimit(1)
                                            Text("\(item.time) · \(item.reason)")
                                                .font(.system(size: 9, design: .monospaced))
                                                .foregroundColor(GhostPalette.textMuted)
                                                .lineLimit(1)
                                        }
                                        Spacer()
                                        if !item.host.isEmpty {
                                            let nextAction = item.action == "DIRECT" ? "PROXY" : "DIRECT"
                                            Button(item.action == "DIRECT" ? "改代理" : "改直连") {
                                                viewModel.quickAddCustomRule(host: item.host, action: nextAction)
                                            }
                                            .font(.system(size: 10, weight: .semibold))
                                            .foregroundColor(GhostPalette.textPrimary)
                                            .padding(.horizontal, 7)
                                            .padding(.vertical, 4)
                                            .background(GhostPalette.cardAlt)
                                            .overlay(RoundedRectangle(cornerRadius: 6).stroke(GhostPalette.border, lineWidth: 1))
                                            .cornerRadius(6)
                                        }
                                    }
                                }
                            }
                        }
                        .padding(10)
                        .background(GhostPalette.card)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(GhostPalette.border, lineWidth: 1))
                        .cornerRadius(10)
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("运行日志 (\(viewModel.combinedLogs.count))")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(GhostPalette.textPrimary)
                            Spacer()
                            Button("复制全部") {
                                let text = viewModel.combinedLogs.map { "\($0.time) \($0.message)" }.joined(separator: "\n")
                                UIPasteboard.general.string = text
                                viewModel.showToast("已复制运行日志")
                            }
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundColor(GhostPalette.cyan)

                            Button("清空") { viewModel.clearLogs() }
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(GhostPalette.textMuted)
                                .padding(.leading, 8)
                        }

                        VStack(alignment: .leading, spacing: 5) {
                            let entries = Array(viewModel.combinedLogs.suffix(60).reversed())
                            if entries.isEmpty {
                                Text("等待引擎事件...")
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(GhostPalette.textMuted)
                            } else {
                                ForEach(entries) { item in
                                    HStack(alignment: .top, spacing: 6) {
                                        Text(item.time)
                                            .font(.system(size: 10, design: .monospaced))
                                            .foregroundColor(GhostPalette.textMuted)
                                        Text(item.message)
                                            .font(.system(size: 11, design: .monospaced))
                                            .foregroundColor(logColor(for: item.message))
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                    }
                                }
                            }
                        }
                        .padding(10)
                        .background(GhostPalette.card)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(GhostPalette.border, lineWidth: 1))
                        .cornerRadius(10)
                    }
                }
                .padding(16)
            }
            .background(GhostPalette.background.ignoresSafeArea())
            .navigationTitle("实时波形与日志")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { activeSheet = nil }
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    private func metricBox(title: String, value: String, accent: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.system(size: 10))
                .foregroundColor(GhostPalette.textMuted)
            Text(value)
                .font(.system(size: 12, weight: .bold, design: .monospaced))
                .foregroundColor(accent)
                .lineLimit(1)
                .minimumScaleFactor(0.72)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(9)
        .background(GhostPalette.cardAlt)
        .overlay(RoundedRectangle(cornerRadius: 9).stroke(GhostPalette.border, lineWidth: 1))
        .cornerRadius(9)
    }

    private func labeledNumberField(title: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.system(size: 11))
                .foregroundColor(GhostPalette.textMuted)
            TextField("", text: text)
                .keyboardType(.numberPad)
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(GhostPalette.textPrimary)
                .padding(.horizontal, 10)
                .padding(.vertical, 8)
                .background(GhostPalette.card)
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(GhostPalette.border, lineWidth: 1))
                .cornerRadius(8)
        }
    }

    private func toastOverlay(_ message: String) -> some View {
        Text(message)
            .font(.system(size: 12, weight: .semibold))
            .foregroundColor(GhostPalette.textPrimary)
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .background(GhostPalette.cardAlt.opacity(0.96))
            .overlay(RoundedRectangle(cornerRadius: 20).stroke(GhostPalette.cyan, lineWidth: 1))
            .cornerRadius(20)
            .shadow(radius: 10)
    }

    private var importNodeSheet: some View {
        NavigationView {
            VStack(alignment: .leading, spacing: 14) {
                Text("粘贴 Kestrel 分享链接 (ksl4:// 或 gft3://)")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(GhostPalette.textPrimary)

                TextEditor(text: $importURIText)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(GhostPalette.textPrimary)
                    .frame(height: 150)
                    .padding(8)
                    .background(GhostPalette.cardAlt)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(GhostPalette.border, lineWidth: 1))
                    .cornerRadius(10)

                HStack(spacing: 10) {
                    Button(action: {
                        showImportSheet = false
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) {
                            showQRScanner = true
                        }
                    }) {
                        HStack(spacing: 5) {
                            Image(systemName: "qrcode.viewfinder")
                            Text("扫描二维码")
                        }
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(GhostPalette.textPrimary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 11)
                        .background(GhostPalette.cardAlt)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(GhostPalette.border, lineWidth: 1))
                        .cornerRadius(10)
                    }

                    Button("从剪贴板粘贴") {
                        if let clip = UIPasteboard.general.string {
                            importURIText = clip
                        }
                    }
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(GhostPalette.cyan)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 11)
                    .background(GhostPalette.cardAlt)
                    .cornerRadius(10)
                }

                Button("解析并保存") {
                    if viewModel.importLink(importURIText) {
                        importURIText = ""
                        showImportSheet = false
                    }
                }
                .font(.system(size: 14, weight: .bold))
                .foregroundColor(.black)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .background(GhostPalette.emerald)
                .cornerRadius(10)

                Spacer()
            }
            .padding(16)
            .background(GhostPalette.background.ignoresSafeArea())
            .navigationTitle("导入节点")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { showImportSheet = false }
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    private var diagnosticSheet: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(viewModel.diagnosticText.isEmpty ? "正在采集诊断信息..." : viewModel.diagnosticText)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(GhostPalette.textPrimary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .background(GhostPalette.card)
                        .cornerRadius(10)

                    Button("复制诊断报告") {
                        UIPasteboard.general.string = viewModel.diagnosticText
                        viewModel.showToast("已复制诊断报告")
                    }
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(.black)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 11)
                    .background(GhostPalette.cyan)
                    .cornerRadius(10)
                }
                .padding(16)
            }
            .background(GhostPalette.background.ignoresSafeArea())
            .navigationTitle("脱敏诊断报告")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { activeSheet = nil }
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    private func tunnelErrorSheet(_ report: GhostTunnelErrorReport) -> some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(report.title)
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(GhostPalette.crimson)

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Domain: \(report.domain)")
                        Text("Code: \(report.code)")
                        Text("Main Bundle: \(report.mainBundleID)")
                        Text("Extension Bundle: \(report.extensionBundleID)")
                        Text("Message: \(report.message)")
                    }
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(GhostPalette.textPrimary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                    .background(GhostPalette.card)
                    .cornerRadius(10)

                    Text(report.hint)
                        .font(.system(size: 12))
                        .foregroundColor(GhostPalette.amber)
                        .padding(12)
                        .background(GhostPalette.amber.opacity(0.12))
                        .cornerRadius(10)

                    Button("复制完整错误详情") {
                        UIPasteboard.general.string = "\(report.title)\nDomain: \(report.domain)\nCode: \(report.code)\nMain: \(report.mainBundleID)\nExt: \(report.extensionBundleID)\nMessage: \(report.message)\nHint: \(report.hint)"
                        viewModel.showToast("已复制系统错误报告")
                    }
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(.black)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 11)
                    .background(GhostPalette.cyan)
                    .cornerRadius(10)
                }
                .padding(16)
            }
            .background(GhostPalette.background.ignoresSafeArea())
            .navigationTitle("NetworkExtension 错误详情")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { viewModel.tunnelErrorReport = nil }
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    private var statusColor: Color {
        if viewModel.isConnected { return GhostPalette.emerald }
        if viewModel.isTransitioning { return GhostPalette.amber }
        if !viewModel.errorBanner.isEmpty { return GhostPalette.crimson }
        return GhostPalette.textMuted
    }

    private var kernelStateColor: Color {
        switch viewModel.status.state {
        case "connected": return GhostPalette.emerald
        case "connecting": return GhostPalette.amber
        case "error": return GhostPalette.crimson
        default: return GhostPalette.textMuted
        }
    }

    private var primaryButtonTitle: String {
        if viewModel.isConnected {
            return "断开安全隧道"
        }
        if viewModel.isTransitioning {
            return "正在建立通道... (点击取消)"
        }
        return "连接 Kestrel (v4.0 LTS)"
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

    private var nicAndMemText: String {
        let nic = viewModel.status.physicalIface.isEmpty ? "-" : viewModel.status.physicalIface
        let mem = String(format: "%.1fM", viewModel.status.memAllocMB)
        return "\(nic) · \(mem)"
    }

    private func logColor(for msg: String) -> Color {
        let lower = msg.lowercased()
        if lower.contains("error") || lower.contains("fail") || lower.contains("timeout") || lower.contains("rejected") {
            return GhostPalette.crimson
        }
        if lower.contains("connected") || lower.contains("rekey") || lower.contains("hopped") {
            return GhostPalette.emerald
        }
        return GhostPalette.textPrimary
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

private struct TrafficWaveformCanvas: View {
    let points: [GhostTrafficPoint]

    var body: some View {
        Canvas { context, size in
            let w = size.width
            let h = size.height
            guard w > 10, h > 10 else { return }

            for i in 1...3 {
                let y = h * CGFloat(i) / 4.0
                var grid = Path()
                grid.move(to: CGPoint(x: 0, y: y))
                grid.addLine(to: CGPoint(x: w, y: y))
                context.stroke(grid, with: .color(Color.white.opacity(0.06)), lineWidth: 1)
            }

            guard points.count >= 2 else { return }
            let maxRate = max(Double(64 * 1024), points.map { Double(max($0.up, $0.down)) }.max() ?? 1.0)
            let count = points.count

            var upPath = Path()
            var downPath = Path()
            for (idx, pt) in points.enumerated() {
                let x = w * CGFloat(idx) / CGFloat(max(1, count - 1))
                let yUp = h - CGFloat(Double(pt.up) / maxRate) * (h - 8) - 4
                let yDown = h - CGFloat(Double(pt.down) / maxRate) * (h - 8) - 4
                if idx == 0 {
                    upPath.move(to: CGPoint(x: x, y: yUp))
                    downPath.move(to: CGPoint(x: x, y: yDown))
                } else {
                    upPath.addLine(to: CGPoint(x: x, y: yUp))
                    downPath.addLine(to: CGPoint(x: x, y: yDown))
                }
            }

            context.stroke(downPath, with: .color(GhostPalette.emerald), lineWidth: 2)
            context.stroke(upPath, with: .color(GhostPalette.cyan), lineWidth: 2)
        }
    }
}
