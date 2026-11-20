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

struct ConsoleView: View {
    @ObservedObject var viewModel: GhostAppViewModel

    @State private var showImportSheet = false
    @State private var showQRScanner = false
    @State private var importURIText = ""
    @State private var showDiagnosticSheet = false

    var body: some View {
        ZStack(alignment: .bottom) {
            GhostPalette.background.ignoresSafeArea()

            VStack(spacing: 0) {
                headerCard
                    .padding(.horizontal, 14)
                    .padding(.top, 8)
                    .padding(.bottom, 10)
                    .background(GhostPalette.background)

                ScrollView {
                    VStack(spacing: 14) {
                        connectionHeroCard
                        editionSpecificCard
                        waveformCard
                        nodesCard
                        controlsCard
                        logsCard
                    }
                    .padding(.horizontal, 14)
                    .padding(.top, 4)
                    .padding(.bottom, 16)
                }
                .clipped()
            }

            if !viewModel.toastMessage.isEmpty {
                toastOverlay(viewModel.toastMessage)
                    .padding(.bottom, 18)
                    .transition(.opacity)
            }
        }
        .preferredColorScheme(.dark)
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

    private var headerCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Circle()
                    .fill(statusColor)
                    .frame(width: 11, height: 11)

                Text(viewModel.edition.title)
                    .font(.system(size: 17, weight: .bold))
                    .foregroundColor(GhostPalette.textPrimary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)

                Text("v4.0-LTS")
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    .foregroundColor(GhostPalette.cyan)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(GhostPalette.cyan.opacity(0.15))
                    .cornerRadius(6)

                Spacer()

                Button(action: { showQRScanner = true }) {
                    HStack(spacing: 4) {
                        Image(systemName: "qrcode.viewfinder")
                        Text("扫码")
                    }
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(GhostPalette.textPrimary)
                    .padding(.horizontal, 9)
                    .padding(.vertical, 6)
                    .background(GhostPalette.cardAlt)
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(GhostPalette.border, lineWidth: 1))
                    .cornerRadius(8)
                }

                Button(action: {
                    viewModel.refreshDiagnostic()
                    showDiagnosticSheet = true
                }) {
                    Text("诊断")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(GhostPalette.textPrimary)
                        .padding(.horizontal, 9)
                        .padding(.vertical, 6)
                        .background(GhostPalette.cardAlt)
                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(GhostPalette.border, lineWidth: 1))
                        .cornerRadius(8)
                }

                Button(action: {
                    if let clip = UIPasteboard.general.string, clip.hasPrefix("gft") {
                        importURIText = clip
                    }
                    showImportSheet = true
                }) {
                    Text("导入")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.black)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(GhostPalette.cyan)
                        .cornerRadius(8)
                }
            }

            HStack(spacing: 8) {
                Text("S5 :\(viewModel.effectiveSocksPort) · HTTP :\(viewModel.effectiveHttpPort) · \(viewModel.backendStateLabel)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(GhostPalette.textMuted)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)

                Spacer()

                if viewModel.isConnected || viewModel.isTransitioning {
                    Text("内核:\(viewModel.status.state)")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundColor(viewModel.status.state == "connected" ? GhostPalette.emerald : GhostPalette.amber)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background((viewModel.status.state == "connected" ? GhostPalette.emerald : GhostPalette.amber).opacity(0.14))
                        .cornerRadius(5)
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
            Button(action: { viewModel.toggleConnection() }) {
                HStack(spacing: 10) {
                    Image(systemName: viewModel.isConnected ? "stop.fill" : (viewModel.isTransitioning ? "arrow.triangle.2.circlepath" : "play.fill"))
                        .font(.system(size: 16, weight: .bold))
                    Text(primaryButtonTitle)
                        .font(.system(size: 16, weight: .bold))
                }
                .foregroundColor(viewModel.isConnected ? GhostPalette.textPrimary : Color.black)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 15)
                .background(
                    viewModel.isConnected
                        ? GhostPalette.crimson.opacity(0.88)
                        : (viewModel.isTransitioning ? GhostPalette.amber : GhostPalette.emerald)
                )
                .cornerRadius(12)
            }

            LazyVGrid(columns: [
                GridItem(.flexible(), spacing: 8),
                GridItem(.flexible(), spacing: 8),
                GridItem(.flexible(), spacing: 8)
            ], spacing: 8) {
                metricBox(title: "通道延迟", value: rttText, accent: GhostPalette.cyan)
                metricBox(title: "传输引擎", value: activeTransportText, accent: GhostPalette.emerald)
                metricBox(title: "双通道端口", value: hopPortsText, accent: GhostPalette.textPrimary)
                metricBox(title: "跳跃/轮换", value: "H\(viewModel.status.hopCount) · R\(viewModel.status.rekeyCount)", accent: GhostPalette.cyan)
                metricBox(title: "FEC 恢复", value: "\(viewModel.status.fecRecovered) pkt", accent: GhostPalette.emerald)
                metricBox(title: "网卡 / 内存", value: nicAndMemText, accent: GhostPalette.amber)
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
        .padding(14)
        .background(GhostPalette.card)
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(GhostPalette.border, lineWidth: 1))
        .cornerRadius(14)
    }

    @ViewBuilder
    private var editionSpecificCard: some View {
        switch viewModel.edition {
        case .vpn:
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Label("重签自适应系统级 VPN", systemImage: "checkmark.shield.fill")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(GhostPalette.emerald)
                    Spacer()
                    Text("零 App Group")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundColor(GhostPalette.cyan)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(GhostPalette.cyan.opacity(0.14))
                        .cornerRadius(5)
                }
                Text("Main Bundle: \(Bundle.main.bundleIdentifier ?? "-")")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(GhostPalette.textMuted)
                Text("Ext Bundle: \(viewModel.detectedExtensionBundleID.isEmpty ? "自动扫描中..." : viewModel.detectedExtensionBundleID)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(GhostPalette.textPrimary)
                Text("配置通过 NETunnelProviderProtocol.providerConfiguration 下发，状态通过 sendProviderMessage IPC 同步；全能签改包名 100% 互通。")
                    .font(.system(size: 11))
                    .foregroundColor(GhostPalette.textMuted)
            }
            .padding(14)
            .background(GhostPalette.card)
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(GhostPalette.border, lineWidth: 1))
            .cornerRadius(14)

        case .companion:
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Label("单进程伴侣模式 (Shadowrocket 串联)", systemImage: "link.circle.fill")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(GhostPalette.cyan)
                    Spacer()
                    Text(viewModel.keepAliveActive ? "静音保活中" : "保活待机")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundColor(viewModel.keepAliveActive ? GhostPalette.emerald : GhostPalette.textMuted)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background((viewModel.keepAliveActive ? GhostPalette.emerald : GhostPalette.textMuted).opacity(0.16))
                        .cornerRadius(6)
                }

                Text("16kHz 静音 PCM 混音保活 (.playback + .mixWithOthers)，切后台不杀进程、不打断音乐。")
                    .font(.system(size: 11))
                    .foregroundColor(GhostPalette.textMuted)

                Button(action: openInShadowrocket) {
                    Text("🚀 一键导入本地节点到 Shadowrocket")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(.black)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                        .background(GhostPalette.cyan)
                        .cornerRadius(10)
                }

                Button(action: copyBypassRule) {
                    Text("📋 复制 VPS 防回环直连规则")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(GhostPalette.textPrimary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(GhostPalette.cardAlt)
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(GhostPalette.border, lineWidth: 1))
                        .cornerRadius(10)
                }
            }
            .padding(14)
            .background(GhostPalette.card)
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(GhostPalette.border, lineWidth: 1))
            .cornerRadius(14)
        }
    }

    private var waveformCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("实时吞吐 (60s)")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(GhostPalette.textPrimary)
                Spacer()
                Text("↑ \(GhostByteFormatter.formatRate(viewModel.status.upBps)) (\(GhostByteFormatter.formatBytes(viewModel.status.totalUp)))")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(GhostPalette.cyan)
            }
            HStack {
                Spacer()
                Text("↓ \(GhostByteFormatter.formatRate(viewModel.status.downBps)) (\(GhostByteFormatter.formatBytes(viewModel.status.totalDown)))")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(GhostPalette.emerald)
            }

            TrafficWaveformCanvas(points: viewModel.status.history)
                .frame(height: 92)
                .background(GhostPalette.background.opacity(0.6))
                .cornerRadius(10)
        }
        .padding(14)
        .background(GhostPalette.card)
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(GhostPalette.border, lineWidth: 1))
        .cornerRadius(14)
    }

    private var nodesCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("节点列表 (\(viewModel.nodes.count))")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(GhostPalette.textPrimary)
                Spacer()
                Button("添加节点") { showImportSheet = true }
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(GhostPalette.cyan)
            }

            if viewModel.nodes.isEmpty {
                Text("暂无节点，点击右上角「导入 gft3://」或粘贴分享链接。")
                    .font(.system(size: 12))
                    .foregroundColor(GhostPalette.textMuted)
                    .padding(.vertical, 8)
            } else {
                ForEach(viewModel.nodes) { node in
                    let isSelected = (viewModel.activeNode?.id == node.id)
                    HStack(spacing: 10) {
                        Button(action: { viewModel.selectNode(node) }) {
                            HStack(spacing: 8) {
                                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                                    .foregroundColor(isSelected ? GhostPalette.emerald : GhostPalette.textMuted)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(node.remark)
                                        .font(.system(size: 13, weight: .semibold))
                                        .foregroundColor(GhostPalette.textPrimary)
                                    Text("\(node.host):\(node.port) · \(node.transport.uppercased())\(node.hopRange.isEmpty ? "" : " · Hop \(node.hopRange)")")
                                        .font(.system(size: 11, design: .monospaced))
                                        .foregroundColor(GhostPalette.textMuted)
                                }
                                Spacer()
                            }
                        }

                        Button(action: { viewModel.deleteNode(node) }) {
                            Image(systemName: "trash")
                                .font(.system(size: 13))
                                .foregroundColor(GhostPalette.crimson.opacity(0.85))
                                .padding(6)
                        }
                    }
                    .padding(10)
                    .background(isSelected ? GhostPalette.emerald.opacity(0.10) : GhostPalette.cardAlt)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(isSelected ? GhostPalette.emerald.opacity(0.6) : GhostPalette.border, lineWidth: 1))
                    .cornerRadius(10)
                }
            }
        }
        .padding(14)
        .background(GhostPalette.card)
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(GhostPalette.border, lineWidth: 1))
        .cornerRadius(14)
    }

    private var controlsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("传输、路由与带宽调优")
                .font(.system(size: 13, weight: .bold))
                .foregroundColor(GhostPalette.textPrimary)

            VStack(alignment: .leading, spacing: 6) {
                Text("运行模式")
                    .font(.system(size: 11))
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
                    .font(.system(size: 11))
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

            Button(action: { viewModel.applySettings() }) {
                Text("保存并应用参数")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(GhostPalette.textPrimary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(GhostPalette.cardAlt)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(GhostPalette.cyan.opacity(0.65), lineWidth: 1))
                    .cornerRadius(10)
            }
        }
        .padding(14)
        .background(GhostPalette.card)
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(GhostPalette.border, lineWidth: 1))
        .cornerRadius(14)
    }

    private var logsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("内核运行日志 (\(viewModel.combinedLogs.count))")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(GhostPalette.textPrimary)
                Spacer()
                Button("清空日志") { viewModel.clearLogs() }
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(GhostPalette.textMuted)
            }

            VStack(alignment: .leading, spacing: 4) {
                let entries = Array(viewModel.combinedLogs.suffix(30).reversed())
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
            .background(GhostPalette.background)
            .cornerRadius(10)
        }
        .padding(14)
        .background(GhostPalette.card)
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(GhostPalette.border, lineWidth: 1))
        .cornerRadius(14)
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
                .minimumScaleFactor(0.75)
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
                .background(GhostPalette.background)
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
                Text("粘贴 GhostFrame 分享链接 (gft3:// 或 gft2://)")
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
                    Button("关闭") { showDiagnosticSheet = false }
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

    private var primaryButtonTitle: String {
        if viewModel.isConnected {
            return "断开 GhostFrame 安全隧道"
        }
        if viewModel.isTransitioning {
            return "正在建立加密通道... (点击取消)"
        }
        return "连接 GhostFrame (v4.0 LTS)"
    }

    private var rttText: String {
        let ms = viewModel.status.srttMs > 0 ? viewModel.status.srttMs : viewModel.status.pingMs
        return ms > 0 ? "\(ms) ms" : "-- ms"
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
            return ":\(viewModel.status.rtcPort)"
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
        if lower.contains("error") || lower.contains("fail") || lower.contains("timeout") {
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
