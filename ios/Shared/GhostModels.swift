import Foundation
import Network

enum GhostEdition: String {
    case vpn
    case companion

    var title: String {
        switch self {
        case .vpn:
            return "Kestrel Duo"
        case .companion:
            return "Kestrel Air"
        }
    }

    var subtitle: String {
        switch self {
        case .vpn:
            return "系统级 NEPacketTunnel · 重签自适应 (零 App Group)"
        case .companion:
            return "单进程静音保活伴侣 · Shadowrocket 串联"
        }
    }
}

enum GhostRouteMode: String, CaseIterable, Codable, Identifiable {
    case rule = "rule"
    case global = "global"
    case core = "core"

    var id: String { rawValue }

    var label: String {
        switch self {
        case .rule: return "Rule 智能"
        case .global: return "Global 全局"
        case .core: return "Core 仅端口"
        }
    }
}

enum GhostTransportMode: String, CaseIterable, Codable, Identifiable {
    case auto = "auto"
    case rtc = "rtc"
    case tcp = "tcp"

    var id: String { rawValue }

    var label: String {
        switch self {
        case .auto: return "Auto 双栈"
        case .rtc: return "RTC 极速"
        case .tcp: return "TCP uTLS"
        }
    }
}

struct GhostNode: Identifiable, Codable, Equatable {
    var id: String
    var remark: String
    var host: String
    var port: Int
    var sni: String
    var verify: String
    var transport: String
    var hopRange: String
    var upMbps: Int
    var downMbps: Int
    var uri: String

    enum CodingKeys: String, CodingKey {
        case id
        case remark
        case host
        case port
        case sni
        case verify
        case transport
        case hopRange = "hop_range"
        case upMbps = "up_mbps"
        case downMbps = "down_mbps"
        case uri
    }

    init(
        id: String = UUID().uuidString,
        remark: String,
        host: String,
        port: Int,
        sni: String,
        verify: String,
        transport: String,
        hopRange: String,
        upMbps: Int,
        downMbps: Int,
        uri: String
    ) {
        self.id = id
        self.remark = remark
        self.host = host
        self.port = port
        self.sni = sni
        self.verify = verify
        self.transport = transport
        self.hopRange = hopRange
        self.upMbps = upMbps
        self.downMbps = downMbps
        self.uri = uri
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = (try? c.decode(String.self, forKey: .id)) ?? UUID().uuidString
        self.host = (try? c.decode(String.self, forKey: .host)) ?? ""
        self.port = (try? c.decode(Int.self, forKey: .port)) ?? 443
        let rawRemark = (try? c.decode(String.self, forKey: .remark)) ?? ""
        self.remark = rawRemark.isEmpty ? "\(host):\(port)" : rawRemark
        self.sni = (try? c.decode(String.self, forKey: .sni)) ?? ""
        self.verify = (try? c.decode(String.self, forKey: .verify)) ?? "ca"
        self.transport = (try? c.decode(String.self, forKey: .transport)) ?? "auto"
        self.hopRange = (try? c.decode(String.self, forKey: .hopRange)) ?? ""
        self.upMbps = (try? c.decode(Int.self, forKey: .upMbps)) ?? 0
        self.downMbps = (try? c.decode(Int.self, forKey: .downMbps)) ?? 0
        self.uri = (try? c.decode(String.self, forKey: .uri)) ?? ""
    }
}

struct GhostEngineConfig: Codable, Equatable {
    var linkURI: String
    var socksPort: Int
    var httpPort: Int
    var routeMode: String
    var transport: String
    var upMbps: Int
    var downMbps: Int
    var asyncConnect: Bool = true
    var customRules: [String] = []

    enum CodingKeys: String, CodingKey {
        case linkURI = "link_uri"
        case socksPort = "socks_port"
        case httpPort = "http_port"
        case routeMode = "route_mode"
        case transport
        case upMbps = "up_mbps"
        case downMbps = "down_mbps"
        case asyncConnect = "async_connect"
        case customRules = "custom_rules"
    }

    init(
        linkURI: String,
        socksPort: Int,
        httpPort: Int,
        routeMode: String,
        transport: String,
        upMbps: Int,
        downMbps: Int,
        asyncConnect: Bool = true,
        customRules: [String] = []
    ) {
        self.linkURI = linkURI
        self.socksPort = socksPort
        self.httpPort = httpPort
        self.routeMode = routeMode
        self.transport = transport
        self.upMbps = upMbps
        self.downMbps = downMbps
        self.asyncConnect = asyncConnect
        self.customRules = customRules
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        linkURI = (try? c.decode(String.self, forKey: .linkURI)) ?? ""
        socksPort = (try? c.decode(Int.self, forKey: .socksPort)) ?? 10808
        httpPort = (try? c.decode(Int.self, forKey: .httpPort)) ?? 10809
        routeMode = (try? c.decode(String.self, forKey: .routeMode)) ?? "rule"
        transport = (try? c.decode(String.self, forKey: .transport)) ?? "auto"
        upMbps = (try? c.decode(Int.self, forKey: .upMbps)) ?? 0
        downMbps = (try? c.decode(Int.self, forKey: .downMbps)) ?? 0
        asyncConnect = (try? c.decode(Bool.self, forKey: .asyncConnect)) ?? true
        customRules = (try? c.decode([String].self, forKey: .customRules)) ?? []
    }

    func toJSONString() -> String {
        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(self),
              let str = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return str
    }

    static func decode(from jsonString: String) -> GhostEngineConfig? {
        guard let data = jsonString.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(GhostEngineConfig.self, from: data)
    }
}

struct GhostLogEntry: Codable, Identifiable, Equatable {
    var id: String { "\(time)-\(message)" }
    var time: String
    var message: String
}

struct GhostTrafficPoint: Codable, Identifiable, Equatable {
    var id: Int64 { t }
    var t: Int64
    var up: UInt64
    var down: UInt64
}

struct GhostRecentRoute: Codable, Identifiable, Equatable {
    var id: String { "\(time)-\(target)-\(action)-\(reason)" }
    var time: String
    var target: String
    var host: String
    var action: String
    var reason: String
}

struct GhostStatusSnapshot: Codable, Equatable {
    var version: String
    var state: String
    var lastErr: String
    var activeTransport: String
    var transportPref: String
    var routeMode: String
    var hopRange: String
    var rtcPort: Int
    var rtcPorts: [Int]
    var hopCount: UInt64
    var hopState: String
    var rekeyCount: UInt64
    var srttMs: Int64
    var minRttMs: Int64
    var fecRecovered: UInt64
    var lossPct: Double
    var pacingMbps: Double
    var upMbps: Int
    var downMbps: Int
    var activeConns: Int
    var activeStreams: Int
    var pingMs: Int64
    var upBps: UInt64
    var downBps: UInt64
    var totalUp: UInt64
    var totalDown: UInt64
    var history: [GhostTrafficPoint]
    var socksAddr: String
    var httpAddr: String
    var nodeName: String
    var nodeHost: String
    var nodePort: Int
    var isTunnelExt: Bool
    var lowMemMode: Bool
    var netbindEnabled: Bool
    var physicalIface: String
    var memAllocMB: Double
    var memSysMB: Double
    var logs: [GhostLogEntry]
    var customRules: [String]
    var recentRoutes: [GhostRecentRoute]

    static let empty = GhostStatusSnapshot()

    init() {
        version = "v4.0.29-LTS"
        state = "disconnected"
        lastErr = ""
        activeTransport = ""
        transportPref = "auto"
        routeMode = "rule"
        hopRange = ""
        rtcPort = 0
        rtcPorts = []
        hopCount = 0
        hopState = ""
        rekeyCount = 0
        srttMs = 0
        minRttMs = 0
        fecRecovered = 0
        lossPct = 0
        pacingMbps = 0
        upMbps = 0
        downMbps = 0
        activeConns = 0
        activeStreams = 0
        pingMs = 0
        upBps = 0
        downBps = 0
        totalUp = 0
        totalDown = 0
        history = []
        socksAddr = "127.0.0.1:10808"
        httpAddr = "127.0.0.1:10809"
        nodeName = ""
        nodeHost = ""
        nodePort = 0
        isTunnelExt = false
        lowMemMode = false
        netbindEnabled = false
        physicalIface = ""
        memAllocMB = 0
        memSysMB = 0
        logs = []
        customRules = []
        recentRoutes = []
    }

    enum CodingKeys: String, CodingKey {
        case version
        case state
        case lastErr = "last_err"
        case activeTransport = "active_transport"
        case transportPref = "transport_pref"
        case routeMode = "route_mode"
        case hopRange = "hop_range"
        case rtcPort = "rtc_port"
        case rtcPorts = "rtc_ports"
        case hopCount = "hop_count"
        case hopState = "hop_state"
        case rekeyCount = "rekey_count"
        case srttMs = "srtt_ms"
        case minRttMs = "min_rtt_ms"
        case fecRecovered = "fec_recovered"
        case lossPct = "loss_pct"
        case pacingMbps = "pacing_mbps"
        case upMbps = "up_mbps"
        case downMbps = "down_mbps"
        case activeConns = "active_conns"
        case activeStreams = "active_streams"
        case pingMs = "ping_ms"
        case upBps = "up_bps"
        case downBps = "down_bps"
        case totalUp = "total_up"
        case totalDown = "total_down"
        case history
        case socksAddr = "socks_addr"
        case httpAddr = "http_addr"
        case nodeName = "node_name"
        case nodeHost = "node_host"
        case nodePort = "node_port"
        case isTunnelExt = "is_tunnel_ext"
        case lowMemMode = "low_mem_mode"
        case netbindEnabled = "netbind_enabled"
        case physicalIface = "physical_iface"
        case memAllocMB = "mem_alloc_mb"
        case memSysMB = "mem_sys_mb"
        case logs
        case customRules = "custom_rules"
        case recentRoutes = "recent_routes"
    }

    init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = (try? c.decode(String.self, forKey: .version)) ?? version
        state = (try? c.decode(String.self, forKey: .state)) ?? state
        lastErr = (try? c.decode(String.self, forKey: .lastErr)) ?? ""
        activeTransport = (try? c.decode(String.self, forKey: .activeTransport)) ?? ""
        transportPref = (try? c.decode(String.self, forKey: .transportPref)) ?? "auto"
        routeMode = (try? c.decode(String.self, forKey: .routeMode)) ?? "rule"
        hopRange = (try? c.decode(String.self, forKey: .hopRange)) ?? ""
        rtcPort = (try? c.decode(Int.self, forKey: .rtcPort)) ?? 0
        rtcPorts = (try? c.decode([Int].self, forKey: .rtcPorts)) ?? []
        hopCount = (try? c.decode(UInt64.self, forKey: .hopCount)) ?? 0
        hopState = (try? c.decode(String.self, forKey: .hopState)) ?? ""
        rekeyCount = (try? c.decode(UInt64.self, forKey: .rekeyCount)) ?? 0
        srttMs = (try? c.decode(Int64.self, forKey: .srttMs)) ?? 0
        minRttMs = (try? c.decode(Int64.self, forKey: .minRttMs)) ?? 0
        fecRecovered = (try? c.decode(UInt64.self, forKey: .fecRecovered)) ?? 0
        lossPct = (try? c.decode(Double.self, forKey: .lossPct)) ?? 0
        pacingMbps = (try? c.decode(Double.self, forKey: .pacingMbps)) ?? 0
        upMbps = (try? c.decode(Int.self, forKey: .upMbps)) ?? 0
        downMbps = (try? c.decode(Int.self, forKey: .downMbps)) ?? 0
        activeConns = (try? c.decode(Int.self, forKey: .activeConns)) ?? 0
        activeStreams = (try? c.decode(Int.self, forKey: .activeStreams)) ?? 0
        pingMs = (try? c.decode(Int64.self, forKey: .pingMs)) ?? 0
        upBps = (try? c.decode(UInt64.self, forKey: .upBps)) ?? 0
        downBps = (try? c.decode(UInt64.self, forKey: .downBps)) ?? 0
        totalUp = (try? c.decode(UInt64.self, forKey: .totalUp)) ?? 0
        totalDown = (try? c.decode(UInt64.self, forKey: .totalDown)) ?? 0
        history = (try? c.decode([GhostTrafficPoint].self, forKey: .history)) ?? []
        socksAddr = (try? c.decode(String.self, forKey: .socksAddr)) ?? socksAddr
        httpAddr = (try? c.decode(String.self, forKey: .httpAddr)) ?? httpAddr
        nodeName = (try? c.decode(String.self, forKey: .nodeName)) ?? ""
        nodeHost = (try? c.decode(String.self, forKey: .nodeHost)) ?? ""
        nodePort = (try? c.decode(Int.self, forKey: .nodePort)) ?? 0
        isTunnelExt = (try? c.decode(Bool.self, forKey: .isTunnelExt)) ?? false
        lowMemMode = (try? c.decode(Bool.self, forKey: .lowMemMode)) ?? false
        netbindEnabled = (try? c.decode(Bool.self, forKey: .netbindEnabled)) ?? false
        physicalIface = (try? c.decode(String.self, forKey: .physicalIface)) ?? ""
        memAllocMB = (try? c.decode(Double.self, forKey: .memAllocMB)) ?? 0
        memSysMB = (try? c.decode(Double.self, forKey: .memSysMB)) ?? 0
        logs = (try? c.decode([GhostLogEntry].self, forKey: .logs)) ?? []
        customRules = (try? c.decode([String].self, forKey: .customRules)) ?? []
        recentRoutes = (try? c.decode([GhostRecentRoute].self, forKey: .recentRoutes)) ?? []
    }
}

struct TunnelIPCRequest: Codable {
    var action: String
    var configJSON: String?
    var iface: String?
}

struct TunnelIPCResponse: Codable {
    var ok: Bool
    var payload: String?
    var error: String?
}

struct GhostTunnelErrorReport: Identifiable, Equatable {
    let id = UUID()
    let title: String
    let domain: String
    let code: Int
    let message: String
    let mainBundleID: String
    let extensionBundleID: String
    let hint: String
}

enum GhostNetworkHelper {
    private static let excludedPrefixes = [
        "lo", "utun", "ipsec", "ppp", "awdl", "llw", "bridge", "ap",
        "anpi", "xhc", "pktap", "stf", "gif", "feth", "vmenet"
    ]

    static func preferredPhysicalInterface(from path: NWPath) -> String {
        let candidates = path.availableInterfaces.filter { iface in
            let lower = iface.name.lowercased()
            return !excludedPrefixes.contains(where: { lower.hasPrefix($0) })
        }
        return candidates.first?.name ?? ""
    }

    static func appSupportDirectory(subdir: String) -> String {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let dir = base.appendingPathComponent(subdir, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.path
    }
}

enum GhostByteFormatter {
    static func formatRate(_ bps: UInt64) -> String {
        "\(formatBytes(bps))/s"
    }

    static func formatBytes(_ bytes: UInt64) -> String {
        let value = Double(bytes)
        if value < 1024 {
            return "\(bytes) B"
        }
        if value < 1024 * 1024 {
            return String(format: "%.1f KB", value / 1024.0)
        }
        if value < 1024 * 1024 * 1024 {
            return String(format: "%.2f MB", value / (1024.0 * 1024.0))
        }
        return String(format: "%.2f GB", value / (1024.0 * 1024.0 * 1024.0))
    }
}
