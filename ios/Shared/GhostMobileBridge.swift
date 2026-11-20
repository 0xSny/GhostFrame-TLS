import Foundation
import GhostMobile

private struct MobileActionEnvelope: Decodable {
    let ok: Bool
    let error: String?
}

private struct MobileParseLinkEnvelope: Decodable {
    let ok: Bool
    let error: String?
    let data: GhostNode?
}

struct GhostBridgeError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

enum GhostMobileBridge {
    static func initCore(dataDir: String, isTunnelExt: Bool) {
        MobileInitCore(dataDir, isTunnelExt)
    }

    static func startEngine(configJSON: String) -> Result<Void, Error> {
        let raw = MobileStartEngineJSON(configJSON)
        guard let data = raw.data(using: .utf8),
              let env = try? JSONDecoder().decode(MobileActionEnvelope.self, from: data) else {
            return .failure(GhostBridgeError(message: "Unable to decode Go engine start response"))
        }
        if env.ok {
            return .success(())
        }
        return .failure(GhostBridgeError(message: env.error ?? "Engine failed to start"))
    }

    static func stopEngine() -> Result<Void, Error> {
        let raw = MobileStopEngineJSON()
        guard let data = raw.data(using: .utf8),
              let env = try? JSONDecoder().decode(MobileActionEnvelope.self, from: data) else {
            return .failure(GhostBridgeError(message: "Unable to decode Go engine stop response"))
        }
        if env.ok {
            return .success(())
        }
        return .failure(GhostBridgeError(message: env.error ?? "Engine failed to stop"))
    }

    static func onNetworkChanged(ifaceName: String) {
        MobileOnNetworkChanged(ifaceName)
    }

    static func getStatusJSON() -> String {
        MobileGetStatusJSON()
    }

    static func getStatus() -> GhostStatusSnapshot {
        decodeStatus(from: getStatusJSON())
    }

    static func decodeStatus(from jsonString: String) -> GhostStatusSnapshot {
        guard let data = jsonString.data(using: .utf8),
              let snapshot = try? JSONDecoder().decode(GhostStatusSnapshot.self, from: data) else {
            return GhostStatusSnapshot.empty
        }
        return snapshot
    }

    static func getDiagnosticSnapshot() -> String {
        MobileGetDiagnosticSnapshot()
    }

    static func clearLogs() {
        MobileClearLogs()
    }

    static func parseLink(uri: String) -> Result<GhostNode, Error> {
        let raw = MobileParseLinkEnvelopeJSON(uri)
        guard let data = raw.data(using: .utf8),
              let env = try? JSONDecoder().decode(MobileParseLinkEnvelope.self, from: data) else {
            return .failure(GhostBridgeError(message: "Unable to decode link parser response"))
        }
        if env.ok, let node = env.data {
            return .success(node)
        }
        return .failure(GhostBridgeError(message: env.error ?? "Invalid ksl4:// link"))
    }

    static func buildShadowrocketAddURL(socksPort: Int, remark: String) -> String {
        MobileBuildShadowrocketAddURL(numericCast(socksPort), remark)
    }

    static func buildBypassRule(serverHost: String) -> String {
        MobileBuildBypassRule(serverHost)
    }

    static func startTUN(writer: MobileTunPacketWriterProtocol, mtu: Int = 1400) -> Result<Void, Error> {
        let raw = MobileStartTUNJSON(writer, mtu)
        guard let data = raw.data(using: .utf8),
              let env = try? JSONDecoder().decode(MobileActionEnvelope.self, from: data) else {
            return .failure(GhostBridgeError(message: "Unable to decode Go TUN start response"))
        }
        if env.ok {
            return .success(())
        }
        return .failure(GhostBridgeError(message: env.error ?? "TUN stack failed to start"))
    }

    static func stopTUN() {
        _ = MobileStopTUNJSON()
    }

    static func pushTunPacket(_ packet: Data) {
        MobilePushTunPacket(packet)
    }

    static func pushTunPacketBatch(_ concat: Data, lens: Data, count: Int) {
        MobilePushTunPacketBatch(concat, lens, count)
    }
}
