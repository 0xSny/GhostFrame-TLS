package com.kestrel.android

import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale
import java.util.UUID

enum class KestrelRouteMode(val rawValue: String, val label: String) {
    RULE("rule", "Rule 智能"),
    GLOBAL("global", "Global 全局"),
    CORE("core", "Core 仅端口");

    companion object {
        fun fromRaw(v: String?): KestrelRouteMode =
            entries.firstOrNull { it.rawValue.equals(v?.trim(), ignoreCase = true) } ?: RULE
    }
}

enum class KestrelTransportMode(val rawValue: String, val label: String) {
    AUTO("auto", "Auto 双栈"),
    RTC("rtc", "RTC 极速"),
    TCP("tcp", "TCP uTLS");

    companion object {
        fun fromRaw(v: String?): KestrelTransportMode =
            entries.firstOrNull { it.rawValue.equals(v?.trim(), ignoreCase = true) } ?: AUTO
    }
}

data class KestrelNode(
    val id: String = UUID.randomUUID().toString(),
    val remark: String,
    val host: String,
    val port: Int,
    val sni: String,
    val verify: String,
    val transport: String,
    val hopRange: String,
    val upMbps: Int,
    val downMbps: Int,
    val uri: String
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("remark", remark)
        put("host", host)
        put("port", port)
        put("sni", sni)
        put("verify", verify)
        put("transport", transport)
        put("hop_range", hopRange)
        put("up_mbps", upMbps)
        put("down_mbps", downMbps)
        put("uri", uri)
    }

    companion object {
        fun fromJson(obj: JSONObject, forcedId: String? = null): KestrelNode {
            val host = obj.optString("host", "")
            val port = obj.optInt("port", 443)
            val rawRemark = obj.optString("remark", "").trim()
            return KestrelNode(
                id = forcedId ?: obj.optString("id", "").ifBlank { UUID.randomUUID().toString() },
                remark = if (rawRemark.isNotEmpty()) rawRemark else "$host:$port",
                host = host,
                port = port,
                sni = obj.optString("sni", ""),
                verify = obj.optString("verify", "ca"),
                transport = obj.optString("transport", "auto"),
                hopRange = obj.optString("hop_range", ""),
                upMbps = obj.optInt("up_mbps", 0),
                downMbps = obj.optInt("down_mbps", 0),
                uri = obj.optString("uri", "")
            )
        }
    }
}

data class KestrelLogEntry(
    val time: String,
    val message: String
)

data class KestrelRecentRoute(
    val time: String,
    val target: String,
    val host: String,
    val action: String,
    val reason: String
)

data class KestrelRuleStats(
    val rulesetVersion: String = "v4.3-KSLR100K",
    val builtinDomains: Int = 0,
    val builtinCidrs: Int = 0,
    val customRules: Int = 0,
    val directHits: Long = 0,
    val proxyHits: Long = 0,
    val rejectHits: Long = 0,
    val rulesSource: String = "embedded"
) {
    companion object {
        fun fromJson(obj: JSONObject?): KestrelRuleStats {
            if (obj == null) return KestrelRuleStats()
            return KestrelRuleStats(
                rulesetVersion = obj.optString("ruleset_version", "v4.3-KSLR100K"),
                builtinDomains = obj.optInt("builtin_domains", 0),
                builtinCidrs = obj.optInt("builtin_cidrs", 0),
                customRules = obj.optInt("custom_rules", 0),
                directHits = obj.optLong("direct_hits", 0),
                proxyHits = obj.optLong("proxy_hits", 0),
                rejectHits = obj.optLong("reject_hits", 0),
                rulesSource = obj.optString("rules_source", "embedded")
            )
        }
    }
}

data class KestrelStatusSnapshot(
    val version: String = defaultVersionLabel(),
    val state: String = "disconnected",
    val lastErr: String = "",
    val activeTransport: String = "",
    val transportPref: String = "auto",
    val routeMode: String = "rule",
    val hopRange: String = "",
    val rtcPort: Int = 0,
    val hopCount: Long = 0,
    val hopState: String = "",
    val rekeyCount: Long = 0,
    val srttMs: Long = 0,
    val minRttMs: Long = 0,
    val fecRecovered: Long = 0,
    val lossPct: Double = 0.0,
    val pacingMbps: Double = 0.0,
    val activeConns: Int = 0,
    val activeStreams: Int = 0,
    val pingMs: Long = 0,
    val upBps: Long = 0,
    val downBps: Long = 0,
    val totalUp: Long = 0,
    val totalDown: Long = 0,
    val socksAddr: String = "127.0.0.1:10808",
    val httpAddr: String = "127.0.0.1:10809",
    val nodeName: String = "",
    val nodeHost: String = "",
    val nodePort: Int = 0,
    val enableIPv6: Boolean = false,
    val tunActive: Boolean = false,
    val memAllocMB: Double = 0.0,
    val memSysMB: Double = 0.0,
    val logs: List<KestrelLogEntry> = emptyList(),
    val recentRoutes: List<KestrelRecentRoute> = emptyList(),
    val ruleStats: KestrelRuleStats = KestrelRuleStats()
) {
    companion object {
        fun defaultVersionLabel(): String {
            val v = BuildConfig.VERSION_NAME.trim()
            return if (v.startsWith("v", ignoreCase = true)) v else "v$v"
        }

        fun fromJsonString(raw: String): KestrelStatusSnapshot? {
            if (raw.isBlank()) return null
            return runCatching {
                val o = JSONObject(raw)
                val logsArr = o.optJSONArray("logs") ?: JSONArray()
                val logs = buildList(logsArr.length()) {
                    for (i in 0 until logsArr.length()) {
                        val item = logsArr.optJSONObject(i) ?: continue
                        add(
                            KestrelLogEntry(
                                time = item.optString("time", ""),
                                message = item.optString("message", "")
                            )
                        )
                    }
                }
                val routesArr = o.optJSONArray("recent_routes") ?: JSONArray()
                val routes = buildList(routesArr.length()) {
                    for (i in 0 until routesArr.length()) {
                        val item = routesArr.optJSONObject(i) ?: continue
                        add(
                            KestrelRecentRoute(
                                time = item.optString("time", ""),
                                target = item.optString("target", ""),
                                host = item.optString("host", ""),
                                action = item.optString("action", ""),
                                reason = item.optString("reason", "")
                            )
                        )
                    }
                }
                KestrelStatusSnapshot(
                    version = o.optString("version", "").ifBlank { defaultVersionLabel() },
                    state = o.optString("state", "disconnected"),
                    lastErr = o.optString("last_err", ""),
                    activeTransport = o.optString("active_transport", ""),
                    transportPref = o.optString("transport_pref", "auto"),
                    routeMode = o.optString("route_mode", "rule"),
                    hopRange = o.optString("hop_range", ""),
                    rtcPort = o.optInt("rtc_port", 0),
                    hopCount = o.optLong("hop_count", 0),
                    hopState = o.optString("hop_state", ""),
                    rekeyCount = o.optLong("rekey_count", 0),
                    srttMs = o.optLong("srtt_ms", 0),
                    minRttMs = o.optLong("min_rtt_ms", 0),
                    fecRecovered = o.optLong("fec_recovered", 0),
                    lossPct = o.optDouble("loss_pct", 0.0),
                    pacingMbps = o.optDouble("pacing_mbps", 0.0),
                    activeConns = o.optInt("active_conns", 0),
                    activeStreams = o.optInt("active_streams", 0),
                    pingMs = o.optLong("ping_ms", 0),
                    upBps = o.optLong("up_bps", 0),
                    downBps = o.optLong("down_bps", 0),
                    totalUp = o.optLong("total_up", 0),
                    totalDown = o.optLong("total_down", 0),
                    socksAddr = o.optString("socks_addr", "127.0.0.1:10808"),
                    httpAddr = o.optString("http_addr", "127.0.0.1:10809"),
                    nodeName = o.optString("node_name", ""),
                    nodeHost = o.optString("node_host", ""),
                    nodePort = o.optInt("node_port", 0),
                    enableIPv6 = o.optBoolean("enable_ipv6", false),
                    tunActive = o.optBoolean("tun_active", false),
                    memAllocMB = o.optDouble("mem_alloc_mb", 0.0),
                    memSysMB = o.optDouble("mem_sys_mb", 0.0),
                    logs = logs,
                    recentRoutes = routes,
                    ruleStats = KestrelRuleStats.fromJson(o.optJSONObject("rule_stats"))
                )
            }.getOrNull()
        }
    }
}

object KestrelFormatters {
    fun formatBytes(bytes: Long): String {
        val v = bytes.coerceAtLeast(0L).toDouble()
        return when {
            v < 1024.0 -> "${bytes.coerceAtLeast(0L)} B"
            v < 1024.0 * 1024.0 -> String.format(Locale.US, "%.1f KB", v / 1024.0)
            v < 1024.0 * 1024.0 * 1024.0 -> String.format(Locale.US, "%.2f MB", v / (1024.0 * 1024.0))
            else -> String.format(Locale.US, "%.2f GB", v / (1024.0 * 1024.0 * 1024.0))
        }
    }

    fun formatRate(bps: Long): String {
        val b = bps.coerceAtLeast(0L).toDouble()
        return when {
            b < 1024.0 -> "${bps.coerceAtLeast(0L)} B/s"
            b < 1024.0 * 1024.0 -> String.format(Locale.US, "%.1f KB/s", b / 1024.0)
            else -> String.format(Locale.US, "%.2f MB/s", b / (1024.0 * 1024.0))
        }
    }
}
