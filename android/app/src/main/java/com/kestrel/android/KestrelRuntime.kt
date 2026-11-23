package com.kestrel.android

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import mobile.Mobile
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class KestrelUiState(
    val nodes: List<KestrelNode> = emptyList(),
    val selectedNodeId: String = "",
    val routeMode: KestrelRouteMode = KestrelRouteMode.RULE,
    val transportMode: KestrelTransportMode = KestrelTransportMode.AUTO,
    val upMbpsText: String = "0",
    val downMbpsText: String = "0",
    val socksPortText: String = "10808",
    val httpPortText: String = "10809",
    val enableIPv6: Boolean = false,
    val customRulesText: String = "",
    val status: KestrelStatusSnapshot = KestrelStatusSnapshot(),
    val serviceActive: Boolean = false,
    val isTransitioning: Boolean = false,
    val ruleStats: KestrelRuleStats = KestrelRuleStats(),
    val isUpdatingRules: Boolean = false,
    val diagnosticText: String = "",
    val errorBanner: String = "",
    val toastMessage: String = "",
    val localLogs: List<KestrelLogEntry> = emptyList()
) {
    val activeNode: KestrelNode?
        get() = nodes.firstOrNull { it.id == selectedNodeId } ?: nodes.firstOrNull()

    val isConnected: Boolean
        get() = serviceActive && status.state.equals("connected", ignoreCase = true)

    val effectiveSocksPort: Int
        get() = socksPortText.trim().toIntOrNull()?.takeIf { it in 1..65535 } ?: 10808

    val effectiveHttpPort: Int
        get() {
            val parsed = httpPortText.trim().toIntOrNull()
            if (parsed != null && parsed in 1..65535 && parsed != effectiveSocksPort) {
                return parsed
            }
            return if (effectiveSocksPort == 10809) 10810 else 10809
        }
}

object KestrelRuntime {
    private const val PREFS_NAME = "kestrel_android_prefs"
    private const val KEY_NODES = "nodes_json"
    private const val KEY_SELECTED_ID = "selected_node_id"
    private const val KEY_ROUTE_MODE = "route_mode"
    private const val KEY_TRANSPORT_MODE = "transport_mode"
    private const val KEY_UP_MBPS = "up_mbps"
    private const val KEY_DOWN_MBPS = "down_mbps"
    private const val KEY_SOCKS_PORT = "socks_port"
    private const val KEY_HTTP_PORT = "http_port"
    private const val KEY_ENABLE_IPV6 = "enable_ipv6"
    private const val KEY_CUSTOM_RULES = "custom_rules"

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    private lateinit var appContext: Context
    private lateinit var prefs: SharedPreferences
    private var initialized = false
    private var pollJob: Job? = null
    private var toastJob: Job? = null

    private val _uiState = MutableStateFlow(KestrelUiState())
    val uiState: StateFlow<KestrelUiState> = _uiState.asStateFlow()

    @Synchronized
    fun init(context: Context) {
        if (initialized) return
        appContext = context.applicationContext
        prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        Mobile.initCore(appContext.filesDir.absolutePath, false)

        val nodes = loadNodes()
        var selectedId = prefs.getString(KEY_SELECTED_ID, "") ?: ""
        if (nodes.none { it.id == selectedId }) {
            selectedId = nodes.firstOrNull()?.id ?: ""
        }
        val routeMode = KestrelRouteMode.fromRaw(prefs.getString(KEY_ROUTE_MODE, KestrelRouteMode.RULE.rawValue))
        val transportMode = KestrelTransportMode.fromRaw(prefs.getString(KEY_TRANSPORT_MODE, KestrelTransportMode.AUTO.rawValue))
        val upMbps = prefs.getString(KEY_UP_MBPS, "0") ?: "0"
        val downMbps = prefs.getString(KEY_DOWN_MBPS, "0") ?: "0"
        val socksPort = prefs.getString(KEY_SOCKS_PORT, "10808") ?: "10808"
        val httpPort = prefs.getString(KEY_HTTP_PORT, "10809") ?: "10809"
        val enableIPv6 = prefs.getBoolean(KEY_ENABLE_IPV6, false)
        val customRules = prefs.getString(KEY_CUSTOM_RULES, "") ?: ""

        _uiState.value = KestrelUiState(
            nodes = nodes,
            selectedNodeId = selectedId,
            routeMode = routeMode,
            transportMode = transportMode,
            upMbpsText = upMbps,
            downMbpsText = downMbps,
            socksPortText = socksPort,
            httpPortText = httpPort,
            enableIPv6 = enableIPv6,
            customRulesText = customRules,
            ruleStats = fetchRuleStats(),
            localLogs = listOf(
                KestrelLogEntry(nowTime(), "Kestrel Android ${KestrelStatusSnapshot.defaultVersionLabel()} 已就绪")
            )
        )
        initialized = true
        refreshStatusNow()
    }

    fun startPolling() {
        if (pollJob?.isActive == true) return
        pollJob = scope.launch {
            while (isActive) {
                refreshStatusNow()
                delay(1000L)
            }
        }
    }

    fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }

    fun refreshStatusNow() {
        val snap = KestrelStatusSnapshot.fromJsonString(runCatching { Mobile.getStatusJSON() }.getOrDefault(""))
            ?: return
        _uiState.update { cur ->
            val err = when {
                snap.state.equals("connected", ignoreCase = true) -> ""
                snap.lastErr.isNotBlank() -> snap.lastErr
                else -> cur.errorBanner
            }
            cur.copy(
                status = snap,
                ruleStats = snap.ruleStats,
                errorBanner = err,
                serviceActive = cur.serviceActive || snap.state.equals("connected", ignoreCase = true) || snap.tunActive
            )
        }
    }

    fun buildConfigJson(state: KestrelUiState = _uiState.value): String? {
        val node = state.activeNode ?: return null
        val customLines = state.customRulesText
            .split('\n')
            .map { it.trim() }
            .filter { it.isNotEmpty() }

        return JSONObject().apply {
            put("link_uri", node.uri)
            put("socks_port", state.effectiveSocksPort)
            put("http_port", state.effectiveHttpPort)
            put("route_mode", state.routeMode.rawValue)
            put("transport", state.transportMode.rawValue)
            put("up_mbps", state.upMbpsText.trim().toIntOrNull()?.coerceAtLeast(0) ?: 0)
            put("down_mbps", state.downMbpsText.trim().toIntOrNull()?.coerceAtLeast(0) ?: 0)
            put("async_connect", true)
            put("enable_ipv6", state.enableIPv6)
            put("custom_rules", JSONArray(customLines))
        }.toString()
    }

    fun connect() {
        val st = _uiState.value
        val node = st.activeNode
        if (node == null) {
            _uiState.update { it.copy(errorBanner = "请先通过扫码或粘贴导入节点链接") }
            showToast("请先添加节点")
            return
        }
        val cfg = buildConfigJson(st) ?: return
        _uiState.update { it.copy(isTransitioning = true, errorBanner = "") }
        appendLocalLog("启动连接：${node.remark} (${st.routeMode.label} / ${st.transportMode.label})")

        val intent = Intent(appContext, KestrelVpnService::class.java).apply {
            action = KestrelVpnService.ACTION_START
            putExtra(KestrelVpnService.EXTRA_CONFIG_JSON, cfg)
            putExtra(KestrelVpnService.EXTRA_ROUTE_MODE, st.routeMode.rawValue)
            putExtra(KestrelVpnService.EXTRA_ENABLE_IPV6, st.enableIPv6)
            putExtra(KestrelVpnService.EXTRA_NODE_REMARK, node.remark)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            appContext.startForegroundService(intent)
        } else {
            appContext.startService(intent)
        }
    }

    fun disconnect() {
        _uiState.update { it.copy(isTransitioning = true) }
        appendLocalLog("用户请求断开连接")
        val intent = Intent(appContext, KestrelVpnService::class.java).apply {
            action = KestrelVpnService.ACTION_STOP
        }
        appContext.startService(intent)
    }

    fun reloadIfActive() {
        val st = _uiState.value
        if (!st.serviceActive) return
        val node = st.activeNode ?: return
        val cfg = buildConfigJson(st) ?: return
        val intent = Intent(appContext, KestrelVpnService::class.java).apply {
            action = KestrelVpnService.ACTION_RELOAD
            putExtra(KestrelVpnService.EXTRA_CONFIG_JSON, cfg)
            putExtra(KestrelVpnService.EXTRA_ROUTE_MODE, st.routeMode.rawValue)
            putExtra(KestrelVpnService.EXTRA_ENABLE_IPV6, st.enableIPv6)
            putExtra(KestrelVpnService.EXTRA_NODE_REMARK, node.remark)
        }
        appContext.startService(intent)
    }

    fun setServiceTransitioning(v: Boolean) {
        _uiState.update { it.copy(isTransitioning = v) }
    }

    fun onServiceStarted(remark: String) {
        _uiState.update { it.copy(serviceActive = true, isTransitioning = false, errorBanner = "") }
        appendLocalLog("隧道核心已启动（$remark）")
        refreshStatusNow()
    }

    fun onServiceStopped() {
        _uiState.update {
            it.copy(
                serviceActive = false,
                isTransitioning = false,
                status = it.status.copy(state = "disconnected", upBps = 0, downBps = 0, tunActive = false)
            )
        }
        appendLocalLog("隧道核心已停止")
        refreshStatusNow()
    }

    fun onServiceError(message: String) {
        _uiState.update {
            it.copy(serviceActive = false, isTransitioning = false, errorBanner = message)
        }
        appendLocalLog("错误：$message")
    }

    fun importLink(rawText: String): Boolean {
        val trimmed = rawText.trim()
        if (trimmed.isEmpty()) {
            showToast("链接不能为空")
            return false
        }
        val rawResp = runCatching { Mobile.parseLinkEnvelopeJSON(trimmed) }.getOrNull()
        if (rawResp == null) {
            showToast("解析失败：核心调用异常")
            return false
        }
        val env = runCatching { JSONObject(rawResp) }.getOrNull()
        if (env == null || !env.optBoolean("ok", false)) {
            val errMsg = env?.optString("error", "无效链接") ?: "无效链接"
            _uiState.update { it.copy(errorBanner = errMsg) }
            showToast(errMsg)
            return false
        }
        val data = env.optJSONObject("data") ?: return false
        val current = _uiState.value.nodes.toMutableList()
        val parsed = KestrelNode.fromJson(data)
        val existingIdx = current.indexOfFirst {
            it.host == parsed.host && it.port == parsed.port && it.sni == parsed.sni
        }
        val targetId: String
        if (existingIdx >= 0) {
            val old = current[existingIdx]
            current[existingIdx] = parsed.copy(id = old.id)
            targetId = old.id
        } else {
            current.add(0, parsed)
            targetId = parsed.id
        }
        saveNodes(current, targetId)
        _uiState.update {
            it.copy(nodes = current, selectedNodeId = targetId, errorBanner = "")
        }
        appendLocalLog("已导入节点：${parsed.remark}")
        showToast("已导入 ${parsed.remark}")
        if (_uiState.value.serviceActive) {
            reloadIfActive()
        }
        return true
    }

    fun selectNode(id: String) {
        val node = _uiState.value.nodes.firstOrNull { it.id == id } ?: return
        prefs.edit().putString(KEY_SELECTED_ID, id).apply()
        _uiState.update { it.copy(selectedNodeId = id) }
        appendLocalLog("切换节点：${node.remark}")
        if (_uiState.value.serviceActive) {
            reloadIfActive()
            showToast("正在无缝切换至 ${node.remark}")
        }
    }

    fun renameNode(id: String, newRemark: String) {
        val clean = newRemark.trim()
        if (clean.isEmpty()) return
        val updated = _uiState.value.nodes.map {
            if (it.id == id) it.copy(remark = clean) else it
        }
        saveNodes(updated, _uiState.value.selectedNodeId)
        _uiState.update { it.copy(nodes = updated) }
        showToast("节点已重命名")
    }

    fun deleteNode(id: String) {
        val updated = _uiState.value.nodes.filterNot { it.id == id }
        val nextSelected = if (_uiState.value.selectedNodeId == id) {
            updated.firstOrNull()?.id ?: ""
        } else {
            _uiState.value.selectedNodeId
        }
        saveNodes(updated, nextSelected)
        _uiState.update { it.copy(nodes = updated, selectedNodeId = nextSelected) }
        showToast("已删除节点")
    }

    fun setRouteMode(mode: KestrelRouteMode) {
        prefs.edit().putString(KEY_ROUTE_MODE, mode.rawValue).apply()
        _uiState.update { it.copy(routeMode = mode) }
        if (_uiState.value.serviceActive) {
            reloadIfActive()
        }
    }

    fun setTransportMode(mode: KestrelTransportMode) {
        prefs.edit().putString(KEY_TRANSPORT_MODE, mode.rawValue).apply()
        _uiState.update { it.copy(transportMode = mode) }
        if (_uiState.value.serviceActive) {
            reloadIfActive()
        }
    }

    fun setEnableIPv6(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ENABLE_IPV6, enabled).apply()
        _uiState.update { it.copy(enableIPv6 = enabled) }
        if (_uiState.value.serviceActive) {
            showToast("IPv6 设置已保存，重连后生效")
        }
    }

    fun saveAdvancedSettings(
        socksPort: String,
        httpPort: String,
        upMbps: String,
        downMbps: String,
        customRules: String
    ) {
        prefs.edit()
            .putString(KEY_SOCKS_PORT, socksPort.trim())
            .putString(KEY_HTTP_PORT, httpPort.trim())
            .putString(KEY_UP_MBPS, upMbps.trim())
            .putString(KEY_DOWN_MBPS, downMbps.trim())
            .putString(KEY_CUSTOM_RULES, customRules)
            .apply()
        _uiState.update {
            it.copy(
                socksPortText = socksPort.trim(),
                httpPortText = httpPort.trim(),
                upMbpsText = upMbps.trim(),
                downMbpsText = downMbps.trim(),
                customRulesText = customRules
            )
        }
        showToast("设置已保存")
        if (_uiState.value.serviceActive) {
            reloadIfActive()
        }
    }

    fun clearLogs() {
        runCatching { Mobile.clearLogs() }
        _uiState.update {
            it.copy(
                localLogs = emptyList(),
                status = it.status.copy(logs = emptyList())
            )
        }
        showToast("日志已清空")
    }

    fun updateRuleBundle() {
        if (_uiState.value.isUpdatingRules) return
        _uiState.update { it.copy(isUpdatingRules = true) }
        scope.launch {
            val raw = runCatching { Mobile.updateRuleBundleJSON("") }.getOrDefault("")
            val env = runCatching { JSONObject(raw) }.getOrNull()
            if (env != null && env.optBoolean("ok", false)) {
                val stats = KestrelRuleStats.fromJson(env.optJSONObject("data"))
                _uiState.update { it.copy(isUpdatingRules = false, ruleStats = stats) }
                appendLocalLog("规则库已热更新：${stats.rulesetVersion}")
                showToast("规则库已更新 (${stats.rulesetVersion})")
            } else {
                val err = env?.optString("error", "规则库更新失败") ?: "规则库更新失败"
                _uiState.update { it.copy(isUpdatingRules = false) }
                appendLocalLog("规则更新失败：$err")
                showToast(err)
            }
        }
    }

    fun loadDiagnosticSnapshot() {
        scope.launch {
            val text = runCatching { Mobile.getDiagnosticSnapshot() }.getOrDefault("诊断信息不可用")
            _uiState.update { it.copy(diagnosticText = text) }
        }
    }

    fun buildClashYaml(): String {
        val st = _uiState.value
        return """
            |mixed-port: ${st.effectiveHttpPort}
            |socks-port: ${st.effectiveSocksPort}
            |allow-lan: false
            |mode: rule
            |proxies:
            |  - name: "Kestrel-Android"
            |    type: socks5
            |    server: 127.0.0.1
            |    port: ${st.effectiveSocksPort}
            |    udp: true
        """.trimMargin()
    }

    fun buildAntiLoopBypassRule(): String {
        val host = _uiState.value.activeNode?.host?.trim().orEmpty()
        if (host.isEmpty()) return ""
        return runCatching { Mobile.buildBypassRule(host) }.getOrDefault("")
    }

    fun showToast(msg: String) {
        _uiState.update { it.copy(toastMessage = msg) }
        toastJob?.cancel()
        toastJob = scope.launch {
            delay(2200L)
            _uiState.update { cur ->
                if (cur.toastMessage == msg) cur.copy(toastMessage = "") else cur
            }
        }
    }

    private fun fetchRuleStats(): KestrelRuleStats {
        val raw = runCatching { Mobile.getRuleStatsJSON() }.getOrDefault("")
        val env = runCatching { JSONObject(raw) }.getOrNull() ?: return KestrelRuleStats()
        return KestrelRuleStats.fromJson(env.optJSONObject("data"))
    }

    private fun loadNodes(): List<KestrelNode> {
        val raw = prefs.getString(KEY_NODES, "") ?: ""
        if (raw.isBlank()) return emptyList()
        return runCatching {
            val arr = JSONArray(raw)
            buildList(arr.length()) {
                for (i in 0 until arr.length()) {
                    val obj = arr.optJSONObject(i) ?: continue
                    add(KestrelNode.fromJson(obj))
                }
            }
        }.getOrDefault(emptyList())
    }

    private fun saveNodes(nodes: List<KestrelNode>, selectedId: String) {
        val arr = JSONArray()
        nodes.forEach { arr.put(it.toJson()) }
        prefs.edit()
            .putString(KEY_NODES, arr.toString())
            .putString(KEY_SELECTED_ID, selectedId)
            .apply()
    }

    private fun appendLocalLog(msg: String) {
        val entry = KestrelLogEntry(nowTime(), msg)
        _uiState.update { cur ->
            val next = (cur.localLogs + entry).takeLast(120)
            cur.copy(localLogs = next)
        }
    }

    private fun nowTime(): String = synchronized(timeFmt) { timeFmt.format(Date()) }
}
