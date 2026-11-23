package com.kestrel.android

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AddLink
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.ListAlt
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.util.Locale

private object KestrelPalette {
    val Background = Color(0xFFF6F7FA)
    val Card = Color(0xFFFFFFFF)
    val CardAlt = Color(0xFFF1F5F9)
    val Border = Color(0xFFE2E8F0)
    val Brand = Color(0xFF0284C7)
    val Emerald = Color(0xFF059669)
    val Amber = Color(0xFFD97706)
    val Crimson = Color(0xFFDC2626)
    val TextPrimary = Color(0xFF0F172A)
    val TextSecondary = Color(0xFF64748B)
}

private enum class MainTab(val title: String) {
    CONSOLE("控制台"),
    NODES("节点"),
    RULES_LOGS("分流与日志"),
    SETTINGS("设置")
}

@Composable
fun KestrelConsoleScreen(
    state: KestrelUiState,
    onToggleConnect: () -> Unit,
    onScanQr: () -> Unit
) {
    val context = LocalContext.current
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    var showImportDialog by remember { mutableStateOf(false) }
    var importUriDraft by remember { mutableStateOf("") }
    var renamingNode by remember { mutableStateOf<KestrelNode?>(null) }
    var renameDraft by remember { mutableStateOf("") }
    var showDiagDialog by remember { mutableStateOf(false) }

    val openImport = {
        val clip = readClipboardPrefixUri(context)
        if (clip.isNotEmpty()) {
            importUriDraft = clip
        }
        showImportDialog = true
    }

    Scaffold(
        containerColor = KestrelPalette.Background,
        topBar = {
            KestrelTopBar(
                state = state,
                onScanQr = onScanQr,
                onImport = openImport
            )
        },
        bottomBar = {
            NavigationBar(
                containerColor = KestrelPalette.Card,
                tonalElevation = 0.dp
            ) {
                val tabs = listOf(
                    Triple(MainTab.CONSOLE, Icons.Filled.Bolt, "控制台"),
                    Triple(MainTab.NODES, Icons.Filled.Dns, "节点"),
                    Triple(MainTab.RULES_LOGS, Icons.Filled.ListAlt, "分流与日志"),
                    Triple(MainTab.SETTINGS, Icons.Filled.Tune, "设置")
                )
                tabs.forEachIndexed { idx, (_, icon, label) ->
                    NavigationBarItem(
                        selected = selectedTab == idx,
                        onClick = { selectedTab = idx },
                        icon = { Icon(icon, contentDescription = label, modifier = Modifier.size(20.dp)) },
                        label = { Text(label, fontSize = 11.sp, maxLines = 1) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = KestrelPalette.Brand,
                            selectedTextColor = KestrelPalette.Brand,
                            indicatorColor = KestrelPalette.Brand.copy(alpha = 0.12f),
                            unselectedIconColor = KestrelPalette.TextSecondary,
                            unselectedTextColor = KestrelPalette.TextSecondary
                        )
                    )
                }
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .background(KestrelPalette.Background)
        ) {
            when (selectedTab) {
                0 -> ConsoleTabContent(
                    state = state,
                    onToggleConnect = onToggleConnect,
                    onOpenNodes = { selectedTab = 1 }
                )

                1 -> NodesTabContent(
                    state = state,
                    onSelectNode = { KestrelRuntime.selectNode(it.id) },
                    onRenameNode = {
                        renamingNode = it
                        renameDraft = it.remark
                    },
                    onCopyNodeUri = {
                        copyText(context, it.uri, "已复制节点链接")
                    },
                    onDeleteNode = { KestrelRuntime.deleteNode(it.id) },
                    onImport = openImport,
                    onScanQr = onScanQr
                )

                2 -> RulesAndLogsTabContent(
                    state = state,
                    onCopyLogs = {
                        val merged = (state.status.logs + state.localLogs)
                            .joinToString("\n") { "[${it.time}] ${it.message}" }
                        copyText(context, merged, "已复制运行日志")
                    }
                )

                3 -> SettingsTabContent(
                    state = state,
                    onCopyClash = {
                        copyText(context, KestrelRuntime.buildClashYaml(), "已复制 Clash 配置")
                    },
                    onCopyBypass = {
                        val rule = KestrelRuntime.buildAntiLoopBypassRule()
                        if (rule.isBlank()) {
                            KestrelRuntime.showToast("请先选择节点")
                        } else {
                            copyText(context, rule, "已复制防环回规则")
                        }
                    },
                    onShowDiagnostics = {
                        KestrelRuntime.loadDiagnosticSnapshot()
                        showDiagDialog = true
                    }
                )
            }

            if (state.toastMessage.isNotEmpty()) {
                Surface(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(bottom = 16.dp, start = 24.dp, end = 24.dp),
                    color = KestrelPalette.TextPrimary.copy(alpha = 0.92f),
                    shape = RoundedCornerShape(24.dp),
                    shadowElevation = 4.dp
                ) {
                    Text(
                        text = state.toastMessage,
                        color = Color.White,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Medium,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 9.dp)
                    )
                }
            }
        }
    }

    if (showImportDialog) {
        AlertDialog(
            onDismissRequest = { showImportDialog = false },
            containerColor = KestrelPalette.Card,
            title = { Text("导入节点链接", fontWeight = FontWeight.SemiBold, color = KestrelPalette.TextPrimary) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        "支持 ksl4:// 与 gft3:// 链接（自动识别剪贴板）",
                        fontSize = 12.sp,
                        color = KestrelPalette.TextSecondary
                    )
                    OutlinedTextField(
                        value = importUriDraft,
                        onValueChange = { importUriDraft = it },
                        placeholder = { Text("ksl4://...") },
                        minLines = 3,
                        maxLines = 5,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (KestrelRuntime.importLink(importUriDraft)) {
                            importUriDraft = ""
                            showImportDialog = false
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = KestrelPalette.Brand)
                ) {
                    Text("导入并选中")
                }
            },
            dismissButton = {
                TextButton(onClick = { showImportDialog = false }) {
                    Text("取消", color = KestrelPalette.TextSecondary)
                }
            }
        )
    }

    val editing = renamingNode
    if (editing != null) {
        AlertDialog(
            onDismissRequest = { renamingNode = null },
            containerColor = KestrelPalette.Card,
            title = { Text("重命名节点", fontWeight = FontWeight.SemiBold, color = KestrelPalette.TextPrimary) },
            text = {
                OutlinedTextField(
                    value = renameDraft,
                    onValueChange = { renameDraft = it },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        KestrelRuntime.renameNode(editing.id, renameDraft)
                        renamingNode = null
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = KestrelPalette.Brand)
                ) {
                    Text("保存")
                }
            },
            dismissButton = {
                TextButton(onClick = { renamingNode = null }) {
                    Text("取消", color = KestrelPalette.TextSecondary)
                }
            }
        )
    }

    if (showDiagDialog) {
        AlertDialog(
            onDismissRequest = { showDiagDialog = false },
            containerColor = KestrelPalette.Card,
            title = { Text("诊断快照", fontWeight = FontWeight.SemiBold, color = KestrelPalette.TextPrimary) },
            text = {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(260.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(KestrelPalette.CardAlt)
                        .padding(10.dp)
                        .verticalScroll(rememberScrollState())
                ) {
                    Text(
                        text = state.diagnosticText.ifBlank { "正在采集核心诊断信息..." },
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = KestrelPalette.TextPrimary
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = { copyText(context, state.diagnosticText, "已复制诊断报告") },
                    colors = ButtonDefaults.buttonColors(containerColor = KestrelPalette.Brand)
                ) {
                    Text("复制报告")
                }
            },
            dismissButton = {
                TextButton(onClick = { showDiagDialog = false }) {
                    Text("关闭", color = KestrelPalette.TextSecondary)
                }
            }
        )
    }
}

@Composable
private fun KestrelTopBar(
    state: KestrelUiState,
    onScanQr: () -> Unit,
    onImport: () -> Unit
) {
    val dotColor = when {
        state.isTransitioning -> KestrelPalette.Amber
        state.isConnected -> KestrelPalette.Emerald
        state.serviceActive -> KestrelPalette.Amber
        else -> KestrelPalette.TextSecondary.copy(alpha = 0.55f)
    }
    val pulse = rememberInfiniteTransition(label = "breath")
    val alpha by pulse.animateFloat(
        initialValue = 1f,
        targetValue = 0.35f,
        animationSpec = infiniteRepeatable(tween(1200), RepeatMode.Reverse),
        label = "dotAlpha"
    )

    Surface(color = KestrelPalette.Card) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .alpha(if (state.isConnected || state.isTransitioning) alpha else 1f)
                        .clip(CircleShape)
                        .background(dotColor)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = "Kestrel",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    color = KestrelPalette.TextPrimary
                )
                Spacer(Modifier.width(6.dp))
                Surface(
                    color = KestrelPalette.Brand.copy(alpha = 0.1f),
                    shape = RoundedCornerShape(6.dp)
                ) {
                    Text(
                        text = "Android",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = KestrelPalette.Brand,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
                Spacer(Modifier.width(6.dp))
                Text(
                    text = state.status.version,
                    fontSize = 12.sp,
                    color = KestrelPalette.TextSecondary,
                    style = TextStyle(fontFeatureSettings = "tnum")
                )
                Spacer(Modifier.weight(1f))
                IconButton(onClick = onScanQr, modifier = Modifier.size(34.dp)) {
                    Icon(
                        Icons.Filled.QrCodeScanner,
                        contentDescription = "扫码导入",
                        tint = KestrelPalette.Brand,
                        modifier = Modifier.size(20.dp)
                    )
                }
                Spacer(Modifier.width(4.dp))
                OutlinedButton(
                    onClick = onImport,
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    border = BorderStroke(1.dp, KestrelPalette.Border),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.height(32.dp)
                ) {
                    Icon(
                        Icons.Filled.AddLink,
                        contentDescription = null,
                        tint = KestrelPalette.Brand,
                        modifier = Modifier.size(15.dp)
                    )
                    Spacer(Modifier.width(4.dp))
                    Text("导入", fontSize = 12.sp, color = KestrelPalette.Brand, fontWeight = FontWeight.SemiBold)
                }
            }
            HorizontalDivider(thickness = 1.dp, color = KestrelPalette.Border)
        }
    }
}

@Composable
private fun ConsoleTabContent(
    state: KestrelUiState,
    onToggleConnect: () -> Unit,
    onOpenNodes: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // 1. Main Connection Card
        PorcelainCard {
            val active = state.activeNode
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(onClick = onOpenNodes),
                color = KestrelPalette.CardAlt,
                shape = RoundedCornerShape(10.dp)
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = active?.remark ?: "未配置节点（点击导入）",
                            fontSize = 14.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = KestrelPalette.TextPrimary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = if (active != null) {
                                val hop = if (active.hopRange.isNotBlank()) " · Hop ${active.hopRange}" else ""
                                "${active.host}:${active.port} · ${active.transport.uppercase()}$hop"
                            } else {
                                "支持 ksl4:// 与扫码导入"
                            },
                            fontSize = 11.sp,
                            color = KestrelPalette.TextSecondary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    Text("切换 ›", fontSize = 12.sp, color = KestrelPalette.Brand, fontWeight = FontWeight.Medium)
                }
            }

            Spacer(Modifier.height(12.dp))

            val btnColor = when {
                state.isTransitioning -> KestrelPalette.Amber
                state.serviceActive -> KestrelPalette.Crimson
                else -> KestrelPalette.Brand
            }
            val btnLabel = when {
                state.isTransitioning && !state.serviceActive -> "正在建立隧道..."
                state.isTransitioning && state.serviceActive -> "正在断开..."
                state.isConnected -> "断开 Kestrel VPN"
                state.serviceActive -> "停止隧道核心"
                else -> "连接 Kestrel VPN"
            }

            Button(
                onClick = onToggleConnect,
                colors = ButtonDefaults.buttonColors(containerColor = btnColor),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
            ) {
                if (state.isTransitioning) {
                    CircularProgressIndicator(
                        color = Color.White,
                        strokeWidth = 2.dp,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                }
                Text(btnLabel, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = Color.White)
            }

            if (state.errorBanner.isNotBlank()) {
                Spacer(Modifier.height(10.dp))
                Surface(
                    color = KestrelPalette.Crimson.copy(alpha = 0.08f),
                    shape = RoundedCornerShape(8.dp),
                    border = BorderStroke(1.dp, KestrelPalette.Crimson.copy(alpha = 0.25f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Filled.WarningAmber,
                            contentDescription = null,
                            tint = KestrelPalette.Crimson,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(state.errorBanner, fontSize = 12.sp, color = KestrelPalette.Crimson)
                    }
                }
            }
        }

        // 2. Pure Numeric Traffic Stats Card (Zero Waveform)
        PorcelainCard {
            Text(
                "实时流量统计",
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = KestrelPalette.TextSecondary
            )
            Spacer(Modifier.height(10.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                MetricTile(
                    label = "↑ 实时上行",
                    value = KestrelFormatters.formatRate(state.status.upBps),
                    valueColor = KestrelPalette.Brand,
                    modifier = Modifier.weight(1f)
                )
                MetricTile(
                    label = "↓ 实时下行",
                    value = KestrelFormatters.formatRate(state.status.downBps),
                    valueColor = KestrelPalette.Emerald,
                    modifier = Modifier.weight(1f)
                )
            }
            Spacer(Modifier.height(8.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                MetricTile(
                    label = "累计上行",
                    value = KestrelFormatters.formatBytes(state.status.totalUp),
                    valueColor = KestrelPalette.TextPrimary,
                    modifier = Modifier.weight(1f)
                )
                MetricTile(
                    label = "累计下行",
                    value = KestrelFormatters.formatBytes(state.status.totalDown),
                    valueColor = KestrelPalette.TextPrimary,
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // 3. Route Mode & Transport Pills
        PorcelainCard {
            Text("路由模式", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = KestrelPalette.TextSecondary)
            Spacer(Modifier.height(8.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                KestrelRouteMode.entries.forEach { mode ->
                    PillChoice(
                        label = mode.label,
                        selected = state.routeMode == mode,
                        onClick = { KestrelRuntime.setRouteMode(mode) },
                        modifier = Modifier.weight(1f)
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
            Text("传输协议偏好", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = KestrelPalette.TextSecondary)
            Spacer(Modifier.height(8.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                KestrelTransportMode.entries.forEach { tr ->
                    PillChoice(
                        label = tr.label,
                        selected = state.transportMode == tr,
                        onClick = { KestrelRuntime.setTransportMode(tr) },
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }

        // 4. Live Telemetry Summary
        PorcelainCard {
            Text("链路与内核遥测", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = KestrelPalette.TextSecondary)
            Spacer(Modifier.height(10.dp))
            val rttText = if (state.status.srttMs > 0) "${state.status.srttMs} ms" else if (state.status.pingMs > 0) "${state.status.pingMs} ms" else "--"
            val transText = state.status.activeTransport.ifBlank { state.transportMode.rawValue.uppercase() }
            val memText = String.format(Locale.US, "%.1f MB", state.status.memAllocMB)

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                MetricTile("活跃传输", transText, KestrelPalette.TextPrimary, Modifier.weight(1f))
                MetricTile("链路延迟", rttText, KestrelPalette.Brand, Modifier.weight(1f))
            }
            Spacer(Modifier.height(8.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                MetricTile("活跃连接/流", "${state.status.activeConns} / ${state.status.activeStreams}", KestrelPalette.TextPrimary, Modifier.weight(1f))
                MetricTile("Go 堆内存", memText, KestrelPalette.TextPrimary, Modifier.weight(1f))
            }
        }
    }
}

@Composable
private fun NodesTabContent(
    state: KestrelUiState,
    onSelectNode: (KestrelNode) -> Unit,
    onRenameNode: (KestrelNode) -> Unit,
    onCopyNodeUri: (KestrelNode) -> Unit,
    onDeleteNode: (KestrelNode) -> Unit,
    onImport: () -> Unit,
    onScanQr: () -> Unit
) {
    if (state.nodes.isEmpty()) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            contentAlignment = Alignment.Center
        ) {
            PorcelainCard {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text("暂无节点配置", fontSize = 16.sp, fontWeight = FontWeight.SemiBold, color = KestrelPalette.TextPrimary)
                    Text("通过扫码或粘贴 ksl4:// 链接导入服务器节点", fontSize = 12.sp, color = KestrelPalette.TextSecondary)
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Button(
                            onClick = onScanQr,
                            colors = ButtonDefaults.buttonColors(containerColor = KestrelPalette.Brand)
                        ) {
                            Icon(Icons.Filled.QrCodeScanner, null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("扫码导入")
                        }
                        OutlinedButton(onClick = onImport) {
                            Text("粘贴链接", color = KestrelPalette.Brand)
                        }
                    }
                }
            }
        }
        return
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        items(state.nodes, key = { it.id }) { node ->
            val isActive = node.id == state.activeNode?.id
            Surface(
                color = KestrelPalette.Card,
                shape = RoundedCornerShape(14.dp),
                border = BorderStroke(
                    width = if (isActive) 1.5.dp else 1.dp,
                    color = if (isActive) KestrelPalette.Brand else KestrelPalette.Border
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onSelectNode(node) }
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    if (isActive) {
                        Icon(
                            Icons.Filled.CheckCircle,
                            contentDescription = "已选中",
                            tint = KestrelPalette.Brand,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(Modifier.width(8.dp))
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            node.remark,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = KestrelPalette.TextPrimary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        val hop = if (node.hopRange.isNotBlank()) " · Hop ${node.hopRange}" else ""
                        Text(
                            "${node.host}:${node.port} · ${node.transport.uppercase()}$hop",
                            fontSize = 11.sp,
                            color = KestrelPalette.TextSecondary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    IconButton(onClick = { onRenameNode(node) }, modifier = Modifier.size(32.dp)) {
                        Icon(Icons.Filled.Edit, "重命名", tint = KestrelPalette.TextSecondary, modifier = Modifier.size(16.dp))
                    }
                    IconButton(onClick = { onCopyNodeUri(node) }, modifier = Modifier.size(32.dp)) {
                        Icon(Icons.Filled.ContentCopy, "复制", tint = KestrelPalette.TextSecondary, modifier = Modifier.size(16.dp))
                    }
                    IconButton(onClick = { onDeleteNode(node) }, modifier = Modifier.size(32.dp)) {
                        Icon(Icons.Filled.DeleteOutline, "删除", tint = KestrelPalette.Crimson, modifier = Modifier.size(17.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun RulesAndLogsTabContent(
    state: KestrelUiState,
    onCopyLogs: () -> Unit
) {
    var segment by rememberSaveable { mutableIntStateOf(0) }
    val logs = remember(state.status.logs, state.localLogs) {
        (state.status.logs + state.localLogs).takeLast(120).reversed()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            PillChoice("分流明细", segment == 0, { segment = 0 }, Modifier.weight(1f))
            PillChoice("运行日志", segment == 1, { segment = 1 }, Modifier.weight(1f))
        }

        if (segment == 0) {
            PorcelainCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            "KSLR 规则引擎 ${state.ruleStats.rulesetVersion}",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = KestrelPalette.TextPrimary
                        )
                        Text(
                            "域名 ${state.ruleStats.builtinDomains} · CIDR ${state.ruleStats.builtinCidrs} · 自定义 ${state.ruleStats.customRules}",
                            fontSize = 11.sp,
                            color = KestrelPalette.TextSecondary,
                            style = TextStyle(fontFeatureSettings = "tnum")
                        )
                    }
                    OutlinedButton(
                        onClick = { KestrelRuntime.updateRuleBundle() },
                        enabled = !state.isUpdatingRules,
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        modifier = Modifier.height(32.dp)
                    ) {
                        Icon(Icons.Filled.Refresh, null, tint = KestrelPalette.Brand, modifier = Modifier.size(14.dp))
                        Spacer(Modifier.width(4.dp))
                        Text(if (state.isUpdatingRules) "更新中..." else "热更新", fontSize = 12.sp, color = KestrelPalette.Brand)
                    }
                }
                Spacer(Modifier.height(10.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    MetricTile("直连命中", "${state.ruleStats.directHits}", KestrelPalette.Emerald, Modifier.weight(1f))
                    MetricTile("代理命中", "${state.ruleStats.proxyHits}", KestrelPalette.Brand, Modifier.weight(1f))
                    MetricTile("拦截", "${state.ruleStats.rejectHits}", KestrelPalette.Crimson, Modifier.weight(1f))
                }
            }

            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                items(state.status.recentRoutes.reversed()) { rt ->
                    val badgeColor = when (rt.action.lowercase()) {
                        "direct" -> KestrelPalette.Emerald
                        "reject" -> KestrelPalette.Crimson
                        else -> KestrelPalette.Brand
                    }
                    Surface(
                        color = KestrelPalette.Card,
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, KestrelPalette.Border),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Surface(
                                color = badgeColor.copy(alpha = 0.12f),
                                shape = RoundedCornerShape(6.dp)
                            ) {
                                Text(
                                    rt.action.uppercase(),
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = badgeColor,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                )
                            }
                            Spacer(Modifier.width(8.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    rt.host.ifBlank { rt.target },
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = KestrelPalette.TextPrimary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    "${rt.time} · ${rt.reason}",
                                    fontSize = 10.sp,
                                    color = KestrelPalette.TextSecondary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        }
                    }
                }
            }
        } else {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                TextButton(onClick = onCopyLogs) { Text("复制全部", color = KestrelPalette.Brand, fontSize = 12.sp) }
                TextButton(onClick = { KestrelRuntime.clearLogs() }) { Text("清空", color = KestrelPalette.Crimson, fontSize = 12.sp) }
            }
            Surface(
                color = KestrelPalette.Card,
                shape = RoundedCornerShape(12.dp),
                border = BorderStroke(1.dp, KestrelPalette.Border),
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
            ) {
                LazyColumn(contentPadding = PaddingValues(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    items(logs) { item ->
                        Text(
                            "[${item.time}] ${item.message}",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = KestrelPalette.TextPrimary
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SettingsTabContent(
    state: KestrelUiState,
    onCopyClash: () -> Unit,
    onCopyBypass: () -> Unit,
    onShowDiagnostics: () -> Unit
) {
    var socksDraft by remember(state.socksPortText) { mutableStateOf(state.socksPortText) }
    var httpDraft by remember(state.httpPortText) { mutableStateOf(state.httpPortText) }
    var upDraft by remember(state.upMbpsText) { mutableStateOf(state.upMbpsText) }
    var downDraft by remember(state.downMbpsText) { mutableStateOf(state.downMbpsText) }
    var rulesDraft by remember(state.customRulesText) { mutableStateOf(state.customRulesText) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        PorcelainCard {
            Text("本地端口与带宽配置", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = KestrelPalette.TextPrimary)
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = socksDraft,
                    onValueChange = { socksDraft = it },
                    label = { Text("SOCKS5 端口") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.weight(1f)
                )
                OutlinedTextField(
                    value = httpDraft,
                    onValueChange = { httpDraft = it },
                    label = { Text("HTTP 端口") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.weight(1f)
                )
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = upDraft,
                    onValueChange = { upDraft = it },
                    label = { Text("上行 Mbps (0=自动)") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.weight(1f)
                )
                OutlinedTextField(
                    value = downDraft,
                    onValueChange = { downDraft = it },
                    label = { Text("下行 Mbps (0=自动)") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.weight(1f)
                )
            }
            Spacer(Modifier.height(10.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("IPv6 双栈隧道", fontSize = 13.sp, fontWeight = FontWeight.Medium, color = KestrelPalette.TextPrimary)
                    Text("默认建议保持关闭以避免纯 IPv4 网络解析拖慢", fontSize = 11.sp, color = KestrelPalette.TextSecondary)
                }
                Switch(
                    checked = state.enableIPv6,
                    onCheckedChange = { KestrelRuntime.setEnableIPv6(it) },
                    colors = SwitchDefaults.colors(checkedTrackColor = KestrelPalette.Brand)
                )
            }
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = rulesDraft,
                onValueChange = { rulesDraft = it },
                label = { Text("自定义规则 (每行一条，如 DOMAIN-SUFFIX,example.com,DIRECT)") },
                minLines = 3,
                maxLines = 6,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(10.dp))
            Button(
                onClick = {
                    KestrelRuntime.saveAdvancedSettings(socksDraft, httpDraft, upDraft, downDraft, rulesDraft)
                },
                colors = ButtonDefaults.buttonColors(containerColor = KestrelPalette.Brand),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("保存并热应用", color = Color.White)
            }
        }

        PorcelainCard {
            Text("工具与诊断", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = KestrelPalette.TextPrimary)
            Spacer(Modifier.height(10.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onCopyClash, modifier = Modifier.weight(1f)) {
                    Text("复制 Clash YAML", fontSize = 12.sp, color = KestrelPalette.Brand)
                }
                OutlinedButton(onClick = onCopyBypass, modifier = Modifier.weight(1f)) {
                    Text("复制防环回规则", fontSize = 12.sp, color = KestrelPalette.Brand)
                }
            }
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = onShowDiagnostics, modifier = Modifier.fillMaxWidth()) {
                Text("查看连接诊断快照", fontSize = 12.sp, color = KestrelPalette.TextPrimary)
            }
        }

        Text(
            text = "Kestrel Android ${KestrelStatusSnapshot.defaultVersionLabel()} (Build ${BuildConfig.VERSION_CODE})",
            fontSize = 11.sp,
            color = KestrelPalette.TextSecondary,
            modifier = Modifier.align(Alignment.CenterHorizontally)
        )
    }
}

@Composable
private fun PorcelainCard(content: @Composable ColumnScope.() -> Unit) {
    Surface(
        color = KestrelPalette.Card,
        shape = RoundedCornerShape(14.dp),
        border = BorderStroke(1.dp, KestrelPalette.Border),
        shadowElevation = 0.5.dp,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp), content = content)
    }
}

@Composable
private fun MetricTile(
    label: String,
    value: String,
    valueColor: Color,
    modifier: Modifier = Modifier
) {
    Surface(
        color = KestrelPalette.CardAlt,
        shape = RoundedCornerShape(10.dp),
        modifier = modifier
    ) {
        Column(modifier = Modifier.padding(horizontal = 10.dp, vertical = 9.dp)) {
            Text(label, fontSize = 11.sp, color = KestrelPalette.TextSecondary)
            Spacer(Modifier.height(2.dp))
            Text(
                text = value,
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = valueColor,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                style = TextStyle(fontFeatureSettings = "tnum")
            )
        }
    }
}

@Composable
private fun PillChoice(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        color = if (selected) KestrelPalette.Brand else KestrelPalette.CardAlt,
        shape = RoundedCornerShape(8.dp),
        modifier = modifier
            .height(34.dp)
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(
                text = label,
                fontSize = 12.sp,
                fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium,
                color = if (selected) Color.White else KestrelPalette.TextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

private fun readClipboardPrefixUri(context: Context): String {
    val cm = context.getSystemService(ClipboardManager::class.java) ?: return ""
    val item = cm.primaryClip?.getItemAt(0) ?: return ""
    val txt = item.coerceToText(context)?.toString()?.trim() ?: return ""
    return if (txt.startsWith("ksl", ignoreCase = true) || txt.startsWith("gft", ignoreCase = true)) {
        txt
    } else {
        ""
    }
}

private fun copyText(context: Context, text: String, toast: String) {
    val cm = context.getSystemService(ClipboardManager::class.java) ?: return
    cm.setPrimaryClip(ClipData.newPlainText("Kestrel", text))
    KestrelRuntime.showToast(toast)
}
