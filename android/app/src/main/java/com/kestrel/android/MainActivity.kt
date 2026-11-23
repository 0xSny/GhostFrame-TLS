package com.kestrel.android

import android.Manifest
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.core.content.ContextCompat
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

class MainActivity : ComponentActivity() {

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        if (res.resultCode == RESULT_OK) {
            KestrelRuntime.connect()
        } else {
            KestrelRuntime.showToast("未授予系统 VPN 权限")
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* optional notification permission */ }

    private val qrScannerLauncher = registerForActivityResult(ScanContract()) { result ->
        val contents = result.contents?.trim().orEmpty()
        if (contents.isNotEmpty()) {
            KestrelRuntime.importLink(contents)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(android.graphics.Color.WHITE, android.graphics.Color.WHITE),
            navigationBarStyle = SystemBarStyle.light(android.graphics.Color.WHITE, android.graphics.Color.WHITE)
        )
        super.onCreate(savedInstanceState)

        KestrelRuntime.init(this)
        requestNotificationPermissionIfNeeded()

        setContent {
            MaterialTheme(
                colorScheme = lightColorScheme()
            ) {
                val uiState by KestrelRuntime.uiState.collectAsState()
                KestrelConsoleScreen(
                    state = uiState,
                    onToggleConnect = { handleToggleConnect(uiState) },
                    onScanQr = { launchQrScanner() }
                )
            }
        }
    }

    override fun onStart() {
        super.onStart()
        KestrelRuntime.startPolling()
    }

    override fun onStop() {
        KestrelRuntime.stopPolling()
        super.onStop()
    }

    private fun handleToggleConnect(state: KestrelUiState) {
        if (state.serviceActive) {
            KestrelRuntime.disconnect()
            return
        }
        if (state.activeNode == null) {
            KestrelRuntime.showToast("请先导入节点")
            return
        }
        if (state.routeMode != KestrelRouteMode.CORE) {
            val prepIntent = VpnService.prepare(this)
            if (prepIntent != null) {
                vpnPermissionLauncher.launch(prepIntent)
                return
            }
        }
        KestrelRuntime.connect()
    }

    private fun launchQrScanner() {
        val options = ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt("对准 ksl4:// 节点二维码")
            setBeepEnabled(false)
            setOrientationLocked(true)
        }
        qrScannerLauncher.launch(options)
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }
}
