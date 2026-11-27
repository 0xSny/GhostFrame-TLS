package com.kestrel.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import mobile.Mobile
import mobile.SocketProtector
import org.json.JSONObject
import java.util.concurrent.Executors

class KestrelVpnService : VpnService(), SocketProtector {

    companion object {
        const val ACTION_START = "com.kestrel.android.ACTION_START"
        const val ACTION_STOP = "com.kestrel.android.ACTION_STOP"
        const val ACTION_RELOAD = "com.kestrel.android.ACTION_RELOAD"

        const val EXTRA_CONFIG_JSON = "config_json"
        const val EXTRA_ROUTE_MODE = "route_mode"
        const val EXTRA_ENABLE_IPV6 = "enable_ipv6"
        const val EXTRA_NODE_REMARK = "node_remark"

        private const val PREFS_NAME = "kestrel_android_prefs"
        private const val KEY_LAST_VPN_CFG = "last_vpn_cfg"
        private const val KEY_LAST_VPN_ROUTE = "last_vpn_route"
        private const val KEY_LAST_VPN_IPV6 = "last_vpn_ipv6"
        private const val KEY_LAST_VPN_REMARK = "last_vpn_remark"
        private const val KEY_VPN_USER_STOPPED = "vpn_user_stopped"

        private const val CHANNEL_ID = "kestrel_vpn_channel"
        private const val NOTIFICATION_ID = 4201
        private const val TUN_MTU = 1400

        fun syncNotificationState(context: android.content.Context, phase: KestrelTunnelPhase, remark: String, lastErr: String) {
            val nm = context.getSystemService(NotificationManager::class.java) ?: return
            val active = nm.activeNotifications.any { it.id == NOTIFICATION_ID }
            if (!active) return
            val label = when (phase) {
                KestrelTunnelPhase.PROTECTED -> "VPN 已保护 · ${remark.ifBlank { "Kestrel-RTC" }}"
                KestrelTunnelPhase.LINK_CONNECTING -> "系统已接管 · 链路连接中..."
                KestrelTunnelPhase.SYSTEM_CAPTURED -> "系统已接管 · 准备隧道..."
                KestrelTunnelPhase.FAILED -> "链路异常 (${lastErr.take(40)})"
                KestrelTunnelPhase.IDLE -> "隧道待机"
            }
            val openIntent = PendingIntent.getActivity(
                context,
                0,
                Intent(context, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
                },
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val stopIntent = PendingIntent.getService(
                context,
                1,
                Intent(context, KestrelVpnService::class.java).apply { action = ACTION_STOP },
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val notif = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_vp_phone_call)
                .setContentTitle("Kestrel ${KestrelStatusSnapshot.defaultVersionLabel()}")
                .setContentText(label)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setContentIntent(openIntent)
                .addAction(0, "断开", stopIntent)
                .build()
            nm.notify(NOTIFICATION_ID, notif)
        }
    }

    private val worker = Executors.newSingleThreadExecutor()
    @Volatile
    private var tunPfd: ParcelFileDescriptor? = null
    @Volatile
    private var activeEnableIPv6: Boolean = false
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun protectFD(fd: Int): Boolean = protect(fd)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        when (intent?.action) {
            ACTION_STOP -> {
                prefs.edit().putBoolean(KEY_VPN_USER_STOPPED, true).apply()
                worker.execute {
                    shutdownTunnel()
                    stopForegroundCompat()
                    stopSelf()
                }
                return START_NOT_STICKY
            }

            ACTION_RELOAD -> {
                val cfg = intent.getStringExtra(EXTRA_CONFIG_JSON) ?: return START_STICKY
                val route = intent.getStringExtra(EXTRA_ROUTE_MODE) ?: "rule"
                val ipv6 = intent.getBooleanExtra(EXTRA_ENABLE_IPV6, false)
                val remark = intent.getStringExtra(EXTRA_NODE_REMARK) ?: ""
                prefs.edit()
                    .putString(KEY_LAST_VPN_CFG, cfg)
                    .putString(KEY_LAST_VPN_ROUTE, route)
                    .putBoolean(KEY_LAST_VPN_IPV6, ipv6)
                    .putString(KEY_LAST_VPN_REMARK, remark)
                    .apply()
                worker.execute {
                    handleReload(cfg, route, ipv6, remark)
                }
                return START_STICKY
            }

            else -> {
                val cfg: String?
                val route: String
                val ipv6: Boolean
                val remark: String
                if (intent == null) {
                    if (prefs.getBoolean(KEY_VPN_USER_STOPPED, true)) {
                        stopSelf()
                        return START_NOT_STICKY
                    }
                    cfg = prefs.getString(KEY_LAST_VPN_CFG, null)
                    route = prefs.getString(KEY_LAST_VPN_ROUTE, "rule") ?: "rule"
                    ipv6 = prefs.getBoolean(KEY_LAST_VPN_IPV6, false)
                    remark = prefs.getString(KEY_LAST_VPN_REMARK, "") ?: ""
                } else {
                    cfg = intent.getStringExtra(EXTRA_CONFIG_JSON)
                    route = intent.getStringExtra(EXTRA_ROUTE_MODE) ?: "rule"
                    ipv6 = intent.getBooleanExtra(EXTRA_ENABLE_IPV6, false)
                    remark = intent.getStringExtra(EXTRA_NODE_REMARK) ?: ""
                    if (!cfg.isNullOrBlank()) {
                        prefs.edit()
                            .putBoolean(KEY_VPN_USER_STOPPED, false)
                            .putString(KEY_LAST_VPN_CFG, cfg)
                            .putString(KEY_LAST_VPN_ROUTE, route)
                            .putBoolean(KEY_LAST_VPN_IPV6, ipv6)
                            .putString(KEY_LAST_VPN_REMARK, remark)
                            .apply()
                    }
                }
                if (cfg.isNullOrBlank()) {
                    stopSelf()
                    return START_NOT_STICKY
                }

                ensureNotificationChannel()
                startForegroundCompat(buildNotification("系统已接管 · 正在连接 ${remark.ifBlank { "Kestrel" }}..."))
                KestrelRuntime.setServiceTransitioning(true)

                worker.execute {
                    startTunnel(cfg, route, ipv6, remark)
                }
                return START_STICKY
            }
        }
    }

    override fun onRevoke() {
        worker.execute {
            shutdownTunnel()
            stopForegroundCompat()
            stopSelf()
        }
        super.onRevoke()
    }

    override fun onDestroy() {
        unregisterNetworkMonitor()
        worker.execute {
            shutdownTunnel()
        }
        worker.shutdown()
        super.onDestroy()
    }

    private fun startTunnel(configJson: String, routeMode: String, enableIPv6: Boolean, remark: String) {
        try {
            Mobile.initCore(filesDir.absolutePath, false)
            Mobile.setSocketProtector(this)

            val startEnv = parseEnvelope(Mobile.startEngineJSON(configJson))
            if (!startEnv.first) {
                throw IllegalStateException(startEnv.second.ifBlank { "启动核心失败" })
            }

            if (routeMode != KestrelRouteMode.CORE.rawValue) {
                establishAndAttachTun(enableIPv6)
            } else {
                closeTunPfd()
                Mobile.stopTUNJSON()
            }

            registerNetworkMonitor()
            activeEnableIPv6 = enableIPv6
            KestrelRuntime.onServiceStarted(remark)
            val label = if (routeMode == KestrelRouteMode.CORE.rawValue) {
                "本地代理已就绪 (Core 模式)"
            } else {
                "系统已接管 · 链路连接中..."
            }
            updateNotification(label)
        } catch (t: Throwable) {
            val msg = t.message ?: "启动 VPN 失败"
            shutdownTunnel()
            KestrelRuntime.onServiceError(msg)
            stopForegroundCompat()
            stopSelf()
        }
    }

    private fun handleReload(configJson: String, routeMode: String, enableIPv6: Boolean, remark: String) {
        try {
            Mobile.setSocketProtector(this)
            val relEnv = parseEnvelope(Mobile.reloadEngineJSON(configJson))
            if (!relEnv.first) {
                KestrelRuntime.onServiceError(relEnv.second.ifBlank { "热重载失败" })
                return
            }

            if (routeMode == KestrelRouteMode.CORE.rawValue) {
                Mobile.stopTUNJSON()
                closeTunPfd()
            } else if (tunPfd == null || activeEnableIPv6 != enableIPv6) {
                Mobile.stopTUNJSON()
                establishAndAttachTun(enableIPv6)
                activeEnableIPv6 = enableIPv6
            }
            KestrelRuntime.onServiceStarted(remark)
            val label = if (routeMode == KestrelRouteMode.CORE.rawValue) {
                "本地代理运行中 (Core 模式)"
            } else {
                "系统已接管 · 链路连接中..."
            }
            updateNotification(label)
        } catch (t: Throwable) {
            KestrelRuntime.onServiceError(t.message ?: "热重载异常")
        }
    }

    private fun establishAndAttachTun(enableIPv6: Boolean) {
        closeTunPfd()
        val builder = Builder()
            .setSession("Kestrel")
            .setMtu(TUN_MTU)
            .addAddress("198.18.0.2", 32)
            .addDnsServer("198.18.0.1")
            .addRoute("0.0.0.0", 0)

        if (enableIPv6) {
            builder.addAddress("fd18:c612::2", 128)
            builder.addDnsServer("fd18:c612::1")
            builder.addRoute("::", 0)
        }

        runCatching { builder.addDisallowedApplication(packageName) }

        val pfd = builder.establish()
            ?: throw IllegalStateException("系统拒绝创建 VPN TUN 接口，请检查 VPN 授权")
        tunPfd = pfd

        val tunEnv = parseEnvelope(Mobile.startTUNWithFDJSON(pfd.fd.toLong(), TUN_MTU.toLong()))
        if (!tunEnv.first) {
            closeTunPfd()
            throw IllegalStateException(tunEnv.second.ifBlank { "启动 Go TUN 协议栈失败" })
        }
    }

    private fun shutdownTunnel() {
        unregisterNetworkMonitor()
        runCatching { Mobile.stopTUNJSON() }
        closeTunPfd()
        runCatching { Mobile.stopEngineJSON() }
        runCatching { Mobile.setSocketProtector(null) }
        KestrelRuntime.onServiceStopped()
    }

    private fun closeTunPfd() {
        val prev = tunPfd
        tunPfd = null
        if (prev != null) {
            runCatching { prev.close() }
        }
    }

    private fun registerNetworkMonitor() {
        if (networkCallback != null) return
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        connectivityManager = cm
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val iface = runCatching { cm.getLinkProperties(network)?.interfaceName ?: "" }.getOrDefault("")
                runCatching { Mobile.onNetworkChanged(iface) }
            }

            override fun onLost(network: Network) {
                runCatching { Mobile.onNetworkChanged("") }
            }
        }
        networkCallback = cb
        runCatching { cm.registerNetworkCallback(req, cb) }
    }

    private fun unregisterNetworkMonitor() {
        val cm = connectivityManager
        val cb = networkCallback
        networkCallback = null
        connectivityManager = null
        if (cm != null && cb != null) {
            runCatching { cm.unregisterNetworkCallback(cb) }
        }
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java) ?: return
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Kestrel VPN 隧道",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "保持 Kestrel-RTC 加密隧道后台稳定运行"
                setShowBadge(false)
            }
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(content: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, KestrelVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_vp_phone_call)
            .setContentTitle("Kestrel ${KestrelStatusSnapshot.defaultVersionLabel()}")
            .setContentText(content)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openIntent)
            .addAction(0, "断开", stopIntent)
            .build()
    }

    private fun updateNotification(content: String) {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        nm.notify(NOTIFICATION_ID, buildNotification(content))
    }

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    private fun parseEnvelope(raw: String): Pair<Boolean, String> {
        return runCatching {
            val o = JSONObject(raw)
            Pair(o.optBoolean("ok", false), o.optString("error", ""))
        }.getOrElse { Pair(false, it.message ?: "invalid response") }
    }
}
