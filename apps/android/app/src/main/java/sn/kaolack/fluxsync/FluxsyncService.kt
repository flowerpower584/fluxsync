package sn.kaolack.fluxsync

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import sn.kaolack.fluxsync.vm.DaemonState
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive

class FluxsyncService : Service() {
    private val job = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.IO + job)
    
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var multiLock: WifiManager.MulticastLock? = null

    companion object {
        const val CHANNEL_ID = "fluxsync_service"
        const val NOTIF_ID = 42
    }

    override fun onCreate() {
        super.onCreate()

        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "FluxSync::SyncLock").apply {
            acquire(10 * 60 * 1000L /*10 minutes, refreshed on interaction*/)
        }

        val wm = getSystemService(Context.WIFI_SERVICE) as WifiManager
        wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "FluxSync::WifiLock").apply {
            acquire()
        }
        multiLock = wm.createMulticastLock("FluxSync::MultiLock").apply {
            setReferenceCounted(true)
            acquire()
        }

        createNotificationChannel()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIF_ID, 
                createNotification("Actif & Sécurisé"),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            startForeground(NOTIF_ID, createNotification("Actif & Sécurisé"))
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Daemon is now booted by AccessibilityService (survives swipe).
        // This service only maintains the foreground notification.
        scope.launch {
            startStateObserver()
        }
        return START_STICKY
    }

    private var lastNotifText: String = ""

    private fun startStateObserver() {
        scope.launch {
            while (isActive) {
                try {
                    val state = FluxsyncManager.state.value
                    if (state != null) {
                        val text = if (state.active) "Linked: ${state.peerName}" else "Searching for peers..."
                        if (text != lastNotifText) {
                            lastNotifText = text
                            updateNotification(text)
                        }
                    }
                } catch (_: Exception) {}
                delay(1000)
            }
        }
    }


    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "FluxSync Service",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(content: String): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("FluxSync")
            .setContentText(content)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(content: String) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIF_ID, createNotification(content))
    }

    override fun onBind(intent: Intent?): IBinder? = Binder()

    override fun onDestroy() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wifiLock?.let { if (it.isHeld) it.release() }
        multiLock?.let { if (it.isHeld) it.release() }
        // DO NOT call handle.stop() here!
        // The daemon is owned by AccessibilityService which survives swipe.
        // Killing the daemon here was BUG #2 ("The Saboteur").
        job.cancel()
        super.onDestroy()
    }
}
