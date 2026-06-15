package sn.kaolack.fluxsync.vm

import android.app.Application
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.text.TextUtils
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import sn.kaolack.fluxsync.FluxsyncHandle
import sn.kaolack.fluxsync.FluxsyncService
import sn.kaolack.fluxsync.FluxsyncAccessibilityService
import sn.kaolack.fluxsync.FluxsyncManager
// LogEntryView lives in the vm package; same-package import is implicit
// for Kotlin so no explicit import is required.

/**
 * Connects the UI to the long-lived [FluxsyncService].
 */
class FluxsyncViewModel(app: Application) : AndroidViewModel(app) {

    private val _state = MutableStateFlow<DaemonState?>(null)
    val state: StateFlow<DaemonState?> = _state.asStateFlow()

    /** Live log feed driven by `FluxsyncManager.logs`. Bounded to 200 entries. */
    val logs: StateFlow<List<LogEntryView>> = FluxsyncManager.logs

    private val _booted = MutableStateFlow(false)
    val booted: StateFlow<Boolean> = _booted.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    private val _isAccessibilityEnabled = MutableStateFlow(false)
    val isAccessibilityEnabled: StateFlow<Boolean> = _isAccessibilityEnabled.asStateFlow()

    init {
        checkAccessibility()
        viewModelScope.launch {
            val intent = Intent(app, FluxsyncService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                app.startForegroundService(intent)
            } else {
                app.startService(intent)
            }
            
            _booted.value = true
            
            // Collect state from manager
            FluxsyncManager.state.collect {
                _state.value = it
            }
        }
    }

    private fun getHandle(): FluxsyncHandle? = FluxsyncManager.getHandle()

    /** Transient FFI/daemon error, surfaced as a Snackbar by FluxsyncApp. */
    val transientError: StateFlow<String?> = FluxsyncManager.lastError

    fun clearTransientError() = FluxsyncManager.clearError()

    /**
     * FS-018: run a fire-and-forget FFI call with a user-visible error
     * path. A missing handle or a thrown exception reports to
     * [FluxsyncManager.reportError] instead of failing silently.
     */
    private fun ffi(action: String, block: (FluxsyncHandle) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            val h = getHandle()
            if (h == null) {
                FluxsyncManager.reportError("$action failed: daemon not running")
                return@launch
            }
            try {
                block(h)
            } catch (e: Exception) {
                FluxsyncManager.reportError("$action failed: ${e.message}")
            }
        }
    }

    fun toggle(on: Boolean) = ffi("Toggle") { it.toggle(on) }

    fun toggleSync(on: Boolean) = toggle(on) // Legacy alias

    fun pushText(text: String) = ffi("Send clipboard") { it.pushText(text) }

    fun pushImage(png: ByteArray) = ffi("Send image") { it.pushItem("image", png) }

    fun setBatteryThreshold(threshold: UByte) =
        ffi("Set battery threshold") { it.setBatteryThreshold(threshold.toShort().toUByte()) }

    fun setSelfBattery(level: UByte, charging: Boolean) =
        ffi("Battery update") { it.setSelfBattery(level.toShort().toUByte(), charging) }

    fun setChargeOverride(on: Boolean) = ffi("Set charge override") { it.setChargeOverride(on) }

    fun unpair() = ffi("Unpair") { it.unpair() }

    /** FluxMesh: revoke one specific peer by hex peer-id, leaving every
     *  other paired device linked. Drives the per-secondary unpair button. */
    fun revoke(peerId: String) = ffi("Unpair") { it.revoke(peerId) }

    suspend fun pairShow(): String? = withContext(Dispatchers.IO) {
        try {
            var retry = 0
            while (getHandle() == null && retry < 25) {
                delay(200)
                retry++
            }
            getHandle()?.pairShow()
        } catch (t: Throwable) {
            _error.value = t.message
            null
        }
    }

    fun pairFromUri(uri: String, name: String) =
        ffi("Pair") { it.pairFromUri(uri, name) }

    fun pairAccept(pubkeyB32: String, name: String, addr: String = "") =
        ffi("Accept pairing") { it.pairAccept(pubkeyB32, name, addr) }

    /**
     * FS-052: raw JSON array of TOFU pairs awaiting verbal SAS confirmation.
     * Polled by the verify screen after a scan so the user can compare the
     * 6 words against the peer's screen. Empty `[]` once confirmed.
     */
    suspend fun pairPending(): String? = withContext(Dispatchers.IO) {
        try {
            getHandle()?.pairPending()
        } catch (t: Throwable) {
            _error.value = t.message
            null
        }
    }

    /** FS-052: accept (clears gate) or reject (revokes) a pending pair. */
    fun pairConfirm(peerId: String, accept: Boolean) =
        ffi(if (accept) "Confirm pairing" else "Reject pairing") { it.pairConfirm(peerId, accept) }

    fun checkAccessibility() {
        val app = getApplication<Application>()
        _isAccessibilityEnabled.value = isAccessibilityServiceEnabled(app, FluxsyncAccessibilityService::class.java)
    }

    private fun isAccessibilityServiceEnabled(context: android.content.Context, service: Class<out android.accessibilityservice.AccessibilityService>): Boolean {
        val expectedComponentName = android.content.ComponentName(context, service)
        val enabledServices = Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: return false
        val colonSplitter = TextUtils.SimpleStringSplitter(':')
        colonSplitter.setString(enabledServices)
        while (colonSplitter.hasNext()) {
            val componentNameString = colonSplitter.next()
            val enabledService = android.content.ComponentName.unflattenFromString(componentNameString)
            if (enabledService != null && enabledService == expectedComponentName) return true
        }
        return false
    }

    override fun onCleared() {
        // Service continues running
    }
}
