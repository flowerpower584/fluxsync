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

    fun toggle(on: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            getHandle()?.toggle(on)
        }
    }

    fun toggleSync(on: Boolean) = toggle(on) // Legacy alias

    fun pushText(text: String) {
        viewModelScope.launch(Dispatchers.IO) {
            getHandle()?.pushText(text)
        }
    }

    fun setBatteryThreshold(threshold: UByte) {
        viewModelScope.launch(Dispatchers.IO) {
            getHandle()?.setBatteryThreshold(threshold.toShort().toUByte())
        }
    }

    fun setSelfBattery(level: UByte, charging: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            getHandle()?.setSelfBattery(level.toShort().toUByte(), charging)
        }
    }

    fun setChargeOverride(on: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            getHandle()?.setChargeOverride(on)
        }
    }

    fun unpair() {
        viewModelScope.launch(Dispatchers.IO) {
            getHandle()?.unpair()
        }
    }

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

    fun pairFromUri(uri: String, name: String) {
        viewModelScope.launch(Dispatchers.IO) {
            getHandle()?.pairFromUri(uri, name)
        }
    }

    fun pairAccept(pubkeyB32: String, name: String, addr: String = "") {
        viewModelScope.launch(Dispatchers.IO) {
            getHandle()?.pairAccept(pubkeyB32, name, addr)
        }
    }

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
