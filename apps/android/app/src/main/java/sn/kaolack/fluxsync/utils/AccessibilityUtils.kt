package sn.kaolack.fluxsync.utils

import android.content.Context
import android.provider.Settings
import android.text.TextUtils
import sn.kaolack.fluxsync.FluxsyncAccessibilityService

object AccessibilityUtils {
    fun isServiceEnabled(context: Context): Boolean {
        val expectedServiceName = context.packageName + "/" + FluxsyncAccessibilityService::class.java.canonicalName
        val enabledServices = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return false

        val colonSplitter = TextUtils.SimpleStringSplitter(':')
        colonSplitter.setString(enabledServices)

        while (colonSplitter.hasNext()) {
            val componentName = colonSplitter.next()
            if (componentName.equals(expectedServiceName, ignoreCase = true)) {
                return true
            }
        }
        return false
    }
}
