package sn.kaolack.fluxsync.ui

import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import sn.kaolack.fluxsync.ui.screens.LinkedScreen
import sn.kaolack.fluxsync.ui.screens.PairingDashboardScreen
import sn.kaolack.fluxsync.ui.screens.PairScanScreen
import sn.kaolack.fluxsync.ui.screens.PairVerifyScreen
import sn.kaolack.fluxsync.ui.theme.FsAccent
import sn.kaolack.fluxsync.ui.theme.FsDarkFg
import sn.kaolack.fluxsync.ui.theme.FsDarkMuted
import sn.kaolack.fluxsync.ui.theme.FsDarkSurface
import sn.kaolack.fluxsync.ui.theme.FsWarnSoft
import sn.kaolack.fluxsync.utils.BatteryOptimizationUtils
import sn.kaolack.fluxsync.vm.FluxsyncViewModel

object Routes {
    const val PAIR_DASHBOARD = "pair_dashboard"
    const val PAIR_SCAN = "pair_scan"
    const val PAIR_VERIFY = "pair_verify" // FS-052: SAS verify after scan
    const val LINKED = "linked" // This will remain the parent container with BottomNav

    // Main tabs
    const val HOME = "home"
    const val DEVICES = "devices"
    const val LOGS = "logs"
    const val FIREWALL = "firewall"
    const val SETTINGS = "settings"

    // DIR-P3-07: nested under the Settings tab's inner NavHost.
    const val OEM_GUIDANCE = "oem_guidance"
}

/**
 * Top-level app composable. Always starts on the Linked screen so the
 * bottom-nav tabs (Home/Devices/Logs/Settings) stay reachable even
 * with no peer paired. When a peer appears the UI auto-advances to
 * Linked; a peer dropping never forces navigation, so the user's
 * current screen survives WiFi hiccups and daemon restarts.
 */
@Composable
fun FluxsyncApp(vm: FluxsyncViewModel) {
    val nav: NavHostController = rememberNavController()
    val context = LocalContext.current
    val state by vm.state.collectAsStateWithLifecycle()
    val booted by vm.booted.collectAsStateWithLifecycle()
    val error by vm.error.collectAsStateWithLifecycle()
    val isAccessibilityEnabled by vm.isAccessibilityEnabled.collectAsStateWithLifecycle()
    val serviceStale by vm.serviceStale.collectAsStateWithLifecycle()

    // DIR-P3-07: offered once on the first successful pairing (see the
    // PAIR_VERIFY/PAIR_DASHBOARD success handlers below), gated so an
    // already-exempt or previously-dismissed device never sees it again.
    var showBatteryPrompt by remember { mutableStateOf(false) }
    fun maybeOfferBatteryPrompt() {
        val ignoring = BatteryOptimizationUtils.isIgnoringBatteryOptimizations(context)
        val dismissed = BatteryOptimizationUtils.isDismissed(context)
        if (BatteryOptimizationUtils.shouldOfferExemptionPrompt(ignoring, dismissed)) {
            showBatteryPrompt = true
        }
    }

    if (!isAccessibilityEnabled) {
        sn.kaolack.fluxsync.ui.screens.AccessibilityBlockingScreen()
        return
    }

    if (!booted && error == null) {
        Scaffold { padding ->
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Text("Initializing FluxSync engine…", color = sn.kaolack.fluxsync.ui.theme.FsDarkMuted)
            }
        }
        return
    }
    if (error != null) {
        Scaffold { padding ->
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Text("Error: $error")
            }
        }
        return
    }

    val start = Routes.LINKED

    // FS-018: surface transient FFI/daemon errors as a dismissible
    // Snackbar. SnackbarDuration.Short auto-dismisses after ~4s; clear the
    // flow afterwards so the same message can fire again later.
    val transientError by vm.transientError.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(transientError) {
        val msg = transientError ?: return@LaunchedEffect
        snackbarHostState.showSnackbar(msg, duration = SnackbarDuration.Short)
        vm.clearTransientError()
    }

    // Auto-advance to the Linked screen when a peer appears. A peer
    // dropping never triggers navigation — the user keeps their screen.
    androidx.compose.runtime.LaunchedEffect(state?.peerName) {
        val s = state ?: return@LaunchedEffect
        // Only auto-advance from the dashboard. Never yank the user off the
        // scan or SAS-verify screens — FS-052 requires an explicit confirm
        // there, and peerName populates the moment the handshake lands.
        val route = nav.currentBackStackEntry?.destination?.route
        if (s.peerName.isNotEmpty() && route == Routes.PAIR_DASHBOARD) {
            nav.navigate(Routes.LINKED) {
                popUpTo(Routes.PAIR_DASHBOARD) { inclusive = true }
            }
        }
    }

    Box(Modifier.fillMaxSize()) {
    NavHost(navController = nav, startDestination = start) {
        composable(Routes.PAIR_DASHBOARD) {
            PairingDashboardScreen(
                vm = vm,
                onBack = { /* Stay here */ },
                onScan = { nav.navigate(Routes.PAIR_SCAN) },
                onSuccess = {
                    maybeOfferBatteryPrompt()
                    nav.navigate(Routes.LINKED) {
                        popUpTo(Routes.PAIR_DASHBOARD) { inclusive = true }
                    }
                }
            )
        }
        composable(Routes.PAIR_SCAN) {
            PairScanScreen(
                vm = vm,
                // FS-052: a scan only TOFU-trusts; the SAS verify gate decides
                // whether clipboard flows. Hand off to the verify screen.
                onPaired = { nav.navigate(Routes.PAIR_VERIFY) },
                onBack = { nav.popBackStack() },
            )
        }
        composable(Routes.PAIR_VERIFY) {
            PairVerifyScreen(
                vm = vm,
                onConfirmed = {
                    maybeOfferBatteryPrompt()
                    nav.navigate(Routes.LINKED) {
                        popUpTo(Routes.PAIR_DASHBOARD) { inclusive = true }
                    }
                },
                onRejected = {
                    nav.navigate(Routes.PAIR_DASHBOARD) {
                        popUpTo(Routes.PAIR_SCAN) { inclusive = true }
                    }
                },
            )
        }
        composable(Routes.LINKED) {
            LinkedScreen(
                vm = vm,
                onNavigateToPairing = {
                    nav.navigate(Routes.PAIR_DASHBOARD)
                }
            )
        }
    }
        SnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier.align(Alignment.BottomCenter),
        )
        // DIR-P3-07: Settings says the a11y service is ON but it hasn't
        // heartbeated — an OEM kill Settings doesn't reflect. Overlaid at
        // the top so it's visible from any tab; tapping deep-links to the
        // accessibility settings screen to re-bind.
        if (serviceStale) {
            ServiceStaleBanner(
                onTap = { context.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) },
                modifier = Modifier.align(Alignment.TopCenter),
            )
        }
    }

    if (showBatteryPrompt) {
        BatteryExemptionDialog(
            onEnable = {
                context.startActivity(BatteryOptimizationUtils.exemptionIntent(context.packageName))
                showBatteryPrompt = false
            },
            onDismiss = {
                BatteryOptimizationUtils.setDismissed(context)
                showBatteryPrompt = false
            },
        )
    }
}

/**
 * DIR-P3-07: "clipboard service enabled but not running" banner —
 * self-check runs once per `MainActivity.onResume`, no polling loop.
 */
@Composable
private fun ServiceStaleBanner(onTap: () -> Unit, modifier: Modifier = Modifier) {
    Row(
        modifier
            .fillMaxWidth()
            .background(FsWarnSoft)
            .statusBarsPadding()
            .clickable(onClick = onTap)
            .padding(horizontal = 16.dp, vertical = 10.dp),
        horizontalArrangement = Arrangement.Center,
    ) {
        Text(
            "Clipboard service enabled but not running — tap to re-bind",
            color = FsDarkFg,
            style = MaterialTheme.typography.labelSmall,
        )
    }
}

/**
 * DIR-P3-07: offered once after the first successful pairing. "Not now"
 * persists the dismissal (see [BatteryOptimizationUtils.setDismissed]) —
 * the same choice stays reachable manually from Settings afterwards.
 */
@Composable
private fun BatteryExemptionDialog(onEnable: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = FsDarkSurface,
        title = { Text("Keep FluxSync running?", color = FsDarkFg) },
        text = {
            Text(
                "Android may pause background sync to save battery. Exempting FluxSync " +
                    "keeps clipboard sync alive even when the app isn't open. You can change " +
                    "this later in Settings.",
                color = FsDarkMuted,
                style = MaterialTheme.typography.bodySmall,
            )
        },
        confirmButton = {
            TextButton(onClick = onEnable) {
                Text("ENABLE", color = FsAccent)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("NOT NOW", color = FsDarkMuted)
            }
        },
    )
}
