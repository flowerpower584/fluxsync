package sn.kaolack.fluxsync.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import sn.kaolack.fluxsync.ui.screens.LinkedScreen
import sn.kaolack.fluxsync.ui.screens.PairingDashboardScreen
import sn.kaolack.fluxsync.ui.screens.PairScanScreen
import sn.kaolack.fluxsync.ui.screens.PairVerifyScreen
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
    const val SETTINGS = "settings"
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
    val state by vm.state.collectAsStateWithLifecycle()
    val booted by vm.booted.collectAsStateWithLifecycle()
    val error by vm.error.collectAsStateWithLifecycle()
    val isAccessibilityEnabled by vm.isAccessibilityEnabled.collectAsStateWithLifecycle()

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
    }
}
