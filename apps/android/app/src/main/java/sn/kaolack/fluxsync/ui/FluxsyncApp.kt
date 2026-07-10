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
import androidx.compose.ui.text.style.TextAlign
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
    val identityUnreadable by vm.identityUnreadable.collectAsStateWithLifecycle()

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

    // The daemon deliberately refused to boot rather than mint a
    // replacement identity — see FluxsyncAccessibilityService.ensureDaemonAlive
    // and KeystoreIdentityStore.IdentityResult.Unreadable. Blocking here
    // (rather than a dismissible banner) is intentional: proceeding would
    // let the user believe sync is working while every peer silently
    // rejects this device.
    if (identityUnreadable) {
        IdentityUnreadableScreen()
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

    // Auto-advance to the Linked screen when a peer APPEARS — i.e. only on
    // the no-live-peer → live-peer transition, never as a continuous
    // enforcement of "linked means LINKED". A user who is already linked
    // and deliberately opens the pairing dashboard to add another device
    // (multipeer) must not be bounced back by a snapshot whose peerName was
    // live all along, nor by a reconnect flap or mesh primary-name switch
    // (both live→live, no transition). `hadLivePeer == null` (no snapshot
    // observed yet) counts as "was not live", so the very first snapshot
    // carrying a live peer still advances if the user is on the dashboard
    // at that moment. A peer dropping never triggers navigation — the user
    // keeps their screen.
    var hadLivePeer by remember { mutableStateOf<Boolean?>(null) }
    androidx.compose.runtime.LaunchedEffect(state?.peerName) {
        val s = state ?: return@LaunchedEffect
        val hasLivePeer = s.peerName.isNotEmpty()
        val wasLive = hadLivePeer ?: false
        hadLivePeer = hasLivePeer
        if (!hasLivePeer || wasLive) return@LaunchedEffect
        // Only auto-advance from the dashboard — the sole pairing route
        // besides scan/verify. Never yank the user off the scan or
        // SAS-verify screens: FS-052 requires an explicit confirm there,
        // and peerName populates the moment the handshake lands.
        val route = nav.currentBackStackEntry?.destination?.route
        if (route == Routes.PAIR_DASHBOARD) {
            nav.navigate(Routes.LINKED) {
                popUpTo(Routes.LINKED) { inclusive = true }
            }
        }
    }

    // Symmetric re-verify (Msg::PairVerifyStarted, cap "verify-restart") and
    // responder-side TOFU: the daemon can (re)start a SAS flow while the app
    // sits anywhere — e.g. on LINKED after an already_paired short-circuit
    // against a peer that was reset and now announces fresh verify words.
    // Route to the verify screen so the words actually show. Same FS-052
    // rule as above: never yank the user OFF the scan/verify screens —
    // navigating TO verify is the whole point here. Loop safety: the effect
    // is keyed on the sasPhase *string*, so it restarts exactly once per
    // phase transition (state snapshots with an unchanged phase do not
    // re-run it), and the route check makes a re-run while already on
    // scan/verify a no-op.
    androidx.compose.runtime.LaunchedEffect(state?.sasPhase) {
        if (state?.sasPhase != "showing") return@LaunchedEffect
        val route = nav.currentBackStackEntry?.destination?.route
        if (route == Routes.PAIR_SCAN || route == Routes.PAIR_VERIFY) return@LaunchedEffect
        nav.navigate(Routes.PAIR_VERIFY) { launchSingleTop = true }
    }

    Box(Modifier.fillMaxSize()) {
    NavHost(navController = nav, startDestination = start) {
        composable(Routes.PAIR_DASHBOARD) {
            PairingDashboardScreen(
                vm = vm,
                // Backing out of an add-device visit returns to Linked (the
                // start destination is always underneath). No-op if the
                // stack has nothing to pop.
                onBack = { nav.popBackStack() },
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
                // The daemon reported `already_paired`: it took a silent
                // reconnect path with no fresh SAS to verify, so skip the
                // verify screen entirely and go straight to Linked.
                onAlreadyPaired = {
                    nav.navigate(Routes.LINKED) {
                        popUpTo(Routes.PAIR_DASHBOARD) { inclusive = true }
                    }
                },
                onBack = { nav.popBackStack() },
            )
        }
        composable(Routes.PAIR_VERIFY) {
            PairVerifyScreen(
                vm = vm,
                // Both exits anchor popUpTo on LINKED (the start destination,
                // always at the bottom of the stack) so they produce a clean
                // back stack from EITHER entry path — the normal
                // dashboard→scan→verify flow, or the direct LINKED→verify
                // hop the sasPhase router above takes on a re-verify.
                // Anchoring on PAIR_DASHBOARD/PAIR_SCAN (as before) was a
                // no-op popUpTo on the LINKED→verify path and left a stale
                // verify screen underneath for the back button to find.
                onConfirmed = {
                    maybeOfferBatteryPrompt()
                    nav.navigate(Routes.LINKED) {
                        popUpTo(Routes.LINKED) { inclusive = true }
                    }
                },
                onRejected = {
                    nav.navigate(Routes.PAIR_DASHBOARD) {
                        popUpTo(Routes.LINKED) { inclusive = false }
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
 * Shown instead of the normal app when the stored identity exists but
 * could not be decrypted (corrupted `identity.enc`, or an AndroidKeyStore
 * key that didn't survive a factory-reset/restore-to-new-device). FluxSync
 * refuses to auto-generate a replacement identity because that would
 * silently disconnect every paired peer with no signal to the user — this
 * screen IS that signal. Recovery requires the user to deliberately clear
 * the app's storage (Settings → Apps → FluxSync → Storage → Clear data)
 * and re-pair every device.
 */
@Composable
private fun IdentityUnreadableScreen() {
    Scaffold { padding ->
        Box(
            Modifier.fillMaxSize().padding(padding).padding(24.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                "FluxSync can't read its saved device identity. This can happen after a " +
                    "factory reset or restoring to a new device.\n\n" +
                    "To avoid silently disconnecting your paired devices, FluxSync will not " +
                    "generate a replacement automatically.\n\n" +
                    "Clear FluxSync's app storage in Android Settings, then re-pair your devices.",
                textAlign = TextAlign.Center,
            )
        }
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
