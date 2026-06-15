package sn.kaolack.fluxsync.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import sn.kaolack.fluxsync.ui.Routes
import sn.kaolack.fluxsync.ui.components.E2EBadge
import sn.kaolack.fluxsync.ui.components.LoadingState
import sn.kaolack.fluxsync.ui.components.TabIcon
import sn.kaolack.fluxsync.ui.theme.*
import sn.kaolack.fluxsync.vm.FluxsyncViewModel

/**
 * The main container for the linked state.
 * Handles the persistent AppBar, BottomNavigationBar, and the NavHost for the 4 tabs.
 */
@Composable
fun LinkedScreen(vm: FluxsyncViewModel, onNavigateToPairing: () -> Unit) {
    val innerNav = rememberNavController()
    val state by vm.state.collectAsStateWithLifecycle()
    val s = state
    if (s == null) {
        LoadingState()
        return
    }

    val navBackStackEntry by innerNav.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route ?: Routes.HOME

    Scaffold(
        topBar = {
            AppBar(
                title = when(currentRoute) {
                    Routes.HOME -> "FluxSync"
                    Routes.DEVICES -> "Devices"
                    Routes.LOGS -> "Activity"
                    Routes.FIREWALL -> "Firewall"
                    Routes.SETTINGS -> "Settings"
                    else -> "FluxSync"
                },
                subtitle = when(currentRoute) {
                    Routes.HOME -> "v${sn.kaolack.fluxsync.BuildConfig.VERSION_NAME} · android"
                    Routes.DEVICES -> "paired peers"
                    Routes.LOGS -> "live stream"
                    Routes.FIREWALL -> "policies & decisions"
                    Routes.SETTINGS -> "preferences"
                    else -> "v${sn.kaolack.fluxsync.BuildConfig.VERSION_NAME} · android"
                },
                on = s.active,
            )
        },
        bottomBar = {
            BottomNav(currentRoute) { route ->
                innerNav.navigate(route) {
                    popUpTo(Routes.HOME) { saveState = true }
                    launchSingleTop = true
                    restoreState = true
                }
            }
        },
        containerColor = FsDarkBg
    ) { padding ->
        NavHost(
            navController = innerNav,
            startDestination = Routes.HOME,
            modifier = Modifier.padding(padding)
        ) {
            composable(Routes.HOME) { HomeScreen(vm) }
            composable(Routes.DEVICES) { DevicesScreen(vm, onAddDevice = onNavigateToPairing) }
            composable(Routes.LOGS) { LogsScreen(vm) }
            composable(Routes.FIREWALL) { FirewallScreen(vm) }
            composable(Routes.SETTINGS) { SettingsScreen(vm) }
        }
    }
}

@Composable
private fun AppBar(title: String, subtitle: String, on: Boolean) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(FsDarkBg)
            .statusBarsPadding()
            .padding(horizontal = 18.dp)
            .padding(top = 14.dp, bottom = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column {
            Text(title, color = FsDarkFg, style = FsHeader)
            Text(subtitle, color = FsDarkSubtle, fontFamily = FsMono, fontSize = 9.sp)
        }
        E2EBadge()
    }
}

@Composable
private fun BottomNav(currentRoute: String, onNavigate: (String) -> Unit) {
    val shape = RoundedCornerShape(FsRadius.Nav)
    Row(
        Modifier
            .fillMaxWidth()
            .background(FsDarkBg)
            .navigationBarsPadding()
            .padding(horizontal = 14.dp)
            .padding(bottom = 10.dp, top = 4.dp)
            .border(1.dp, FsDarkBorder, shape)
            .background(FsCard, shape)
            .padding(vertical = 9.dp),
    ) {
        val tabs = listOf(
            TabItem(Routes.HOME, "Home", "home"),
            TabItem(Routes.DEVICES, "Devices", "devices"),
            TabItem(Routes.LOGS, "Logs", "logs"),
            TabItem(Routes.FIREWALL, "Firewall", "firewall"),
            TabItem(Routes.SETTINGS, "Settings", "settings")
        )

        tabs.forEach { tab ->
            val active = currentRoute == tab.id
            val tint = if (active) FsAccent else FsDarkSubtle
            Column(
                Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(12.dp))
                    .clickable { onNavigate(tab.id) }
                    .padding(vertical = 2.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                TabIcon(id = tab.icon, color = tint, modifier = Modifier.size(15.dp))
                Text(
                    tab.label,
                    color = tint,
                    fontFamily = FsSans,
                    fontWeight = FontWeight.W600,
                    fontSize = 9.5.sp,
                )
            }
        }
    }
}

private data class TabItem(val id: String, val label: String, val icon: String)
