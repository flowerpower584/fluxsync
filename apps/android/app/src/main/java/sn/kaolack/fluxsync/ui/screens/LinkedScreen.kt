package sn.kaolack.fluxsync.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import sn.kaolack.fluxsync.ui.Routes
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
                    Routes.SETTINGS -> "Settings"
                    else -> "FluxSync"
                },
                subtitle = when(currentRoute) {
                    Routes.HOME -> "v0.5.0 · android"
                    Routes.DEVICES -> "paired peers"
                    Routes.LOGS -> "live stream"
                    Routes.SETTINGS -> "preferences"
                    else -> "v0.5.0 · android"
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
            composable(Routes.SETTINGS) { SettingsScreen(vm) }
        }
    }
}

@Composable
private fun AppBar(title: String, subtitle: String, on: Boolean) {
    Column {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(FsDarkBg)
                .padding(horizontal = 20.dp)
                .padding(top = 18.dp, bottom = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                // Tray glyph: simulated as in the spec
                Box(
                    Modifier
                        .size(18.dp)
                        .border(width = 1.dp, color = if (on) FsCrit else FsDarkBorderStrong, shape = RoundedCornerShape(2.dp)),
                    contentAlignment = Alignment.Center,
                ) {
                    if (on) {
                        Box(Modifier.size(6.dp).background(FsOk, RoundedCornerShape(50)))
                    }
                }
                Column {
                    Text(title, color = FsDarkFg, style = MaterialTheme.typography.titleMedium)
                    Text(subtitle.uppercase(), color = FsDarkSubtle, style = MaterialTheme.typography.labelSmall, fontSize = 9.sp)
                }
            }
        }
        HorizontalDivider(thickness = 1.dp, color = FsDarkBorder)
    }
}

@Composable
private fun BottomNav(currentRoute: String, onNavigate: (String) -> Unit) {
    Column {
        HorizontalDivider(thickness = 1.dp, color = FsDarkBorder)
        NavigationBar(
            containerColor = FsDarkSurface,
            tonalElevation = 0.dp,
            modifier = Modifier.height(72.dp)
        ) {
            val tabs = listOf(
                TabItem(Routes.HOME, "Home", "home"),
                TabItem(Routes.DEVICES, "Devices", "devices"),
                TabItem(Routes.LOGS, "Logs", "logs"),
                TabItem(Routes.SETTINGS, "Settings", "settings")
            )

            tabs.forEach { tab ->
                val active = currentRoute == tab.id
                NavigationBarItem(
                    selected = active,
                    onClick = { onNavigate(tab.id) },
                    icon = {
                        TabIcon(
                            id = tab.icon,
                            color = if (active) FsCrit else FsDarkMuted,
                        )
                    },
                    label = {
                        Text(
                            tab.label.uppercase(),
                            color = if (active) FsCrit else FsDarkMuted,
                            style = MaterialTheme.typography.labelSmall,
                            fontSize = 9.sp
                        )
                    },
                    colors = NavigationBarItemDefaults.colors(
                        indicatorColor = Color.Transparent
                    )
                )
            }
        }
    }
}

private data class TabItem(val id: String, val label: String, val icon: String)
