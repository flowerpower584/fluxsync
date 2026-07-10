package sn.kaolack.fluxsync.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import kotlinx.coroutines.launch
import sn.kaolack.fluxsync.ui.theme.FsAccent
import sn.kaolack.fluxsync.ui.theme.FsCardFlat
import sn.kaolack.fluxsync.ui.theme.FsDarkBg
import sn.kaolack.fluxsync.ui.theme.FsDarkBorder
import sn.kaolack.fluxsync.ui.theme.FsDarkFg
import sn.kaolack.fluxsync.ui.theme.FsDarkMuted
import sn.kaolack.fluxsync.ui.theme.FsOnAccent
import sn.kaolack.fluxsync.ui.theme.FsRadius
import sn.kaolack.fluxsync.ui.theme.FsSans
import sn.kaolack.fluxsync.vm.FluxsyncViewModel

/**
 * Camera flow. ML Kit's offline QR decoder runs against every CameraX
 * frame; the first frame whose payload starts with `fluxsync://pair/`
 * is fed to `vm.pairFromUri(...)` and we pop back to Linked. The
 * dark theme + 1px outline cap match the rest of the design system.
 */
@Composable
fun PairScanScreen(
    vm: FluxsyncViewModel,
    onPaired: () -> Unit,
    onAlreadyPaired: () -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    var hasPerm by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA)
                == PackageManager.PERMISSION_GRANTED
        )
    }
    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted -> hasPerm = granted }

    LaunchedEffect(Unit) {
        if (!hasPerm) launcher.launch(Manifest.permission.CAMERA)
    }

    Column(
        Modifier
            .fillMaxSize()
            .background(FsDarkBg),
    ) {
        Header(onBack)
        if (!hasPerm) {
            PermissionPrompt(onRequest = { launcher.launch(Manifest.permission.CAMERA) })
        } else {
            ScannerView(vm = vm, onPaired = onPaired, onAlreadyPaired = onAlreadyPaired)
        }
    }
}

@Composable
private fun Header(onBack: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(FsDarkBg)
            .statusBarsPadding()
            .padding(horizontal = 18.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box(
            Modifier
                .size(30.dp)
                .clip(RoundedCornerShape(FsRadius.IconMd))
                .border(1.dp, FsDarkBorder, RoundedCornerShape(FsRadius.IconMd))
                .background(FsCardFlat, RoundedCornerShape(FsRadius.IconMd))
                .clickable(onClick = onBack),
            contentAlignment = Alignment.Center,
        ) {
            Text("←", color = FsDarkMuted, fontSize = 15.sp)
        }
        Text("Scan peer", color = FsDarkFg, fontFamily = FsSans, fontWeight = FontWeight.Bold, fontSize = 16.sp)
    }
}

@Composable
private fun PermissionPrompt(onRequest: () -> Unit) {
    Column(
        Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            "Camera permission",
            color = FsDarkFg,
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(Modifier.height(6.dp))
        Text(
            "FluxSync needs the camera to scan the pair QR. Nothing is recorded; frames are decoded on-device by ML Kit.",
            color = FsDarkMuted,
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.height(20.dp))
        Box(
            Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(FsRadius.Btn))
                .background(FsAccent)
                .clickable(onClick = onRequest)
                .padding(horizontal = 16.dp, vertical = 13.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                "Grant permission",
                color = FsOnAccent,
                fontFamily = FsSans,
                fontWeight = FontWeight.Bold,
                fontSize = 13.sp,
            )
        }
    }
}

@Composable
private fun ScannerView(vm: FluxsyncViewModel, onPaired: () -> Unit, onAlreadyPaired: () -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    var detected by remember { mutableStateOf(false) }

    val cameraProviderFuture = remember { ProcessCameraProvider.getInstance(context) }
    var provider by remember { mutableStateOf<ProcessCameraProvider?>(null) }
    
    LaunchedEffect(cameraProviderFuture) {
        cameraProviderFuture.addListener({
            try {
                provider = cameraProviderFuture.get()
            } catch (e: Exception) {
                android.util.Log.e("FluxSync", "Camera provider error: ${e.message}")
            }
        }, androidx.core.content.ContextCompat.getMainExecutor(context))
    }
    
    DisposableEffect(provider) {
        onDispose { runCatching { provider?.unbindAll() } }
    }

    val scanner = remember {
        BarcodeScanning.getClient(
            BarcodeScannerOptions.Builder()
                .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                .build()
        )
    }

    val analyzer = remember {
        ImageAnalysis.Builder()
            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
            .build()
    }

    val previewView = remember { PreviewView(context) }
    val preview = remember { Preview.Builder().build() }
    
    LaunchedEffect(provider, previewView) {
        val p = provider ?: return@LaunchedEffect
        
        try {
            p.unbindAll()
            preview.setSurfaceProvider(previewView.surfaceProvider)
            
            analyzer.setAnalyzer(ContextCompat.getMainExecutor(context)) { proxy ->
                if (detected) {
                    proxy.close()
                    return@setAnalyzer
                }
                processFrame(proxy, scanner) { uri ->
                    detected = true
                    scope.launch {
                        // already_paired means the daemon took a silent
                        // reconnect path — there is no fresh SAS pending
                        // pair to verify, so the verify screen must not
                        // be entered (its `pairPending` poll would come up
                        // empty and strand the user on that gate forever).
                        val alreadyPaired = vm.pairFromUri(uri, "Peer")
                        if (alreadyPaired) {
                            onAlreadyPaired()
                        } else {
                            onPaired()
                        }
                    }
                }
            }
            
            p.bindToLifecycle(
                lifecycleOwner,
                CameraSelector.DEFAULT_BACK_CAMERA,
                preview,
                analyzer,
            )
        } catch (e: Exception) {
            android.util.Log.e("FluxSync", "Binding failed: ${e.message}")
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 16.dp),
    ) {
        Box(
            Modifier
                .fillMaxWidth()
                .aspectRatio(1f)
                .border(1.dp, FsDarkBorder, RoundedCornerShape(12.dp))
                .clip(RoundedCornerShape(12.dp))
                .background(Color(0xFF101015), RoundedCornerShape(12.dp)),
        ) {
            if (provider != null) {
                AndroidView(
                    modifier = Modifier.fillMaxSize(),
                    factory = { previewView },
                    update = {}
                )
            } else {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("Starting camera…", color = FsDarkMuted, style = MaterialTheme.typography.labelSmall)
                }
            }
            ScanCorners()
        }
        Spacer(Modifier.height(14.dp))
        Text(
            "Align the QR inside the frame",
            color = FsDarkMuted,
            fontFamily = FsSans,
            fontSize = 11.5.sp,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

/** Four green viewfinder corners, `.scan-box .corner` in the mockup. */
@Composable
private fun ScanCorners() {
    androidx.compose.foundation.Canvas(Modifier.fillMaxSize()) {
        val m = 14.dp.toPx()
        val len = 26.dp.toPx()
        val sw = 2.5.dp.toPx()
        val c = FsAccent
        val w = size.width
        val h = size.height
        // top-left
        drawLine(c, Offset(m, m), Offset(m + len, m), sw)
        drawLine(c, Offset(m, m), Offset(m, m + len), sw)
        // top-right
        drawLine(c, Offset(w - m, m), Offset(w - m - len, m), sw)
        drawLine(c, Offset(w - m, m), Offset(w - m, m + len), sw)
        // bottom-left
        drawLine(c, Offset(m, h - m), Offset(m + len, h - m), sw)
        drawLine(c, Offset(m, h - m), Offset(m, h - m - len), sw)
        // bottom-right
        drawLine(c, Offset(w - m, h - m), Offset(w - m - len, h - m), sw)
        drawLine(c, Offset(w - m, h - m), Offset(w - m, h - m - len), sw)
    }
}

@OptIn(androidx.camera.core.ExperimentalGetImage::class)
private fun processFrame(
    proxy: ImageProxy,
    scanner: com.google.mlkit.vision.barcode.BarcodeScanner,
    onUri: (String) -> Unit,
) {
    val media = proxy.image
    if (media == null) {
        proxy.close()
        return
    }
    val img = InputImage.fromMediaImage(media, proxy.imageInfo.rotationDegrees)
    scanner.process(img)
        .addOnSuccessListener { barcodes ->
            val raw = barcodes.firstOrNull { it.format == Barcode.FORMAT_QR_CODE }?.rawValue
            if (raw != null && raw.startsWith("fluxsync://pair/")) {
                onUri(raw)
            }
        }
        .addOnCompleteListener { proxy.close() }
}
