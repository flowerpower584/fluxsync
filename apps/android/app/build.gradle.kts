import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

val gitSha: String = runCatching {
    providers.exec {
        commandLine("git", "rev-parse", "--short", "HEAD")
    }.standardOutput.asText.get().trim()
}.getOrDefault("unknown")

// Release signing (DIR-P4-02). Credentials live in an untracked
// apps/android/keystore.properties (see keystore/README.md) — never
// committed. Falls back to debug signing when that file is absent
// (e.g. a fresh checkout without the owner's keystore) so
// `assembleRelease` still produces an installable, if debug-signed, APK.
val keystorePropsFile = rootProject.file("keystore.properties")
val hasReleaseKeystore = keystorePropsFile.exists()
val keystoreProps = Properties().apply {
    if (hasReleaseKeystore) {
        keystorePropsFile.inputStream().use { load(it) }
    } else {
        logger.warn(
            "apps/android/keystore.properties not found — assembleRelease " +
                "will fall back to debug signing. See keystore/README.md.",
        )
    }
}

android {
    namespace = "sn.kaolack.fluxsync"
    compileSdk = 34

    defaultConfig {
        applicationId = "sn.kaolack.fluxsync"
        minSdk = 26
        targetSdk = 34
        versionCode = 5
        versionName = "0.7.0"
        buildConfigField("String", "GIT_SHA", "\"$gitSha\"")
        ndk {
            // v0.1 supports modern 64-bit ARM only.
            abiFilters += setOf("arm64-v8a")
        }
    }

    signingConfigs {
        if (hasReleaseKeystore) {
            create("release") {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            // No R8/minify yet — FFI/JNA under proguard is untested
            // (explicitly out of scope for DIR-P4-02).
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName(if (hasReleaseKeystore) "release" else "debug")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    testOptions {
        // android.jar ships stubs (org.json, android.util.Log) that
        // throw at runtime; return defaults so plain JVM tests run.
        unitTests.isReturnDefaultValues = true
    }

    sourceSets {
        getByName("main") {
            // Generated UniFFI bindings live alongside the .so; the
            // build script copies both from the workspace target/ dir.
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }

    packaging {
        resources {
            // CameraX + ML Kit pull in duplicate metadata licence files
            // through their transitive deps.
            excludes += setOf(
                "/META-INF/{AL2.0,LGPL2.1}",
                "/META-INF/DEPENDENCIES",
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// Rust FFI build pipeline
//
// `./gradlew assembleDebug` should "just work" — these tasks run the
// `cargo ndk` cross-compile + UniFFI bindgen automatically before the
// Kotlin compiler kicks in. Requires `cargo-ndk` (cargo install
// cargo-ndk) and any Android NDK installed under
// `~/Library/Android/sdk/ndk/`. AGP's `ndkVersion` setting is
// independent — cargo-ndk gets whichever NDK we resolve below.
// ─────────────────────────────────────────────────────────────────
val workspaceRoot = rootProject.projectDir.parentFile.parentFile  // .../fluxsync
val jniLibsDir = file("${projectDir}/src/main/jniLibs")
val javaSrcDir = file("${projectDir}/src/main/java")
val ffiSoPath = file("${jniLibsDir}/arm64-v8a/libfluxsync_mobile_ffi.so")

/**
 * Pick whichever NDK is actually on disk so we don't depend on the
 * specific version AGP defaulted to (which often isn't installed).
 * Search order:
 *   1. `ANDROID_NDK_HOME` env var (developer's explicit pin)
 *   2. `<sdk>/ndk/<highest-version>` from `local.properties`
 *      `sdk.dir` or the conventional macOS path
 *   3. Fail with a helpful message
 */
fun resolveNdkHome(): String {
    System.getenv("ANDROID_NDK_HOME")?.let { envPath ->
        val f = file(envPath)
        if (f.isDirectory) return f.absolutePath
    }

    val sdkDir = file("${System.getProperty("user.home")}/Library/Android/sdk")
    val ndkRoot = file("${sdkDir}/ndk")
    if (ndkRoot.isDirectory) {
        val versions = ndkRoot.listFiles()?.filter { it.isDirectory } ?: emptyList()
        val latest = versions.maxByOrNull { it.name }
        if (latest != null) return latest.absolutePath
    }

    error(
        "No Android NDK found. Install one via Android Studio → " +
            "SDK Manager → SDK Tools → NDK (Side by side), or set " +
            "ANDROID_NDK_HOME to an existing NDK directory.",
    )
}

tasks.register<Exec>("buildRustFfi") {
    group = "fluxsync"
    description = "Cross-compile fluxsync-mobile-ffi for arm64-v8a via cargo-ndk."
    workingDir = workspaceRoot
    // Resolve at execution time (not configuration) so a missing NDK
    // doesn't break `./gradlew tasks`.
    doFirst { environment("ANDROID_NDK_HOME", resolveNdkHome()) }
    // Spawn through `bash -lc` so the developer's shell PATH (rustup,
    // cargo, cargo-ndk) is honored even when Gradle is launched from a
    // GUI context like Android Studio.
    commandLine = listOf(
        "bash", "-lc",
        "PATH=\"\$HOME/.cargo/bin:\$PATH\" cargo ndk -t arm64-v8a -o '${jniLibsDir.absolutePath}' build --release -p fluxsync-mobile-ffi",
    )
    // Track every workspace crate, not just fluxsync-mobile-ffi: the FFI
    // statically links fluxsyncd / fluxsync-core / etc, so a change in any
    // of them must invalidate this task — otherwise the APK ships a stale
    // .so (the build is "successful" but runs old Rust code).
    inputs.dir("${workspaceRoot}/crates")
    outputs.file(ffiSoPath)
}

tasks.register<Exec>("genUniffiBindings") {
    group = "fluxsync"
    description = "Run workspace uniffi-bindgen to emit the Kotlin glue from the .so."
    dependsOn("buildRustFfi")
    workingDir = workspaceRoot
    commandLine = listOf(
        "bash", "-lc",
        "PATH=\"\$HOME/.cargo/bin:\$PATH\" cargo run -p uniffi-bindgen -- generate " +
            "--library '${ffiSoPath.absolutePath}' " +
            "--language kotlin " +
            "--out-dir '${javaSrcDir.absolutePath}'",
    )
    inputs.file(ffiSoPath)
    // The default UniFFI package is `uniffi.<crate-namespace>` =
    // `uniffi.fluxsync_mobile_ffi`. Treating the whole subtree as the
    // task's output keeps Gradle incremental + lets `clean` wipe it.
    outputs.dir("${javaSrcDir}/uniffi")
}

// Wire the Rust pipeline ahead of every Kotlin compile so a fresh
// checkout + `./gradlew assembleDebug` produces a working APK in one
// shot. Both the debug and the release flavors share `preBuild`.
tasks.named("preBuild") {
    dependsOn("genUniffiBindings")
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.09.02")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    // Kotlin/Android core.
    implementation("androidx.core:core-ktx:1.13.1")

    // UniFFI calls into Rust through JNA.
    implementation("net.java.dev.jna:jna:5.14.0@aar")

    // Compose UI stack.
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    // `collectAsStateWithLifecycle` is in -compose, not -ktx.
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
    implementation("androidx.navigation:navigation-compose:2.8.1")

    // QR rendering. ZXing core is the smallest dep that gives us a
    // BitMatrix we can paint with Compose primitives — no AndroidX-only
    // wrappers, ~150 KiB.
    implementation("com.google.zxing:core:3.5.3")

    // QR scanning: CameraX preview + ML Kit barcode (offline model).
    // CameraX 1.4.x ships 16 KB-page-aligned native libs (libimage_processing_util_jni.so),
    // required by Android 15+ — 1.3.4 was not aligned.
    implementation("androidx.camera:camera-core:1.4.1")
    implementation("androidx.camera:camera-camera2:1.4.1")
    implementation("androidx.camera:camera-lifecycle:1.4.1")
    implementation("androidx.camera:camera-view:1.4.1")
    implementation("com.google.mlkit:barcode-scanning:17.3.0")

    // Tooling.
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    // JVM unit tests — no device, no Compose runtime.
    testImplementation("junit:junit:4.13.2")
    // Real org.json: the android.jar copy is a stub that throws.
    testImplementation("org.json:json:20240303")
}
