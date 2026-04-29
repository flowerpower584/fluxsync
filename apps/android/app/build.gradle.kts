plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "sn.kaolack.fluxsync"
    compileSdk = 34

    defaultConfig {
        applicationId = "sn.kaolack.fluxsync"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.4.2"
        ndk {
            // v0.1 supports modern 64-bit ARM only.
            abiFilters += setOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    sourceSets {
        getByName("main") {
            // Generated UniFFI bindings live alongside the .so; the
            // build script copies both from the workspace target/ dir.
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("net.java.dev.jna:jna:5.14.0@aar")
}
