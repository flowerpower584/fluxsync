// FluxSync Android skeleton.
//
// v0.1 ships only the loader stub: it pulls libfluxsync_mobile_ffi.so
// out of `app/src/main/jniLibs/<abi>/` and prints the daemon's first
// state JSON to logcat. A real Compose UI lands in v0.1.1.

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "FluxSync"
include(":app")
