plugins {
    id("com.android.application") version "8.5.0" apply false
    id("org.jetbrains.kotlin.android") version "2.0.0" apply false
    // Kotlin 2.0+ ships the Compose compiler as a standalone Gradle
    // plugin instead of bundling it with `kotlin-android`. Must match
    // the kotlin version exactly.
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.0" apply false
}
