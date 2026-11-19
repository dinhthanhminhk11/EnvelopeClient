import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.cem.doodleart.sample"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.cem.doodleart.sample"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        // Sent as X-App-Version and signed into the handshake: digits and dots (see src/envelope/validate.rs).
        versionName = "1.0.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
            // A sample: sign the release build with the debug key so it installs. Use your own signing config.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    packaging {
        // Keep the core's .so stored uncompressed and page-aligned in the APK (it is built 16 KB aligned).
        jniLibs.useLegacyPackaging = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(project(":security"))
}
