import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

// The Rust crate is the parent of the Gradle root (android/..).
val crateDir: File = rootDir.parentFile
val coreBuildType: String = providers.gradleProperty("envelope.core.buildType").getOrElse("debug")
val coreAutoBuild: Boolean = providers.gradleProperty("envelope.core.autoBuild").map(String::toBoolean).getOrElse(true)
val coreJniLibs: File = crateDir.resolve("target/jniLibs/$coreBuildType")
val cargoBin: String = File(System.getProperty("user.home"), ".cargo/bin").absolutePath

require(coreBuildType in setOf("debug", "qa", "release")) {
    "envelope.core.buildType must be debug, qa or release (got $coreBuildType)"
}

android {
    namespace = "com.cem.doodleart.security"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    // libdoodleart_core.so for every ABI, written by ../build-android.sh.
    sourceSets["main"].jniLibs.srcDir(coreJniLibs)

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}

val sdkDirectory = androidComponents.sdkComponents.sdkDirectory

// Android libraries (arm64-v8a, armeabi-v7a, x86_64) through cargo-ndk.
val buildRustCore by tasks.registering(Exec::class) {
    group = "build"
    description = "Builds libdoodleart_core.so ($coreBuildType) with ../build-android.sh"
    onlyIf { coreAutoBuild }
    workingDir = crateDir
    commandLine(crateDir.resolve("build-android.sh").absolutePath, coreBuildType, "--out", coreJniLibs.absolutePath)
    inputs.dir(crateDir.resolve("src"))
    inputs.dir(crateDir.resolve("config"))
    inputs.files(
        crateDir.resolve("Cargo.toml"),
        crateDir.resolve("Cargo.lock"),
        crateDir.resolve("build.rs"),
        crateDir.resolve("build-android.sh"),
    )
    outputs.dir(coreJniLibs)
    doFirst {
        // Android Studio started from the Dock does not inherit the shell PATH.
        environment("PATH", "$cargoBin${File.pathSeparator}${System.getenv("PATH")}")
        environment("ANDROID_HOME", sdkDirectory.get().asFile.absolutePath)
    }
}

// Host library (target/debug/libdoodleart_core.{so,dylib}) for the JVM unit tests: a plain host build keeps
// JNI_OnLoad, so the same NativeCore object loads it.
val buildRustHostCore by tasks.registering(Exec::class) {
    group = "build"
    description = "Builds the host library of the Rust core for the JVM unit tests"
    onlyIf { coreAutoBuild }
    workingDir = crateDir
    commandLine("cargo", "build", "--lib", "--locked")
    environment("PATH", "$cargoBin${File.pathSeparator}${System.getenv("PATH")}")
    // obfstr reads its seed from the environment; build.rs warns when it differs from config/project.conf.
    val seed = crateDir.resolve("config/project.conf").readLines()
        .map { it.substringBefore('#').trim() }
        .lastOrNull { it.startsWith("OBFSTR_SEED") }
        ?.substringAfter('=')?.trim()
    if (!seed.isNullOrEmpty()) environment("OBFSTR_SEED", seed)
    inputs.dir(crateDir.resolve("src"))
    inputs.dir(crateDir.resolve("config"))
    inputs.files(crateDir.resolve("Cargo.toml"), crateDir.resolve("Cargo.lock"), crateDir.resolve("build.rs"))
    outputs.dir(crateDir.resolve("target/debug"))
}

tasks.named("preBuild") { dependsOn(buildRustCore) }

tasks.withType<Test>().configureEach {
    dependsOn(buildRustHostCore)
    systemProperty("java.library.path", crateDir.resolve("target/debug").absolutePath)
}
