# Envelope Client

A client-side security core for mobile apps, written in Rust. One crate builds the native library for **iOS** (C ABI,
`DoodleArtCore.xcframework`) and **Android** (JNI, `libdoodleart_core.so`) and speaks **envelope v1**: an end-to-end
encrypted, replay-protected session between an app and its API server, on top of TLS.

> The crate keeps its original name, `doodleart-core`: C functions use the `doodleart_` prefix, the Swift module is
> `DoodleArtCore` and the Android binding lives in `com.cem.doodleart.security`.

## Features

- **Device registration**: a P-256 device key that never leaves the Secure Enclave / Android Keystore signs a server
  challenge. The hash of the signed message is ready to bind an App Attest or Play Integrity token.
- **Handshake**: an ephemeral X25519 key per session, a device signature over the handshake, a server Ed25519 signature
  over the transcript checked against keys embedded at build time, HKDF-SHA256 session keys.
- **Sealed requests and responses**: ChaCha20-Poly1305. The AAD binds method, path and query, session id, sequence
  number, timestamp and app version (requests) or HTTP status and content encoding (responses). Each response opens
  once; gzip responses are decoded inside the core.
- **Integrity hashes** for per-request attestation.
- **Device signals (Android)**: hashed ANDROID_ID, Widevine id and hardware fingerprint. Raw values never leave the call.
- **Runtime risk detection**: Frida, hooks, root / jailbreak, emulator / simulator, debugger, re-signed APK. Reported as
  flags signed into the handshake; the core never crashes or blocks the app, the server decides what to trust.
- **Hardened builds**: LTO, stripped symbols, obfuscated strings, remapped source paths, 16 KB page alignment, and a
  check of the exports and imports of every library produced.

## Repository layout

| Path | Contents |
|---|---|
| `src/` | The crate: `envelope/` (protocol), `api.rs` (byte API shared by both platforms), `jni.rs` (Android), `ffi.rs` (iOS), `risk/`, `device_signals.rs`, `apk_identity.rs` |
| `include/` | C header `doodleart_core.h` and module map for Swift |
| `swift/Sources/` | Swift sample: C ABI bridge, Secure Enclave identity, App Attest, `SecureChannel` |
| `android/` | Android sample: `:security` library (Kotlin bridge, Keystore identity, `SecureChannel`) and the `:app` demo |
| `config/` | Build configuration: server public keys per build type, project seed and salt, APK certificate allowlists |
| `build-android.sh`, `build-ios.sh` | Release builds of the native libraries |
| `tools/` | Library checks (`check-so.sh`, `check-macho.sh`), C ABI smoke test, Swift harness |
| `tests/` | C ABI smoke tests, fixtures, Swift harness |

## Requirements

- Rust 1.85 or newer.
- Android: targets `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`; `cargo install cargo-ndk`;
  Android NDK r27 or newer; JDK 17 and the Android SDK (API 36) for the sample.
- iOS: targets `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`, `aarch64-apple-darwin` and the
  `llvm-tools` component; Xcode for the xcframework.

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk
```

## Android

### Run the sample

```bash
cd android
./gradlew :app:assembleDebug
```

Gradle runs `../build-android.sh` first, so one command builds `libdoodleart_core.so` for `arm64-v8a`, `armeabi-v7a` and
`x86_64` and packs it into `android/app/build/outputs/apk/debug/app-debug.apk`. Install it with
`./gradlew :app:installDebug`.

- **Run local checks** calls everything that needs no server: build info, Keystore device key, registration message,
  handshake body, integrity hash, risk scan, device signals.
- **Send sealed request** goes through `SecureChannel` (register, handshake, seal, open) against the server URL you
  type. It needs a server that speaks envelope v1 and whose public key is embedded in the library (see
  [Server keys](#server-keys)).

Settings in `android/gradle.properties`:

| Property | Default | Meaning |
|---|---|---|
| `envelope.core.buildType` | `debug` | Build type of the core: `debug`, `qa` or `release` (selects the embedded server keys) |
| `envelope.core.autoBuild` | `true` | `false` skips the Rust build and uses the libraries already in `target/jniLibs/<buildType>` |

`./gradlew :security:testDebugUnitTest` runs the Kotlin bridge on the JVM against a host build of the core, so a
mismatch between Kotlin and `src/jni.rs` fails before any APK is built.

### Use it in an app

Copy or depend on `android/security`, then send requests through one `SecureChannel` per server:

```kotlin
val channel = SecureChannel(context)   // keep one for the app's lifetime

// Blocking: call it from a background thread.
val response = channel.send(
    HttpRequest(
        url = "https://api.example.com/api/v2/me",
        headers = mapOf("Accept" to "application/json", "X-App-Version" to appVersion),
    ),
)
val json = response.body.toString(Charsets.UTF_8)   // plaintext {meta, data} of the route
```

`send` throws `SecureChannelException.Unavailable` (no session can be opened now), `Untrusted` (tampered or replayed
answer), `UpgradeRequired` (HTTP 426) or `Maintenance` (HTTP 503). Plug in your HTTP client with `SecureTransport` and
your Play Integrity tokens with `IntegrityProvider`. `CoreBridge` exposes every native call with Kotlin types when you
need a lower level.

The JNI class name is part of the binary contract: `JNI_OnLoad` registers the natives of
`com.cem.doodleart.security.NativeCore`. To move it, change `class_name()` and the table in `src/jni.rs` together with
the Kotlin file; `cargo test` compares them.

## iOS

```bash
./build-ios.sh debug                                    # DoodleArtCore.xcframework (needs Xcode)
./build-ios.sh debug --no-xcframework --install <dir>   # static slices + include/ (Command Line Tools are enough)
tools/c-abi-smoke.sh debug                              # C, C++, Objective-C and Swift call the C ABI
```

With `--install`, point `SWIFT_INCLUDE_PATHS` at `<dir>/debug/include` and `LIBRARY_SEARCH_PATHS` at the slice of each
SDK and architecture; `import DoodleArtCore` links the library. `include/doodleart_core.h` documents the C ABI (reply
format, buffer ownership, blocking calls). `swift/Sources/` is a Swift sample over it (`CoreBridge`, `DeviceIdentity`,
`AppAttest`, `SecureChannel`); `tools/swift-harness.sh` runs it on macOS against a local server.

## Configuration

### Server keys

The library only trusts the server Ed25519 public keys embedded at build time, one file per build type:

| Build type | File | State in this repository |
|---|---|---|
| `debug` | `config/server-keys.debug.conf` | Placeholder key (private half discarded): replace it with your development server's |
| `qa` | `config/server-keys.qa.conf` | `REPLACE_...` placeholders: the build stops until you fill them |
| `release` | `config/server-keys.release.conf` | `REPLACE_...` placeholders: the build stops until you fill them |

Each file holds `current.kid` / `current.public_key` (64 lowercase hex characters) and an optional `next.*` key for
rotation. Public keys only: the private key stays on the server. `DOODLEART_SERVER_KEYS_FILE` overrides the file for one
build. Every environment needs its own key pair.

### Project configuration

`config/project.conf` sets `PROJECT_ID`, the string obfuscation seed `OBFSTR_SEED`, the source path remapping key
`REMAP_SALT` and the APK signing-certificate allowlists of the release and QA builds. **The seed and salt in this
repository are samples.** For a shipped app, generate your own and keep that copy of the file out of git:

```bash
LC_ALL=C tr -dc 'A-Za-z0-9_-' </dev/urandom | head -c 32; echo   # OBFSTR_SEED
openssl rand -hex 16                                              # REMAP_SALT
DOODLEART_PROJECT_CONF=/path/to/project.conf ./build-android.sh debug
```

A release build with another project file also needs `DOODLEART_PROJECT_CONF_ALLOW_RELEASE=1` (rules at the top of
`build.rs`).

### APK certificates

The core reads the signing certificate of the installed APK and reports `apk_resigned` when it is not on the allowlist
of its build type. Debug digests go in `config/debug-certs.conf`, one line per development machine:

```bash
keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android | grep SHA256
```

Until you add yours, a debug build signed on your machine reports `apk_resigned` in its risk flags, which is expected.

## Native API

Both platforms share one byte API (`src/api.rs`):

- Every reply is `status (1 byte) || payload`. Multi-value payloads are `frame(...)`: for each field a big-endian u32
  length, then the bytes; numbers are 8-byte big-endian fields.
- Handshakes and sessions are random 63-bit handles, never pointers; unknown or consumed handles are refused.
- All calls are thread-safe. `handshakeBegin` and `riskScan` scan the process: keep them off the main thread.

| Status | Name | Status | Name |
|---|---|---|---|
| 0 | `OK` | 8 | `REPLAYED_RESPONSE` |
| 1 | `INVALID_ARGUMENT` | 9 | `SEQ_EXHAUSTED` |
| 2 | `UNKNOWN_HANDLE` | 10 | `SESSION_EXPIRED` |
| 3 | `HANDSHAKE_STATE` | 11 | `LIMIT_REACHED` |
| 4 | `BAD_SERVER_RESPONSE` | 12 | `RNG` |
| 5 | `BAD_SERVER_SIGNATURE` | 13 | `INTERNAL` |
| 6 | `SERVER_REJECTED` | 14 | `UNSEALED_RESPONSE` |
| 7 | `DECRYPT_FAILED` | | |

## Server side

This repository holds the client only. A compatible server implements, under one route prefix (`api/v2` in the
samples): `POST auth/challenge`, `POST devices/register` and `POST session/start` as plain JSON, then accepts sealed
requests (`Content-Type: application/vnd.doodle.sealed`, headers `X-Tx-Session`, `X-Tx-Seq`, `X-Tx-Ts`,
`X-App-Version`, and `X-Tx-Tag` for bodyless requests) and answers them sealed (`X-Tx-Encoding` when compressed). The
exact byte layouts of every signed message, transcript and AAD are in `src/envelope/wire.rs`.

## Tests

```bash
cargo test
DOODLEART_SERVER_KEYS_FILE=tests/fixtures/server-keys.release-test.conf \
  cargo test --no-default-features --features build-release
(cd android && ./gradlew :security:testDebugUnitTest)
```

`cargo test` warns unless `OBFSTR_SEED` matches `config/project.conf`. The protocol vector tests and the interop
tests (`envelope::vector_tests`, `interop_tests`, and the parts of `api`, `ffi` and `integrity_hash` that use the same
vectors) read test vectors and a Go peer from the reference server repository, expected at `../server`. That repository
is not part of this one: without it, those tests fail.

## Security

- Only public keys are embedded; device private keys stay in the Secure Enclave or the Android Keystore.
- Risk detection only reports. Nothing in the core exits, crashes or refuses to work because of a detection.
- Please report vulnerabilities privately through GitHub's "Report a vulnerability" (Security tab), not in a public
  issue.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
