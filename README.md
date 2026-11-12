# doodleart-core

Core bảo mật phía client của DoodleArt, viết bằng Rust, port từ core Rust của theme-x (repo theme-x trên GitLab, thư mục
`source/android/<core>`, commit `3019af49`). Một crate dùng cho cả iOS (C ABI, `DoodleArtCore`) và Android
(JNI), nói đúng giao thức phiên mã hoá của app service: [`../server/docs/app-security.md`](../server/docs/app-security.md).

Gồm:

- **envelope v1**: thông điệp đăng ký `doodle/v1/register`, handshake (`doodle/v1/start`, transcript, kiểm chữ ký Ed25519 của
  server bằng khoá nhúng, HKDF), seal / open request và response (ChaCha20-Poly1305, AAD có `content_encoding`, giải gzip của
  `X-Tx-Encoding`), seq, đồng hồ theo `server_time` + đồng hồ đơn điệu.
- **hàm băm integrity**: SHA-256 của thông điệp đăng ký (clientDataHash của App Attest), `DAAS1` (assertion của handshake),
  `DAPI1` (assertion theo action, server chưa kiểm), `iosDeviceHash`.
- **quét risk**: Frida, hook, jailbreak / root, Simulator / emulator, debugger, trả về cờ, không tự chặn gì.
- **Android** (chưa có app): JNI `com/cem/doodleart/security/NativeCore`, APK identity, device signals CNHW1.

## Vì sao đặt ở gốc repo

Core không thuộc riêng `ios/` hay `android/`: cùng một bản build cho cả hai, và test của nó cần `server/` (vector, peer interop
viết bằng Go). Đặt ngang hàng các module khác (`doodleart-core/`) để cả hai team app dùng chung mà không phụ thuộc thư mục của nhau;
tên thư mục trùng tên crate. theme-x đặt core dưới `source/android/` chỉ vì Android có trước.

## Khác core của theme-x

| Chỗ | theme-x | doodleart-core | Lý do |
|---|---|---|---|
| Tên | Tiền tố theo tên theme-x (hàm C, module Swift, biến môi trường) | `doodleart_*`, `DoodleArtCore`, `DOODLEART_*` | Yêu cầu của dự án |
| Nhãn wire | `<theme-x>/v1/*`, `TXPI1`, `TXAS1`, `TXAA1`, media type sealed của theme-x | `doodle/v1/*`, `DAPI1`, `DAAS1`, `application/vnd.doodle.sealed` | Theo server Go đã có (longlt port trước) |
| JSON | camelCase, không bọc | snake_case trong `{meta, data}` của golib, lỗi là `meta.code` số | Quy ước của server doodle-art |
| Đăng ký | Không ký bằng khoá thiết bị; App Attest qua `TXAA1` | Ký `doodle/v1/register`; App Attest trên SHA-256 của thông điệp đó | Server doodle-art đã chọn cách này |
| Response | AAD không có encoding | AAD có `content_encoding`, core tự giải gzip | Server nén catalog trong seal |
| Lỗi handshake | `details.serverTime` trong body | Header `X-Server-Time` truyền vào `handshake_finish` | Server doodle-art gửi header |
| `device_id` | `installId` bất kỳ | UUID chữ thường | Server ký và lưu dạng chữ thường |
| Bỏ | `attest_client_data_hash` (TXAA1), attest muộn | Thêm `doodleart_register_message` | Server chưa có `/devices/attest` |
| Test interop | Peer Node (`interop/server.js`) | Peer Go: route, middleware, usecase thật trên store in-memory (`server/src/app/routers/interop_peer_test.go`) | Server là Go |
| Slice iOS | arm64 | Thêm `x86_64-apple-ios` (`--install`, build Simulator generic) | Build Simulator generic của app iOS gồm cả x86_64 |

Cấu trúc mã, C ABI, quy ước reply `status || payload`, bảng handle, quét risk, kiểm Mach-O giữ nguyên như theme-x.

## Khoá server theo build type

| File | Build | Nội dung |
|---|---|---|
| `config/server-keys.debug.conf` | `build-debug` (mặc định) | Khoá của app service trên máy dev: kid `2026-11`, public key của `ENVELOPE_SIGNING_KEY` trong `server/.env`. Sinh lại: `tools/derive-debug-server-key.sh` |
| `config/server-keys.release.conf` | `build-release` | **Chưa có.** Giá trị `REPLACE_...`: build release dừng với lỗi rõ ràng cho tới khi owner điền public key production và kid (`ENVELOPE_SIGNING_KID` của deploy). Lệnh lấy public key ghi trong file |
| `config/server-keys.qa.conf` | `build-qa` | Chưa có (không có staging riêng) |

Chỉ có public key. Mỗi môi trường một cặp khoá, không dùng chung khoá với theme-x hay project khác (transcript không chứa app id).
`config/project.conf`: `PROJECT_ID = doodleart`, `OBFSTR_SEED`, `REMAP_SALT` riêng của DoodleArt; hai digest cert APK là chỗ giữ chỗ
(chưa có app Android).

## Lệnh

```bash
cd doodleart-core
cargo test                                   # 182 test, gồm vector của server và interop với peer Go (cần go)
OBFSTR_SEED=<của config/project.conf> cargo test   # như trên, không cảnh báo
DOODLEART_SERVER_KEYS_FILE=tests/fixtures/server-keys.release-test.conf OBFSTR_SEED=<...> \
  cargo test --no-default-features --features build-release   # nhánh release, khoá test
./build-ios.sh debug --no-xcframework --install <dir>   # slice iOS (arm64 máy, arm64 + x86_64 Simulator) + include/ vào <dir>
./build-ios.sh debug                         # thêm DoodleArtCore.xcframework (cần Xcode)
tools/c-abi-smoke.sh debug                   # C, C++, Objective-C, Swift gọi C ABI trên slice macOS
DOODLEART_SERVER_KEYS_FILE=tests/fixtures/server-keys.release-test.conf tools/c-abi-smoke.sh release
tools/swift-harness.sh [--stub] [--fresh]    # lớp Swift mẫu (swift/Sources) + core, tới server local (make run-app)
```

`build-ios.sh` chỉ cần CommandLineTools cho slice (`--no-xcframework`); xcframework cần `xcodebuild` của Xcode. Cần rustup target
`aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`, `aarch64-apple-darwin` và component `llvm-tools`. Mỗi slice được
prelink chỉ còn 19 hàm của header (18 ở bản release) và qua `tools/check-macho.sh`.

## Cung cấp cho đội iOS

Team server chỉ cung cấp core; ghép vào app (`ios/`) là việc của đội iOS. Hướng dẫn ghép từng bước (Xcode, lớp Swift mẫu,
danh sách API, mã lỗi, thử qua ngrok): [`../server/docs/client-api.md`](../server/docs/client-api.md) mục 3 (iOS, Android) và các mục API.

- **Thư viện:** `./build-ios.sh debug` (cần Xcode) cho `DoodleArtCore.xcframework`; không có Xcode thì `--no-xcframework` cho
  slice. `--install <dir>` chép ba slice iOS, `include/` và manifest vào `<dir>/debug/`; module map ở đó có
  `link "doodleart_core"`, nên chỉ cần `SWIFT_INCLUDE_PATHS` trỏ `include/` và `LIBRARY_SEARCH_PATHS` theo SDK / arch trỏ slice
  (`[sdk=iphoneos*][arch=arm64]` → `aarch64-apple-ios`, `[sdk=iphonesimulator*][arch=arm64]` → `aarch64-apple-ios-sim`,
  `[sdk=iphonesimulator*][arch=x86_64]` → `x86_64-apple-ios`); `import DoodleArtCore` tự link. Thư viện debug nhúng khoá server
  local, chỉ hợp với cấu hình Debug trỏ server dev.
- **Header:** `include/doodleart_core.h` là hợp đồng C ABI (reply `status || payload`, quyền sở hữu buffer, hàm blocking).
- **Lớp Swift mẫu:** `swift/Sources/` (`CoreBridge` bọc C ABI, `DeviceIdentity` khoá Secure Enclave, `AppAttest` attestation +
  assertion và stub Simulator, `SecureChannel` actor đăng ký / handshake / seal / open / thử lại, `SecureSupport` Keychain, log, công
  tắc). Đã chạy với server local qua `tools/swift-harness.sh` (macOS). Đội iOS chép hoặc viết lại theo kiến trúc của app.
- **Server để thử:** `make migrate-up` rồi `make run-app ATTESTATION_MODE=observe` trong `server/` (verifier stub của profile local
  nhận App Attest giả của Simulator).

## Android

Chưa có app. Phần JNI giữ nguyên hình dạng theme-x, đổi chữ ký theo server doodle-art: `handshakeFinish(JIJ[B)[B` (thêm
`serverTime`), `sessionOpen(JJI[B[B)[B` và `sessionResponse(JJI[B[B[B)[B` (thêm `contentEncoding`), thêm
`registerMessage([B[B[B[B)[B`. Lớp Kotlin phải là `com.cem.doodleart.security.NativeCore` (đổi khi biết package thật của app).
`build-android.sh`, `tools/check-so.sh` chép sang nhưng chưa chạy trên máy này.

## Chưa làm

- Chưa có job CI cho core (theme-x có `core:check`, `core:publish`, registry + `core.lock`; `tools/fetch-core.sh`,
  `tools/publish-core.sh` vẫn còn nhưng chưa nối).
- Chưa build xcframework (máy port không có Xcode); lớp Swift mẫu chỉ chạy trên macOS, chưa chạy trên Simulator / máy thật.
- Khoá production cho bản release; khi app ghép: capability App Attest, `PrivacyInfo.xcprivacy` (core import `_fstat`, `C617.1`).
