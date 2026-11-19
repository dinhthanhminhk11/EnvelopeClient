//
//  SecureSupport.swift
//  doodleart-core Swift sample
//
//  What the sample needs from its host app, kept here so the four files compile alone: the Keychain items, a log line
//  and the switch of the channel. An app maps these onto its own types (its Keychain wrapper, logger, environment).
//

import Foundation
import Security

/// Keychain items of the secure session. `installID` is where the device id lives: an app that already keeps an
/// install id (the guest login of DoodleArt: "install_id") uses that item, so the server keeps the same account.
enum SecureKey {
    static let installID = "install_id"
    static let secureDeviceKey = "secure.device_key"
    static let secureRegisteredKeyID = "secure.registered_key_id"
    static let appAttestKeyID = "secure.app_attest_key_id"
    static let appAttestStubCounter = "secure.app_attest_stub_counter"
}

/// Set by the app: true when the server it talks to holds a key the linked core embeds (debug core: the developer
/// server; release core: production).
enum SecureChannelSettings {
    nonisolated(unsafe) static var serverKeyEmbedded = false
}

struct SecureSetupError: Error, CustomStringConvertible {
    let description: String

    init(_ description: String) {
        self.description = description
    }
}

enum SecureLog {
    static func note(_ message: String) {
        #if DEBUG
            NSLog("[SecureChannel] %@", message)
        #endif
    }
}

/// Generic-password Keychain items of this bundle (accessible after the first unlock, this device only). Debug
/// Simulator builds without signing cannot use the Keychain (errSecMissingEntitlement): there only, values fall back
/// to UserDefaults so the channel can be tried. DOODLEART_SAMPLE_DEFAULTS_STORE (tools/swift-harness.sh) always uses
/// UserDefaults, so a rebuilt host binary never asks the login keychain for access.
enum SecureStore {}

// MARK: - Public Functions

extension SecureStore {
    static func string(for key: String) throws -> String? {
        #if DOODLEART_SAMPLE_DEFAULTS_STORE
            return fallback.string(forKey: key)
        #else
            var query = baseQuery(for: key)
            query[kSecReturnData as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            if status == errSecItemNotFound {
                return nil
            }
            guard status == errSecSuccess, let data = result as? Data else {
                #if DEBUG && targetEnvironment(simulator)
                    return fallback.string(forKey: key)
                #else
                    throw SecureSetupError("Keychain read failed (\(status))")
                #endif
            }
            return String(data: data, encoding: .utf8)
        #endif
    }

    @discardableResult
    static func set(_ value: String?, for key: String) -> Bool {
        #if DOODLEART_SAMPLE_DEFAULTS_STORE
            fallback.set(value, forKey: key)
            return true
        #else
            if keychainSet(value, for: key) {
                return true
            }
            #if DEBUG && targetEnvironment(simulator)
                fallback.set(value, forKey: key)
                return true
            #else
                return false
            #endif
        #endif
    }
}

// MARK: - Private Functions

extension SecureStore {
    private static var fallback: UserDefaults {
        UserDefaults(suiteName: (Bundle.main.bundleIdentifier ?? "doodleart") + ".secure-store") ?? .standard
    }

    private static func baseQuery(for key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Bundle.main.bundleIdentifier ?? "DoodleArt",
            kSecAttrAccount as String: key,
        ]
    }

    private static func keychainSet(_ value: String?, for key: String) -> Bool {
        let query = baseQuery(for: key)
        guard let data = value?.data(using: .utf8) else {
            let status = SecItemDelete(query as CFDictionary)
            return status == errSecSuccess || status == errSecItemNotFound
        }
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        guard status == errSecItemNotFound else { return status == errSecSuccess }
        return SecItemAdd(query.merging(attributes) { _, new in new } as CFDictionary, nil) == errSecSuccess
    }
}
