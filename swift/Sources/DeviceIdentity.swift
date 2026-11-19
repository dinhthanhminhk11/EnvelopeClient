//
//  DeviceIdentity.swift
//  doodleart-core Swift sample
//
//  The long-term credential of the secure session (server docs app-security.md section 2): `device_id` (lowercase UUID,
//  kept in the Keychain; an app that already has an install id stores it under SecureKey.installID so the account its
//  guest login created is kept) and a P-256 key in the Secure Enclave that never leaves the device. The id only names
//  the device; the key's signature is the proof. Simulator builds (Debug only) use a software key: the Simulator has no
//  Secure Enclave.
//

import CryptoKit
import Foundation
import Security

/// The device key: its SubjectPublicKeyInfo (91 bytes) and an ECDSA P-256 / SHA-256 signer (DER signatures).
struct DeviceKey {
    let spki: Data
    let sign: (Data) throws -> Data
}

enum DeviceIdentity {}

// MARK: - Public Functions

extension DeviceIdentity {
    /// The lowercase UUID the server stores and every signed message carries.
    static func deviceID() throws -> String {
        if let stored = try SecureStore.string(for: SecureKey.installID) {
            return stored.lowercased()
        }
        let created = UUID().uuidString
        guard SecureStore.set(created, for: SecureKey.installID) else {
            throw SecureSetupError("device id not stored")
        }
        return created.lowercased()
    }

    static func key() throws -> DeviceKey {
        if let stored = try SecureStore.string(for: SecureKey.secureDeviceKey), let data = Data(base64Encoded: stored) {
            if let key = try? restore(data) {
                return key
            }
        }
        let (key, data) = try create()
        guard SecureStore.set(data.base64EncodedString(), for: SecureKey.secureDeviceKey) else {
            throw SecureSetupError("device key not stored")
        }
        resetRegistration()
        return key
    }

    /// The device key id the server confirmed at registration, nil before.
    static var registeredKeyID: String? {
        (try? SecureStore.string(for: SecureKey.secureRegisteredKeyID)) ?? nil
    }

    static func markRegistered(keyID: String) {
        SecureStore.set(keyID, for: SecureKey.secureRegisteredKeyID)
    }

    /// Forgets the registration (device unknown to the server, account deleted): the next session registers again.
    static func resetRegistration() {
        [SecureKey.secureRegisteredKeyID, SecureKey.appAttestKeyID].forEach { SecureStore.set(nil, for: $0) }
    }

    /// A new device id and a new key (409 40901003: this device_id or key belongs to another row). The guest login
    /// follows the new id too.
    static func startOver() {
        [SecureKey.installID, SecureKey.secureDeviceKey].forEach { SecureStore.set(nil, for: $0) }
        resetRegistration()
    }
}

// MARK: - Private Functions

extension DeviceIdentity {
    private static var usesSoftwareKey: Bool {
        #if DEBUG && (targetEnvironment(simulator) || DOODLEART_SOFTWARE_KEY)
            return true
        #else
            // A device without a Secure Enclave gets no key: the channel stays off and the plain API is used.
            return false
        #endif
    }

    private static func create() throws -> (DeviceKey, Data) {
        if usesSoftwareKey {
            let key = P256.Signing.PrivateKey()
            return (wrap(key), key.rawRepresentation)
        }
        var error: Unmanaged<CFError>?
        // Usable after the first unlock, so a background refresh can still open a session.
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &error) else {
            throw SecureSetupError("Secure Enclave access control: \(String(describing: error?.takeRetainedValue()))")
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        return (wrap(key), key.dataRepresentation)
    }

    private static func restore(_ data: Data) throws -> DeviceKey {
        if usesSoftwareKey {
            return wrap(try P256.Signing.PrivateKey(rawRepresentation: data))
        }
        return wrap(try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data))
    }

    private static func wrap(_ key: P256.Signing.PrivateKey) -> DeviceKey {
        DeviceKey(spki: key.publicKey.derRepresentation) { message in
            try key.signature(for: message).derRepresentation
        }
    }

    private static func wrap(_ key: SecureEnclave.P256.Signing.PrivateKey) -> DeviceKey {
        DeviceKey(spki: key.publicKey.derRepresentation) { message in
            try key.signature(for: message).derRepresentation
        }
    }
}
