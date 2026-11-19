//
//  AppAttest.swift
//  doodleart-core Swift sample
//
//  App Attest proof of the secure session (server docs app-security.md section 2b): an attestation at registration
//  (clientDataHash = SHA-256 of the registration message) and an assertion at every handshake (X-Integrity-Token,
//  clientDataHash = DAAS1 of the signed message). App Attest is evidence, never the device key. Debug Simulator builds
//  send the "doodleart-stub-v1." stand-ins that only a development server (APP_ATTEST_VERIFIER=stub) accepts.
//  Needs the App Attest capability in the provisioning profile; without it attestation fails and the device registers
//  without one (the server keeps it `limited`).
//

import DeviceCheck
import Foundation

enum AppAttest {}

// MARK: - Public Functions

extension AppAttest {
    /// The `attestation` object of the registration body, or nil when App Attest is not available (no capability,
    /// unsupported device, Apple unreachable). A key that fails to attest is dropped: it cannot be attested again.
    static func attestation(clientDataHash: Data) async -> [String: String]? {
        #if DEBUG && (targetEnvironment(simulator) || DOODLEART_APP_ATTEST_STUB)
            let keyID = Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) }).base64EncodedString()
            let payload = ["key_id": keyID, "client_data_hash": clientDataHash.hexString]
            guard let json = try? JSONSerialization.data(withJSONObject: payload, options: .sortedKeys) else { return nil }
            SecureStore.set(keyID, for: SecureKey.appAttestKeyID)
            SecureStore.set("0", for: SecureKey.appAttestStubCounter)
            return ["type": "app_attest", "key_id": keyID, "data": stubPrefix + json.base64URLString]
        #else
            let service = DCAppAttestService.shared
            guard service.isSupported else { return nil }
            do {
                let keyID = try await service.generateKey()
                let object = try await service.attestKey(keyID, clientDataHash: clientDataHash)
                SecureStore.set(keyID, for: SecureKey.appAttestKeyID)
                return ["type": "app_attest", "key_id": keyID, "data": object.base64EncodedString()]
            } catch {
                SecureLog.note("App Attest attestation unavailable: \(error.localizedDescription)")
                return nil
            }
        #endif
    }

    /// The X-Integrity-Token of a handshake (base64url of the assertion), nil when the registration stored no key.
    /// The server only lowers the session's trust when it is missing or wrong; it never refuses the handshake.
    static func assertion(clientDataHash: Data) async -> String? {
        guard let keyID = (try? SecureStore.string(for: SecureKey.appAttestKeyID)) ?? nil else { return nil }
        #if DEBUG && (targetEnvironment(simulator) || DOODLEART_APP_ATTEST_STUB)
            let counter = ((try? SecureStore.string(for: SecureKey.appAttestStubCounter)).flatMap { $0 }.flatMap(UInt32.init) ?? 0) + 1
            SecureStore.set(String(counter), for: SecureKey.appAttestStubCounter)
            _ = keyID
            return stubPrefix + "\(counter)." + clientDataHash.hexString
        #else
            do {
                let assertion = try await DCAppAttestService.shared.generateAssertion(keyID, clientDataHash: clientDataHash)
                return assertion.base64URLString
            } catch {
                SecureLog.note("App Attest assertion unavailable: \(error.localizedDescription)")
                if (error as? DCError)?.code == .invalidKey {
                    // The key is gone (reinstall, restore): register again with a new one.
                    DeviceIdentity.resetRegistration()
                }
                return nil
            }
        #endif
    }
}

// MARK: - Private Functions

extension AppAttest {
    private static let stubPrefix = "doodleart-stub-v1."
}

extension Data {
    /// base64url without padding, the binary encoding of the secure session JSON and headers.
    var base64URLString: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
