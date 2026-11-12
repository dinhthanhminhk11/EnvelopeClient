//
//  SecureChannel.swift
//  doodleart-core Swift sample
//
//  The secure session of the app service (server docs app-security.md, client-api.md sections 2-5), on top of
//  doodleart-core: register the device key once, open a session (POST /api/v2/session/start), then seal every request
//  and open every answer. The new protocol lives under /api/v2 (`apiPrefix`); /api/v1 stays frozen for the released
//  app 2.0.0. Every /api/v2 route but the three handshake ones needs a session: on `.unavailable` there is no plain
//  request to fall back to, the app reports the error (or keeps the data it has).
//

import Foundation

/// Sends one HTTP request as is (APIClient's URLSession).
typealias SecureTransport = @Sendable (URLRequest) async throws -> (Data, HTTPURLResponse)

enum SecureChannelError: Error {
    /// No session can be opened or used right now (server without the secure routes, a server key this build does not
    /// embed, store down, device not registrable...). /api/v2 has no plain route: report the error.
    case unavailable(String)
    /// An answer that must not be trusted (tampered, replayed): neither data nor a reason to fall back.
    case untrusted(String)
    /// This build is below the server's minimum for the platform (426 42601001, at the handshake or on any sealed request:
    /// the minimum can rise while a session is open). Show the update screen; `storeURL` only comes with a sealed answer
    /// (the handshake gives X-Min-App-Version only). The channel is not paused.
    case upgradeRequired(minVersion: String?, storeURL: URL?)
    /// The server is under maintenance (503 50317001). `message` is in the app language (X-Language) and `until` the
    /// expected end, both only in a sealed answer and both optional. Show the maintenance screen and retry later; the
    /// channel is not paused, so the first request after the maintenance works.
    case maintenance(message: String?, until: Date?)
}

actor SecureChannel {
    // MARK: - Properties

    static let shared = SecureChannel()

    static let sealedContentType = "application/vnd.doodle.sealed"
    private static let platform = "ios"
    /// After `.unavailable`, the channel is not used for this long (no handshake storm against a server without sessions).
    private static let pauseInterval: TimeInterval = 10 * 60
    /// A session idle longer than this is renewed before use (the server forgets it after idle_ttl_seconds).
    private static let idleMargin: TimeInterval = 60

    private var session: OpenSession?
    private var opening: Task<OpenSession, Error>?
    private var pausedUntil: Date?
    /// Requests sealed and not yet answered, per core session handle.
    private var inFlight: [Int64: Int] = [:]
    /// Dropped sessions closed in the core only once their last request is answered: closing a handle at once would
    /// make the answers of the requests still running on it unreadable (UNKNOWN_HANDLE).
    private var retired: Set<Int64> = []

    private struct OpenSession {
        let core: CoreSession
        let idleTTL: TimeInterval
        let trust: String
        var lastUsed: Date

        var isIdle: Bool {
            Date().timeIntervalSince(lastUsed) > idleTTL - SecureChannel.idleMargin
        }
    }
}

// MARK: - Public Functions

extension SecureChannel {
    /// Whether the app should send through the channel: the core is linked and the app said the server it talks to
    /// holds a key the linked core embeds (`serverKeyEmbedded`: the debug core holds the developer server's key, a
    /// release core the production key). The app decides; the sample sets nothing.
    nonisolated static var isEnabled: Bool {
        CoreBridge.isLinked && SecureChannelSettings.serverKeyEmbedded
    }

    /// Seals `plain` (URL, method, headers and JSON body as APIClient built them), sends it and opens the answer.
    /// Returns the plaintext `{meta, data}` of the route and the HTTP response; the status is the route's (403, 409...
    /// are sealed too). `.unavailable`: no session now (see SecureChannelError). `.upgradeRequired` / `.maintenance`:
    /// the version gate or the maintenance switch, from the handshake or from this request (no pause either way).
    func send(_ plain: URLRequest, transport: @escaping SecureTransport) async throws -> (Data, HTTPURLResponse) {
        if let pausedUntil, pausedUntil > Date() {
            throw SecureChannelError.unavailable("paused after an earlier failure")
        }
        do {
            return try await sendSealed(plain, transport: transport, retry: true)
        } catch let error as SecureChannelError {
            if case let .unavailable(reason) = error {
                pausedUntil = Date().addingTimeInterval(Self.pauseInterval)
                SecureLog.note("secure channel unavailable (\(reason)): channel paused for \(Int(Self.pauseInterval / 60)) min")
            }
            throw error
        } catch let error as CoreError {
            pausedUntil = Date().addingTimeInterval(Self.pauseInterval)
            SecureLog.note("secure channel unavailable (\(error)): channel paused for \(Int(Self.pauseInterval / 60)) min")
            throw SecureChannelError.unavailable(error.description)
        }
    }

    /// Forgets the session, for example after POST /api/v2/auth/apple, /auth/google or /auth/logout answered
    /// session_ended: the next request opens a new one. Requests still running on the old session can read their answers.
    /// (POST /api/v2/session/end is optional: the server also forgets a session after the idle timeout.)
    func reset() {
        if let session {
            retire(session.core.handle)
        }
        session = nil
    }
}

// MARK: - Private Functions

extension SecureChannel {
    private func sendSealed(_ plain: URLRequest, transport: @escaping SecureTransport, retry: Bool) async throws -> (Data, HTTPURLResponse) {
        guard let url = plain.url, let target = Self.requestTarget(of: url) else {
            throw SecureChannelError.unavailable("no request target")
        }
        if Self.isSessionEnd(target) {
            return try await endSession(plain, url: url, target: target, transport: transport)
        }
        let current = try await currentSession(for: plain, transport: transport)
        let handle = current.core.handle
        begin(handle)
        defer { end(handle) }
        let sealed: CoreSealedRequest
        do {
            sealed = try Self.seal(plain, target: target, on: current)
        } catch let error as CoreError where Self.sessionGone.contains(error.status) {
            drop(current)
            guard retry else { throw SecureChannelError.unavailable(error.description) }
            return try await sendSealed(plain, transport: transport, retry: false)
        }

        let (data, response) = try await exchange(plain, sealed: sealed, on: current, transport: transport)
        do {
            let plaintext = try Self.openAnswer(data, response, seq: sealed.seq, on: current)
            touch(current)
            if let gate = Self.gateError(status: response.statusCode, body: plaintext, minVersionHeader: nil) {
                throw gate
            }
            return (plaintext, response)
        } catch let error as CoreError where error.status == CoreStatus.unsealedResponse {
            // Refused before the route ran: only the code decides what to do, never the body.
            switch error.metaCode {
            case 40_101_010, 40_901_004:
                // Session forgotten (idle, revoked, account switched) or seq / ts refused: a new session, once.
                drop(current)
                guard retry else { throw SecureChannelError.unavailable(error.description) }
                return try await sendSealed(plain, transport: transport, retry: false)
            default:
                throw SecureChannelError.unavailable(error.description)
            }
        } catch let error as CoreError {
            throw SecureChannelError.untrusted(error.description)
        }
    }

    /// POST /api/v2/session/end never opens a session only to end it: a new one would be the session the other running
    /// requests retry on. Without a live session, or when the server has forgotten it, the answer is built here
    /// (`sessionEnded`). After a successful end the session is dropped, so the next request opens a new one at once.
    private func endSession(_ plain: URLRequest, url: URL, target: String, transport: @escaping SecureTransport) async throws -> (Data, HTTPURLResponse) {
        guard let current = session, !current.isIdle else {
            if let session {
                drop(session)
            }
            return try Self.sessionEnded(url, message: "No session to end")
        }
        let handle = current.core.handle
        begin(handle)
        defer { end(handle) }
        let sealed: CoreSealedRequest
        do {
            sealed = try Self.seal(plain, target: target, on: current)
        } catch let error as CoreError where Self.sessionGone.contains(error.status) {
            drop(current)
            return try Self.sessionEnded(url, message: "Session already ended")
        }
        let (data, response) = try await exchange(plain, sealed: sealed, on: current, transport: transport)
        do {
            let plaintext = try Self.openAnswer(data, response, seq: sealed.seq, on: current)
            if response.statusCode == 200 {
                drop(current)
            } else {
                touch(current)
            }
            return (plaintext, response)
        } catch let error as CoreError where error.status == CoreStatus.unsealedResponse {
            switch error.metaCode {
            case 40_101_010:
                // The server forgot the session already, which is all session/end asks for.
                drop(current)
                return try Self.sessionEnded(url, message: "Session already ended")
            case 40_901_004:
                // seq / ts refused: the server keeps the session until its idle timeout, this device forgets its keys.
                drop(current)
                return try Self.sessionEnded(url, message: "Session dropped on this device")
            default:
                throw SecureChannelError.unavailable(error.description)
            }
        } catch let error as CoreError {
            throw SecureChannelError.untrusted(error.description)
        }
    }

    /// Sends a sealed request; a transport error forgets its seq in the core.
    private func exchange(_ plain: URLRequest, sealed: CoreSealedRequest, on current: OpenSession,
                          transport: @escaping SecureTransport) async throws -> (Data, HTTPURLResponse) {
        do {
            return try await transport(Self.sealedRequest(plain, sealed))
        } catch {
            CoreBridge.abandon(session: current.core.handle, seq: sealed.seq)
            throw error
        }
    }

    /// Core statuses of a seal meaning the session is over on this device: a new session is needed.
    private static let sessionGone: [UInt8] = [CoreStatus.sessionExpired, CoreStatus.seqExhausted, CoreStatus.unknownHandle]

    private static func seal(_ plain: URLRequest, target: String, on current: OpenSession) throws -> CoreSealedRequest {
        let body = plain.httpBody.flatMap { $0.isEmpty ? nil : $0 }
        return try CoreBridge.seal(session: current.core.handle, method: plain.httpMethod ?? "GET", pathWithQuery: target, body: body)
    }

    /// `plain` with the session headers and the sealed body (or the tag of a bodyless request).
    private static func sealedRequest(_ plain: URLRequest, _ sealed: CoreSealedRequest) -> URLRequest {
        var request = plain
        // The session authenticates the request; a sealed answer never has an ETag, so no conditional request.
        ["Authorization", "If-None-Match", "If-Modified-Since", "Content-Type"].forEach { request.setValue(nil, forHTTPHeaderField: $0) }
        request.setValue(sealed.sid, forHTTPHeaderField: "X-Tx-Session")
        request.setValue(String(sealed.seq), forHTTPHeaderField: "X-Tx-Seq")
        request.setValue(String(sealed.ts), forHTTPHeaderField: "X-Tx-Ts")
        request.setValue(sealed.appVersion, forHTTPHeaderField: "X-App-Version")
        if let tag = sealed.tag {
            request.setValue(tag, forHTTPHeaderField: "X-Tx-Tag")
            request.httpBody = nil
        } else {
            request.setValue(sealedContentType, forHTTPHeaderField: "Content-Type")
            request.httpBody = sealed.body
        }
        return request
    }

    /// The plaintext of the answer to `seq` (CoreError when it is not a sealed answer or does not open).
    private static func openAnswer(_ data: Data, _ response: HTTPURLResponse, seq: Int64, on current: OpenSession) throws -> Data {
        try CoreBridge.response(session: current.core.handle, seq: seq, httpStatus: response.statusCode,
                                contentType: response.value(forHTTPHeaderField: "Content-Type"),
                                contentEncoding: response.value(forHTTPHeaderField: "X-Tx-Encoding"), body: data)
    }

    private static func isSessionEnd(_ target: String) -> Bool {
        let path = target.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? target
        return sessionEndPaths.contains { path.hasSuffix($0) }
    }

    private func currentSession(for plain: URLRequest, transport: @escaping SecureTransport) async throws -> OpenSession {
        if let session, !session.isIdle {
            return session
        }
        if let session {
            drop(session)
        }
        if let opening {
            return try await opening.value
        }
        let task = Task { try await self.open(for: plain, transport: transport) }
        opening = task
        defer { opening = nil }
        let opened = try await task.value
        session = opened
        return opened
    }

    private func drop(_ dropped: OpenSession) {
        if session?.core.handle == dropped.core.handle {
            session = nil
        }
        retire(dropped.core.handle)
    }

    /// Closes a dropped session in the core now, or after its last running request (see `retired`).
    private func retire(_ handle: Int64) {
        if inFlight[handle, default: 0] == 0 {
            CoreBridge.close(session: handle)
        } else {
            retired.insert(handle)
        }
    }

    private func begin(_ handle: Int64) {
        inFlight[handle, default: 0] += 1
    }

    private func end(_ handle: Int64) {
        let left = inFlight[handle, default: 1] - 1
        if left > 0 {
            inFlight[handle] = left
            return
        }
        inFlight[handle] = nil
        if retired.remove(handle) != nil {
            CoreBridge.close(session: handle)
        }
    }

    private func touch(_ used: OpenSession) {
        if session?.core.handle == used.core.handle {
            session?.lastUsed = Date()
        }
    }

    // MARK: Opening a session

    private func open(for plain: URLRequest, transport: @escaping SecureTransport) async throws -> OpenSession {
        guard let origin = plain.url.flatMap(Self.origin(of:)) else {
            throw SecureChannelError.unavailable("no server origin")
        }
        let context = RequestContext(origin: origin, headers: Self.baseHeaders(of: plain), transport: transport)
        let appVersion = plain.value(forHTTPHeaderField: "X-App-Version") ?? ""
        for attempt in 0 ..< 2 {
            let deviceID: String
            let key: DeviceKey
            do {
                deviceID = try DeviceIdentity.deviceID()
                key = try DeviceIdentity.key()
            } catch {
                throw SecureChannelError.unavailable("device identity: \(error.localizedDescription)")
            }
            let keyID = try CoreBridge.deviceKeyID(spki: key.spki)
            if DeviceIdentity.registeredKeyID != keyID {
                let registered = try await register(deviceID: deviceID, key: key, keyID: keyID, appVersion: appVersion, context: context)
                if !registered, attempt == 0 {
                    // A new device id and key were made (409 40901003): register them.
                    continue
                }
            }
            do {
                return try await handshake(deviceID: deviceID, key: key, keyID: keyID, appVersion: appVersion, context: context)
            } catch let error as CoreError where error.status == CoreStatus.serverRejected {
                switch error.metaCode {
                case 40_101_009 where attempt == 0:
                    // The server does not know this key (account deleted, database reset): register again.
                    DeviceIdentity.resetRegistration()
                    continue
                case 40_001_004, 40_901_004:
                    // Clock fixed from X-Server-Time, or a client_pub already used: one more handshake, fresh key.
                    return try await handshake(deviceID: deviceID, key: key, keyID: keyID, appVersion: appVersion, context: context)
                default:
                    throw SecureChannelError.unavailable("handshake refused: \(error)")
                }
            }
        }
        throw SecureChannelError.unavailable("no session after a new registration")
    }

    /// POST /api/v2/auth/challenge then POST /api/v2/devices/register. Returns false after a conflict that made a new
    /// device identity (the caller registers that one).
    private func register(deviceID: String, key: DeviceKey, keyID: String, appVersion: String, context: RequestContext) async throws -> Bool {
        for _ in 0 ..< 2 {
            let challenge = try await context.postJSON("\(Self.apiPrefix)/auth/challenge", [:])
            guard challenge.status == 200, let nonce = challenge.data?["nonce"] as? String else {
                throw SecureChannelError.unavailable("challenge answered \(challenge.status) \(challenge.code.map(String.init) ?? "")")
            }
            let (message, clientDataHash) = try CoreBridge.registerMessage(nonce: nonce, deviceID: deviceID, keyID: keyID, platform: Self.platform)
            let signature: Data
            do {
                signature = try key.sign(message)
            } catch {
                throw SecureChannelError.unavailable("device key cannot sign: \(error.localizedDescription)")
            }
            var body: [String: Any] = [
                "nonce": nonce,
                "device": Self.deviceInfo(deviceID: deviceID, appVersion: appVersion),
                "device_public_key": key.spki.base64URLString,
                "signature": signature.base64URLString,
            ]
            if let attestation = await AppAttest.attestation(clientDataHash: clientDataHash) {
                body["attestation"] = attestation
            }
            let reply = try await context.postJSON("\(Self.apiPrefix)/devices/register", body)
            switch (reply.status, reply.code) {
            case (200, _):
                DeviceIdentity.markRegistered(keyID: keyID)
                // Ids shortened to 8 characters: enough to find the request in the server log.
                SecureLog.note("secure channel: device registered, trust \(reply.data?["trust"] as? String ?? "?"), "
                    + "new user \(reply.data?["is_new_user"] as? Bool ?? false), user \(Self.short(reply.data?["user_id"])), "
                    + "device \(deviceID.prefix(8))")
                return true
            case (400, 40_001_003):
                continue // nonce expired or used: a new challenge
            case (409, 40_901_003):
                // This device_id or key is bound to another row: start over with a new identity.
                DeviceIdentity.startOver()
                return false
            default:
                throw SecureChannelError.unavailable("register answered \(reply.status) \(reply.code.map(String.init) ?? "")")
            }
        }
        throw SecureChannelError.unavailable("register: no valid challenge")
    }

    private func handshake(deviceID: String, key: DeviceKey, keyID: String, appVersion: String, context: RequestContext) async throws -> OpenSession {
        let begun = try CoreBridge.handshakeBegin(deviceID: deviceID, keyID: keyID, appVersion: appVersion)
        do {
            let signature: Data
            do {
                signature = try key.sign(begun.signatureMessage)
            } catch {
                throw SecureChannelError.unavailable("device key cannot sign: \(error.localizedDescription)")
            }
            let body = try CoreBridge.handshakeBody(begun.handle, signature: signature)
            var headers = ["Content-Type": "application/json"]
            if let token = await AppAttest.assertion(clientDataHash: try CoreBridge.handshakeAssertHash(begun.handle)) {
                headers["X-Integrity-Token"] = token
            }
            let (data, response) = try await context.send("\(Self.apiPrefix)/session/start", body: body, headers: headers)
            if let gate = Self.gateError(status: response.statusCode, body: data,
                                         minVersionHeader: response.value(forHTTPHeaderField: "X-Min-App-Version")) {
                throw gate
            }
            let serverTime = Int64(response.value(forHTTPHeaderField: "X-Server-Time") ?? "") ?? 0
            let core = try CoreBridge.handshakeFinish(begun.handle, httpStatus: response.statusCode, serverTime: serverTime, body: data)
            let info = (try? JSONSerialization.jsonObject(with: core.info) as? [String: Any]) ?? [:]
            let idle = (info["idle_ttl_seconds"] as? NSNumber)?.doubleValue ?? 2 * 3600
            let trust = info["trust"] as? String ?? "?"
            SecureLog.note("secure channel: session open, trust \(trust), user \(Self.short(info["user_id"])), "
                + "device \(deviceID.prefix(8)), risk flags [\(begun.riskFlagsCSV)]")
            return OpenSession(core: core, idleTTL: idle, trust: trust, lastUsed: Date())
        } catch {
            // Gone already when finish ran; otherwise drop the pending handshake and its ephemeral key.
            CoreBridge.handshakeAbort(begun.handle)
            throw error
        }
    }

    // MARK: Helpers

    /// The plain JSON exchanges of the registration and the handshake (no session exists yet).
    private struct RequestContext {
        let origin: URL
        let headers: [String: String]
        let transport: SecureTransport

        func send(_ path: String, body: Data, headers extra: [String: String]) async throws -> (Data, HTTPURLResponse) {
            var request = URLRequest(url: origin.appendingPathComponent(path), cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
            request.httpMethod = "POST"
            request.httpBody = body
            headers.merging(extra) { _, new in new }.forEach { request.setValue($1, forHTTPHeaderField: $0) }
            return try await transport(request)
        }

        func postJSON(_ path: String, _ object: [String: Any]) async throws -> (status: Int, code: Int?, data: [String: Any]?) {
            let body = try JSONSerialization.data(withJSONObject: object)
            let (data, response) = try await send(path, body: body, headers: ["Content-Type": "application/json"])
            let envelope = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            let code = (envelope?["meta"] as? [String: Any])?["code"] as? Int
            return (response.statusCode, code, envelope?["data"] as? [String: Any])
        }
    }

    /// The raw request target the server authenticates: percent-encoded path, then "?" and the query as sent.
    private static func requestTarget(of url: URL) -> String? {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        let path = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
        return path + (components.percentEncodedQuery.map { "?" + $0 } ?? "")
    }

    /// Prefix of the new protocol's routes (handshake included). /api/v1 is frozen for the released app 2.0.0.
    static let apiPrefix = "api/v2"

    /// Request targets of POST session/end, v2 and the v1 copy still served (suffix: the base URL may carry a path).
    private static let sessionEndPaths = ["/api/v2/session/end", "/api/v1/session/end"]

    /// The answer of session/end built on this device (no live session, session already forgotten by the server): the
    /// same `{meta, data}` as a successful end, `meta.message` saying why.
    private static func sessionEnded(_ url: URL, message: String) throws -> (Data, HTTPURLResponse) {
        let body = try JSONSerialization.data(withJSONObject: ["meta": ["code": 200, "message": message], "data": [String: Any]()])
        guard let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"]) else {
            throw SecureChannelError.unavailable("session/end: no response")
        }
        return (body, response)
    }

    /// The version gate and the maintenance switch (server docs client-api.md 2.1, 5.4): 426 42601001 and 503 50317001.
    /// A sealed answer carries the details in `data`; the plain JSON handshake only X-Min-App-Version (an unauthenticated
    /// answer: it can only show a screen, never change what the app stores).
    private static func gateError(status: Int, body: Data, minVersionHeader: String?) -> SecureChannelError? {
        guard status == 426 || status == 503 else { return nil }
        let envelope = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any]
        let code = (envelope?["meta"] as? [String: Any])?["code"] as? Int
        let data = envelope?["data"] as? [String: Any]
        switch (status, code) {
        case (426, 42_601_001):
            return .upgradeRequired(minVersion: data?["min_app_version"] as? String ?? minVersionHeader,
                                    storeURL: (data?["store_url"] as? String).flatMap(URL.init(string:)))
        case (503, 50_317_001):
            return .maintenance(message: data?["message"] as? String, until: date(data?["until"]))
        default:
            return nil
        }
    }

    /// An RFC 3339 time of a JSON answer (whole or fractional seconds), nil when absent or malformed.
    private static func date(_ value: Any?) -> Date? {
        guard let text = value as? String else { return nil }
        let formatter = ISO8601DateFormatter()
        if let date = formatter.date(from: text) {
            return date
        }
        formatter.formatOptions.insert(.withFractionalSeconds)
        return formatter.date(from: text)
    }

    /// The first 8 characters of an id from a JSON answer, "?" when absent.
    private static func short(_ value: Any?) -> String {
        (value as? String).map { String($0.prefix(8)) } ?? "?"
    }

    private static func origin(of url: URL) -> URL? {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        components.path = ""
        components.query = nil
        components.fragment = nil
        return components.url
    }

    /// The headers of every request (language, platform, app version...), without those of this request only.
    private static func baseHeaders(of request: URLRequest) -> [String: String] {
        var headers = request.allHTTPHeaderFields ?? [:]
        ["Authorization", "If-None-Match", "If-Modified-Since", "Content-Type", "Content-Length"].forEach { headers[$0] = nil }
        return headers
    }

    /// `device` of RegisterDeviceRequest (DeviceRequest of the server).
    private static func deviceInfo(deviceID: String, appVersion: String) -> [String: Any] {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        var info: [String: Any] = [
            "device_id": deviceID,
            "platform": platform,
            "app_version": appVersion,
            "os_version": "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)",
            "device_model": modelIdentifier,
            "locale": String(Locale.current.identifier.prefix(16)),
            "timezone": TimeZone.current.identifier,
        ]
        if let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String {
            info["build_number"] = build
        }
        return info
    }

    private static var modelIdentifier: String {
        #if targetEnvironment(simulator)
            if let simulated = ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] {
                return simulated
            }
        #endif
        var systemInfo = utsname()
        uname(&systemInfo)
        return withUnsafeBytes(of: &systemInfo.machine) { buffer in
            String(decoding: buffer.prefix { $0 != 0 }, as: UTF8.self)
        }
    }
}
