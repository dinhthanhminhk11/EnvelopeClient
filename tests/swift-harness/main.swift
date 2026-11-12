// macOS harness of the Swift sample (swift/Sources) over the secure session, against a running app service
// (tools/swift-harness.sh). A minimal HTTP client plays the app over /api/v2: headers like the iOS app's, the sealed path
// first and the plain request when the channel says `.unavailable` (on /api/v2 that plain request gets 401 and shows up as
// "plain" in the output, which is the failure to look for).
import Foundation

struct Reply {
    let status: Int
    let data: Data
    let sealed: Bool
}

@main
struct Harness {
    static var base = URL(string: "http://localhost:9100")!

    static func main() async {
        if let argument = CommandLine.arguments.dropFirst().first(where: { !$0.hasPrefix("--") }), let url = URL(string: argument) {
            base = url
        }
        SecureChannelSettings.serverKeyEmbedded = true
        print("core:", CoreBridge.buildInfo() ?? "not linked", "| enabled:", SecureChannel.isEnabled, "| base", base)
        if CommandLine.arguments.contains("--fresh") {
            DeviceIdentity.startOver()
        }
        do {
            let catalog = try await send("GET", "api/v2/catalog")
            let object = try JSONSerialization.jsonObject(with: catalog.data) as? [String: Any]
            let data = object?["data"] as? [String: Any]
            print("GET catalog ->", catalog.status, catalog.sealed ? "sealed" : "plain",
                  "categories", (data?["categories"] as? [Any])?.count ?? -1, "templates", (data?["templates"] as? [Any])?.count ?? -1)
            let templates = try await send("GET", "api/v2/templates", query: [URLQueryItem(name: "page", value: "1"), URLQueryItem(name: "limit", value: "3")])
            print("GET templates ->", templates.status, templates.sealed ? "sealed" : "plain", String(decoding: templates.data.prefix(120), as: UTF8.self))
            let music = try await send("GET", "api/v2/music")
            print("GET music ->", music.status, music.sealed ? "sealed" : "plain")
            let me = try await send("GET", "api/v2/me")
            print("GET me ->", me.status, me.sealed ? "sealed" : "plain", String(decoding: me.data.prefix(160), as: UTF8.self))
            let body = try JSONSerialization.data(withJSONObject: ["kind": "template", "text": "harness \(Date().timeIntervalSince1970)", "source": "harness"])
            let request = try await send("POST", "api/v2/content-requests", body: body)
            print("POST content-requests ->", request.status, request.sealed ? "sealed" : "plain")
            let end = try await send("POST", "api/v2/session/end")
            print("POST session/end ->", end.status, end.sealed ? "sealed" : "plain")
            // The session is over: a second session/end is answered on this device, without a new handshake.
            let endAgain = try await send("POST", "api/v2/session/end")
            print("POST session/end again ->", endAgain.status, endAgain.sealed ? "sealed" : "plain",
                  String(decoding: endAgain.data, as: UTF8.self))
            // The server forgot the session: the channel opens a new one by itself.
            let again = try await send("GET", "api/v2/catalog")
            print("GET catalog after session/end ->", again.status, again.sealed ? "sealed" : "plain")
            // Requests still running when another one finds the session gone (40101010) keep their answers: the
            // channel closes a dropped session in the core only after its last request is answered.
            let parallel = try await withThrowingTaskGroup(of: Reply.self) { group in
                group.addTask { try await send("POST", "api/v2/session/end") }
                for _ in 0 ..< 12 {
                    group.addTask { try await send("GET", "api/v2/catalog") }
                }
                var replies: [Reply] = []
                for try await reply in group {
                    replies.append(reply)
                }
                return replies
            }
            let good = parallel.filter { $0.status == 200 && $0.sealed }.count
            let others = parallel.filter { $0.status != 200 || !$0.sealed }.map { "\($0.status) \($0.sealed ? "sealed" : "plain")" }
            print("parallel session/end + 12 catalog ->", "\(good)/\(parallel.count) sealed 200", others.isEmpty ? "" : "\(others)")
            guard good == parallel.count else {
                throw SecureSetupError("a parallel request failed or fell back to plain")
            }
        } catch {
            print("FAILED:", error)
            exit(1)
        }
    }

    static func send(_ method: String, _ path: String, query: [URLQueryItem] = [], body: Data? = nil) async throws -> Reply {
        guard var components = URLComponents(url: base.appendingPathComponent(path), resolvingAgainstBaseURL: false) else {
            throw SecureSetupError("bad URL")
        }
        components.queryItems = query.isEmpty ? nil : query
        guard let url = components.url else { throw SecureSetupError("bad URL") }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.httpMethod = method
        request.httpBody = body
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? ""
        ["Accept": "application/json", "X-Platform": "ios", "X-App-Version": version, "X-Language": "en",
         "X-Timezone": TimeZone.current.identifier].forEach { request.setValue($1, forHTTPHeaderField: $0) }
        if body != nil {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        if SecureChannel.isEnabled {
            do {
                let (data, response) = try await SecureChannel.shared.send(request) { try await exchange($0) }
                return Reply(status: response.statusCode, data: data, sealed: true)
            } catch SecureChannelError.unavailable {
                // ENVELOPE_MODE=optional: the plain request below still works.
            }
        }
        let (data, response) = try await exchange(request)
        return Reply(status: response.statusCode, data: data, sealed: false)
    }

    @Sendable static func exchange(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw SecureSetupError("no HTTP response") }
        return (data, http)
    }
}
