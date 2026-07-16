// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation

@testable import WorkOS

/// Build a mocked client like `makeTestClient`, but with a configurable
/// client ID and API key for exercising the hand-maintained helper layer.
func makeHelperTestClient(
    clientID: String? = "client_test_123",
    apiKey: String = "sk_test_123",
    stubs: [MockURLProtocol.Stub]
) -> (WorkOSClient, RequestRecorder) {
    let host = "mock-\(UUID().uuidString.lowercased()).example.test"
    MockURLProtocol.register(host: host, stubs: stubs)
    let sessionConfig = URLSessionConfiguration.ephemeral
    sessionConfig.protocolClasses = [MockURLProtocol.self]
    let session = URLSession(configuration: sessionConfig)
    let configuration = Configuration(
        apiKey: apiKey, baseURL: URL(string: "https://\(host)")!, clientID: clientID)
    let client = WorkOSClient(
        configuration: configuration,
        transport: Transport(configuration: configuration, session: session))
    return (client, RequestRecorder(host: host))
}

/// Convenience: a single canned response with a configurable client ID.
func makeHelperTestClient(
    clientID: String? = "client_test_123",
    apiKey: String = "sk_test_123",
    statusCode: Int = 200,
    responding body: String = "{}"
) -> (WorkOSClient, RequestRecorder) {
    makeHelperTestClient(
        clientID: clientID,
        apiKey: apiKey,
        stubs: [MockURLProtocol.Stub(statusCode: statusCode, data: Data(body.utf8), headers: [:])]
    )
}

/// Decode a URL's query string into a dictionary for assertions.
func queryDictionary(of url: URL) -> [String: String] {
    let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
    var result: [String: String] = [:]
    for item in components?.queryItems ?? [] {
        result[item.name] = item.value
    }
    return result
}

/// Build an unsigned test JWT with the given claims payload.
func makeTestJWT(claims: [String: Any]) -> String {
    let header = Data(#"{"alg":"none","typ":"JWT"}"#.utf8)
    let payload = try! JSONSerialization.data(withJSONObject: claims)
    let encode = { (data: Data) -> String in
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    return "\(encode(header)).\(encode(payload)).signature"
}

/// A canned `AuthenticateResponse` body matching the generated fixtures.
let authenticateResponseJSON = #"""
    {"user":{"object":"user","id":"user_01E4ZCR3C56J083X43JQXF3JK5","first_name":"Marcelina","last_name":"Davis","name":"Marcelina Davis","profile_picture_url":"https://workoscdn.com/images/v1/123abc","email":"marcelina.davis@example.com","email_verified":true,"external_id":"f1ffa2b2-c20b-4d39-be5c-212726e11222","metadata":{"timezone":"America/New_York"},"last_sign_in_at":"2025-06-25T19:07:33.155Z","locale":"en-US","created_at":"2026-01-15T12:00:00.000Z","updated_at":"2026-01-15T12:00:00.000Z"},"organization_id":"org_01H945H0YD4F97JN9MATX7BYAG","authkit_authorization_code":"authkit_authz_code_abc123","access_token":"eyJhb.nNzb19vaWRjX2tleV9.lc5Uk4yWVk5In0","refresh_token":"yAjhKk123NLIjdrBdGZPf8pLIDvK","authentication_method":"SSO","impersonator":{"email":"admin@foocorp.com","reason":"Investigating an issue with the customer's account."},"oauth_tokens":{"provider":"GoogleOAuth","refresh_token":"1//04g...","access_token":"ya29.a0ARrdaM...","expires_at":1735141800,"scopes":["profile","email","openid"]}}
    """#
