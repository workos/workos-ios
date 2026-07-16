// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation
import Testing

@testable import WorkOS

/// Tests for the hand-maintained Passwordless (Magic Link) resource.
@Suite struct PasswordlessTests {
    @Test func resourceIsReachable() {
        let (client, _) = makeTestClient()
        _ = client.passwordless
        #expect(client.configuration.apiKey == "sk_test_123")
    }

    @Test func createSessionSendsExpectedRequest() async throws {
        let (client, recorder) = makeTestClient(
            responding:
                #"{"id":"passwordless_session_01EHDAK2BFGWCSZXP9HGZ3VK8C","email":"marcelina.davis@example.com","expires_at":"2026-01-15T12:00:00.000Z","link":"https://auth.workos.com/passwordless/token/confirm","object":"passwordless_session"}"#
        )
        let session = try await client.passwordless.createSession(
            email: "marcelina.davis@example.com",
            redirectUri: "https://example.com/callback",
            state: "state-123"
        )

        let request = try #require(recorder.lastRequest)
        #expect(request.httpMethod == "POST")
        #expect(request.url?.path == "/passwordless/sessions")
        let body = try #require(recorder.lastBody)
        let json = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        #expect(json?["email"] as? String == "marcelina.davis@example.com")
        #expect(json?["type"] as? String == "MagicLink")
        #expect(json?["redirect_uri"] as? String == "https://example.com/callback")
        #expect(json?["state"] as? String == "state-123")
        #expect(session.id == "passwordless_session_01EHDAK2BFGWCSZXP9HGZ3VK8C")
        #expect(session.email == "marcelina.davis@example.com")
        #expect(session.link == "https://auth.workos.com/passwordless/token/confirm")
        #expect(session.object == "passwordless_session")
    }

    @Test func sendSessionSendsExpectedRequest() async throws {
        let (client, recorder) = makeTestClient(responding: #"{"success":true}"#)
        try await client.passwordless.sendSession(
            sessionId: "passwordless_session_01EHDAK2BFGWCSZXP9HGZ3VK8C")

        let request = try #require(recorder.lastRequest)
        #expect(request.httpMethod == "POST")
        #expect(
            request.url?.path
                == "/passwordless/sessions/passwordless_session_01EHDAK2BFGWCSZXP9HGZ3VK8C/send")
    }
}
