// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation
import Testing

@testable import WorkOS

/// Tests for the hand-maintained session helpers (H04-H07).
@Suite struct SessionHelpersTests {
    static let cookiePassword = "test-cookie-password-with-enough-entropy"

    static func makeAccessToken(expiresIn: TimeInterval = 3600) -> String {
        makeTestJWT(claims: [
            "sid": "session_123",
            "org_id": "org_456",
            "role": "admin",
            "permissions": ["posts:read"],
            "entitlements": ["audit-logs"],
            "exp": Int(Date().addingTimeInterval(expiresIn).timeIntervalSince1970),
        ])
    }

    static func makeSealedSession(expiresIn: TimeInterval = 3600) throws -> String {
        try Session.sealSession(
            accessToken: makeAccessToken(expiresIn: expiresIn),
            refreshToken: "rt_123",
            cookiePassword: cookiePassword
        )
    }

    // MARK: - H06: raw seal/unseal

    @Test func sealUnsealRoundTrip() throws {
        let sealed = try SessionSealing.seal(["hello": "world"], password: Self.cookiePassword)
        let unsealed: [String: String] = try SessionSealing.unseal(
            sealed, password: Self.cookiePassword)
        #expect(unsealed == ["hello": "world"])
    }

    @Test func sealUnsealRoundTripWithHexPassword() throws {
        let hexPassword = String(repeating: "ab", count: 32)
        let sealed = try SessionSealing.seal(["k": "v"], password: hexPassword)
        let unsealed: [String: String] = try SessionSealing.unseal(sealed, password: hexPassword)
        #expect(unsealed == ["k": "v"])
    }

    @Test func unsealWithWrongPasswordThrows() throws {
        let sealed = try SessionSealing.seal(["k": "v"], password: Self.cookiePassword)
        #expect(throws: SessionSealingError.self) {
            let _: [String: String] = try SessionSealing.unseal(sealed, password: "wrong")
        }
    }

    // MARK: - H04: session cookie object

    @Test func authenticateAcceptsValidSession() throws {
        let sealed = try Self.makeSealedSession()
        let session = Session(sessionData: sealed, cookiePassword: Self.cookiePassword)
        let result = session.authenticate()

        #expect(result.authenticated)
        #expect(result.sessionId == "session_123")
        #expect(result.organizationId == "org_456")
        #expect(result.role == "admin")
        #expect(result.permissions == ["posts:read"])
        #expect(result.entitlements == ["audit-logs"])
        #expect(!result.needsRefresh)
        #expect(result.reason == nil)
    }

    @Test func authenticateFlagsExpiredTokenForRefresh() throws {
        let sealed = try Self.makeSealedSession(expiresIn: -3600)
        let result = Session.authenticate(
            sealedSession: sealed, cookiePassword: Self.cookiePassword)

        #expect(!result.authenticated)
        #expect(result.needsRefresh)
        #expect(result.reason == "session_expired")
        #expect(result.sessionId == "session_123")
    }

    @Test func authenticateRejectsEmptySession() {
        let result = Session.authenticate(sealedSession: "", cookiePassword: Self.cookiePassword)
        #expect(!result.authenticated)
        #expect(result.reason == "no_session_cookie_provided")
    }

    @Test func authenticateRejectsGarbageSession() {
        let result = Session.authenticate(
            sealedSession: "not-a-sealed-session", cookiePassword: Self.cookiePassword)
        #expect(!result.authenticated)
        #expect(result.reason == "invalid_session_cookie")
    }

    @Test func authenticateRejectsWrongPassword() throws {
        let sealed = try Self.makeSealedSession()
        let result = Session.authenticate(sealedSession: sealed, cookiePassword: "wrong-password")
        #expect(!result.authenticated)
        #expect(result.reason == "invalid_session_cookie")
    }

    @Test func refreshExchangesRefreshTokenAndReseals() async throws {
        let sealed = try Self.makeSealedSession()
        let (client, recorder) = makeHelperTestClient(responding: authenticateResponseJSON)

        let session = client.loadSealedSession(
            sessionData: sealed, cookiePassword: Self.cookiePassword)
        let result = try await session.refresh()

        let request = try #require(recorder.lastRequest)
        #expect(request.httpMethod == "POST")
        #expect(request.url?.path == "/user_management/authenticate")
        let body = try #require(recorder.lastBody)
        let json = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        #expect(json?["grant_type"] as? String == "refresh_token")
        #expect(json?["refresh_token"] as? String == "rt_123")
        #expect(json?["organization_id"] as? String == "org_456")

        #expect(result.authenticated)
        #expect(result.session?.accessToken == "eyJhb.nNzb19vaWRjX2tleV9.lc5Uk4yWVk5In0")

        // The new sealed session unseals with the same cookie password.
        let resealed = try #require(result.sealedSession)
        let unsealed: SessionData = try SessionSealing.unseal(
            resealed, password: Self.cookiePassword)
        #expect(unsealed.refreshToken == "yAjhKk123NLIjdrBdGZPf8pLIDvK")
    }

    @Test func refreshReportsRevokedToken() async throws {
        let sealed = try Self.makeSealedSession()
        let (client, _) = makeHelperTestClient(
            statusCode: 401,
            responding: #"{"error":"invalid_grant","error_description":"Refresh token revoked"}"#
        )
        let result = try await client.refreshSession(
            sealedSession: sealed, cookiePassword: Self.cookiePassword)

        #expect(!result.authenticated)
        #expect(result.reason == "refresh_token_revoked")
    }

    @Test func refreshWithoutClientThrows() async throws {
        let sealed = try Self.makeSealedSession()
        let session = Session(sessionData: sealed, cookiePassword: Self.cookiePassword)
        await #expect(throws: SessionError.clientRequired) {
            _ = try await session.refresh()
        }
    }

    @Test func getLogoutUrlCarriesSessionID() throws {
        let sealed = try Self.makeSealedSession()
        let session = Session(sessionData: sealed, cookiePassword: Self.cookiePassword)
        let url = try session.getLogoutUrl(returnTo: "https://example.com/goodbye")

        #expect(url.path == "/user_management/sessions/logout")
        let query = queryDictionary(of: url)
        #expect(query["session_id"] == "session_123")
        #expect(query["return_to"] == "https://example.com/goodbye")
    }

    @Test func getLogoutUrlWorksForExpiredSessions() throws {
        let sealed = try Self.makeSealedSession(expiresIn: -3600)
        let session = Session(sessionData: sealed, cookiePassword: Self.cookiePassword)
        let url = try session.getLogoutUrl()
        #expect(queryDictionary(of: url)["session_id"] == "session_123")
    }

    // MARK: - H07: sealed session from auth response

    @Test func sealFromAuthResponseRoundTrips() throws {
        let response = try Coding.makeDecoder().decode(
            AuthenticateResponse.self, from: Data(authenticateResponseJSON.utf8))
        let sealed = try Session.seal(from: response, cookiePassword: Self.cookiePassword)

        let unsealed: SessionData = try SessionSealing.unseal(
            sealed, password: Self.cookiePassword)
        #expect(unsealed.accessToken == response.accessToken)
        #expect(unsealed.refreshToken == response.refreshToken)
        #expect(unsealed.user?.id == response.user.id)
        #expect(unsealed.impersonator?.email == "admin@foocorp.com")
    }
}
