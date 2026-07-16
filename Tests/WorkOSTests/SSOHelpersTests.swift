// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation
import Testing

@testable import WorkOS

/// Tests for the hand-maintained SSO helpers (H14-H17).
@Suite struct SSOHelpersTests {
    static let ssoTokenResponseJSON = #"""
        {"token_type":"Bearer","access_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6InNzby...","expires_in":600,"profile":{"object":"profile","id":"prof_01DMC79VCBZ0NY2099737PSVF1","organization_id":"org_01EHQMYV6MBK39QC5PZXHY59C3","connection_id":"conn_01E4ZCR3C56J083X43JQXF3JK5","connection_type":"OktaSAML","idp_id":"103456789012345678901","email":"todd@example.com","first_name":"Todd","last_name":"Rundgren","name":"Todd Rundgren","role":{"slug":"admin"},"roles":[{"slug":"admin"}],"groups":["Engineering","Admins"],"custom_attributes":{"key":{}},"raw_attributes":{"key":{}}},"oauth_tokens":{"provider":"GoogleOAuth","refresh_token":"1//04g...","access_token":"ya29.a0ARrdaM...","expires_at":1735141800,"scopes":["profile","email","openid"]}}
        """#

    // MARK: - H14: authorization URL builder

    @Test func ssoAuthorizationUrlCarriesAllParameters() throws {
        let (client, _) = makeHelperTestClient(clientID: "client_abc")
        let url = try client.getSSOAuthorizationUrl(
            redirectUri: "https://example.com/callback",
            connectionId: "conn_123",
            domainHint: "example.com",
            state: "state-1"
        )

        #expect(url.path == "/sso/authorize")
        let query = queryDictionary(of: url)
        #expect(query["client_id"] == "client_abc")
        #expect(query["redirect_uri"] == "https://example.com/callback")
        #expect(query["response_type"] == "code")
        #expect(query["connection_id"] == "conn_123")
        #expect(query["domain_hint"] == "example.com")
        #expect(query["state"] == "state-1")
    }

    @Test func ssoAuthorizationUrlThrowsWithoutClientID() {
        let (client, _) = makeHelperTestClient(clientID: nil)
        #expect(throws: HelperError.missingClientID) {
            try client.getSSOAuthorizationUrl(redirectUri: "https://example.com/callback")
        }
    }

    // MARK: - H15: PKCE authorization URL

    @Test func ssoPkceAuthorizationUrlGeneratesChallengeAndState() throws {
        let (client, _) = makeHelperTestClient(clientID: "client_abc")
        let result = try client.getSSOAuthorizationUrlWithPKCE(
            redirectUri: "https://example.com/callback")

        let query = queryDictionary(of: result.url)
        #expect(query["code_challenge_method"] == "S256")
        #expect(query["code_challenge"] == PKCE.generateCodeChallenge(for: result.codeVerifier))
        #expect(query["state"] == result.state)
        #expect(!result.state.isEmpty)
    }

    // MARK: - H16: PKCE code exchange

    @Test func ssoPkceCodeExchangeSendsCodeVerifier() async throws {
        let (client, recorder) = makeHelperTestClient(responding: Self.ssoTokenResponseJSON)
        let response = try await client.ssoPKCECodeExchange(
            code: "code_123", codeVerifier: "verifier_456")

        let request = try #require(recorder.lastRequest)
        #expect(request.httpMethod == "POST")
        #expect(request.url?.path == "/sso/token")
        let body = try #require(recorder.lastBody)
        let json = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        #expect(json?["grant_type"] as? String == "authorization_code")
        #expect(json?["code"] as? String == "code_123")
        #expect(json?["code_verifier"] as? String == "verifier_456")
        #expect(json?["client_id"] as? String == "client_test_123")
        #expect(json?["client_secret"] as? String == "sk_test_123")
        #expect(response.profile.id == "prof_01DMC79VCBZ0NY2099737PSVF1")
    }

    // MARK: - H17: logout flow

    @Test func ssoLogoutAuthorizesAndBuildsRedirectUrl() async throws {
        let (client, recorder) = makeHelperTestClient(
            responding:
                #"{"logout_url":"https://auth.workos.com/sso/logout?token=eyJhbGciOiJSUzI1NiJ9","logout_token":"logout_token_abc123"}"#
        )
        let url = try await client.ssoLogout(
            sessionId: "prof_01DMC79VCBZ0NY2099737PSVF1",
            returnTo: "https://example.com/goodbye"
        )

        let request = try #require(recorder.lastRequest)
        #expect(request.httpMethod == "POST")
        #expect(request.url?.path == "/sso/logout/authorize")
        let body = try #require(recorder.lastBody)
        let json = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        #expect(json?["profile_id"] as? String == "prof_01DMC79VCBZ0NY2099737PSVF1")

        #expect(url.path == "/sso/logout")
        let query = queryDictionary(of: url)
        #expect(query["token"] == "logout_token_abc123")
        #expect(query["return_to"] == "https://example.com/goodbye")
    }
}
