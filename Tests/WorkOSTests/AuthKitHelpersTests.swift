// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation
import Testing

@testable import WorkOS

/// Tests for the hand-maintained AuthKit helpers (H09-H12).
@Suite struct AuthKitHelpersTests {
    // MARK: - H09: authorization URL builder

    @Test func authorizationUrlCarriesAllParameters() throws {
        let (client, _) = makeHelperTestClient(clientID: "client_abc")
        let url = try client.getAuthKitAuthorizationUrl(
            redirectUri: "https://example.com/callback",
            provider: "GoogleOAuth",
            organizationId: "org_123",
            loginHint: "user@example.com",
            state: "state-1",
            screenHint: "sign-up"
        )

        #expect(url.path == "/user_management/authorize")
        let query = queryDictionary(of: url)
        #expect(query["client_id"] == "client_abc")
        #expect(query["redirect_uri"] == "https://example.com/callback")
        #expect(query["response_type"] == "code")
        #expect(query["provider"] == "GoogleOAuth")
        #expect(query["organization_id"] == "org_123")
        #expect(query["login_hint"] == "user@example.com")
        #expect(query["state"] == "state-1")
        #expect(query["screen_hint"] == "sign-up")
    }

    @Test func authorizationUrlThrowsWithoutClientID() {
        let (client, _) = makeHelperTestClient(clientID: nil)
        #expect(throws: HelperError.missingClientID) {
            try client.getAuthKitAuthorizationUrl(redirectUri: "https://example.com/callback")
        }
    }

    @Test func authorizationUrlAcceptsExplicitClientID() throws {
        let (client, _) = makeHelperTestClient(clientID: nil)
        let url = try client.getAuthKitAuthorizationUrl(
            redirectUri: "https://example.com/callback", clientId: "client_override")
        #expect(queryDictionary(of: url)["client_id"] == "client_override")
    }

    // MARK: - H10: PKCE authorization URL

    @Test func pkceAuthorizationUrlGeneratesChallengeAndState() throws {
        let (client, _) = makeHelperTestClient(clientID: "client_abc")
        let result = try client.getAuthKitAuthorizationUrlWithPKCE(
            redirectUri: "https://example.com/callback")

        let query = queryDictionary(of: result.url)
        #expect(query["code_challenge_method"] == "S256")
        #expect(query["code_challenge"] == PKCE.generateCodeChallenge(for: result.codeVerifier))
        #expect(query["state"] == result.state)
        #expect(!result.state.isEmpty)
        #expect(result.codeVerifier.count == 43)
    }

    @Test func pkceAuthorizationUrlHonorsProvidedState() throws {
        let (client, _) = makeHelperTestClient(clientID: "client_abc")
        let result = try client.getAuthKitAuthorizationUrlWithPKCE(
            redirectUri: "https://example.com/callback", state: "my-state")
        #expect(result.state == "my-state")
        #expect(queryDictionary(of: result.url)["state"] == "my-state")
    }

    // MARK: - H11: PKCE code exchange

    @Test func pkceCodeExchangeSendsCodeVerifier() async throws {
        let (client, recorder) = makeHelperTestClient(responding: authenticateResponseJSON)
        let response = try await client.authKitPKCECodeExchange(
            code: "code_123", codeVerifier: "verifier_456")

        let request = try #require(recorder.lastRequest)
        #expect(request.httpMethod == "POST")
        #expect(request.url?.path == "/user_management/authenticate")
        let body = try #require(recorder.lastBody)
        let json = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        #expect(json?["grant_type"] as? String == "authorization_code")
        #expect(json?["code"] as? String == "code_123")
        #expect(json?["code_verifier"] as? String == "verifier_456")
        #expect(json?["client_id"] as? String == "client_test_123")
        #expect(json?["client_secret"] as? String == "sk_test_123")
        #expect(response.user.id == "user_01E4ZCR3C56J083X43JQXF3JK5")
    }

    // MARK: - H12: device flow

    @Test func startDeviceAuthorizationSendsClientID() async throws {
        let (client, recorder) = makeHelperTestClient(
            clientID: "client_abc",
            responding:
                #"{"device_code":"CVE2wOfIFK4vhmiDBntpX9s8KT2f0qngpWYL0LGy9HxYgBRXUKIUkZB9BgIFho5h","user_code":"BCDF-GHJK","verification_uri":"https://authkit_domain/device","verification_uri_complete":"https://authkit_domain/device?user_code=BCDF-GHJK","expires_in":300,"interval":5}"#
        )
        let response = try await client.authKitStartDeviceAuthorization()

        let request = try #require(recorder.lastRequest)
        #expect(request.httpMethod == "POST")
        #expect(request.url?.path == "/user_management/authorize/device")
        let body = try #require(recorder.lastBody)
        let json = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        #expect(json?["client_id"] as? String == "client_abc")
        #expect(response.userCode == "BCDF-GHJK")
    }

    @Test func startDeviceAuthorizationThrowsWithoutClientID() async {
        let (client, _) = makeHelperTestClient(clientID: nil)
        await #expect(throws: HelperError.missingClientID) {
            _ = try await client.authKitStartDeviceAuthorization()
        }
    }

    @Test func pollDeviceCodeRetriesWhilePending() async throws {
        let pending = MockURLProtocol.Stub(
            statusCode: 400,
            data: Data(
                #"{"error":"authorization_pending","error_description":"Authorization pending"}"#
                    .utf8),
            headers: [:]
        )
        let success = MockURLProtocol.Stub(
            statusCode: 200, data: Data(authenticateResponseJSON.utf8), headers: [:])
        let (client, recorder) = makeHelperTestClient(stubs: [pending, success])

        let response = try await client.authKitPollDeviceCode(
            deviceCode: "device_code_123", interval: 1)

        #expect(recorder.allRequests.count == 2)
        #expect(response.accessToken == "eyJhb.nNzb19vaWRjX2tleV9.lc5Uk4yWVk5In0")
        let body = try #require(recorder.lastBody)
        let json = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        #expect(
            json?["grant_type"] as? String == "urn:ietf:params:oauth:grant-type:device_code")
        #expect(json?["device_code"] as? String == "device_code_123")
    }

    @Test func pollDeviceCodePropagatesTerminalErrors() async {
        let (client, _) = makeHelperTestClient(
            statusCode: 400,
            responding: #"{"error":"expired_token","error_description":"Device code expired"}"#
        )
        await #expect(throws: WorkOSError.self) {
            _ = try await client.authKitPollDeviceCode(deviceCode: "device_code_123", interval: 1)
        }
    }
}
