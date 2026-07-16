// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation
import Testing

@testable import WorkOS

/// Tests for the hand-maintained public-client factory (H19).
@Suite struct PublicClientTests {
    /// Build a `PublicClient` whose transport is mocked, mirroring
    /// `makeHelperTestClient` but with an empty API key.
    static func makePublicClient(
        stubs: [MockURLProtocol.Stub] = []
    ) -> (PublicClient, RequestRecorder) {
        let (client, recorder) = makeHelperTestClient(
            clientID: "client_public_123", apiKey: "", stubs: stubs)
        return (PublicClient(client: client), recorder)
    }

    @Test func initRequiresNoAPIKey() throws {
        let publicClient = PublicClient(clientID: "client_public_123")
        let url = try publicClient.getAuthorizationUrl(
            redirectUri: "https://example.com/callback")
        #expect(url.host == "api.workos.com")
        #expect(queryDictionary(of: url)["client_id"] == "client_public_123")
    }

    @Test func initHonorsCustomBaseURL() throws {
        let publicClient = PublicClient(
            clientID: "client_public_123", baseURL: URL(string: "https://api.example.test")!)
        let url = try publicClient.getAuthorizationUrl(
            redirectUri: "https://example.com/callback")
        #expect(url.host == "api.example.test")
    }

    @Test func authorizationUrlWithPKCEIsConsistent() throws {
        let publicClient = PublicClient(clientID: "client_public_123")
        let result = try publicClient.getAuthorizationUrlWithPKCE(
            redirectUri: "https://example.com/callback")
        let query = queryDictionary(of: result.url)
        #expect(query["code_challenge"] == PKCE.generateCodeChallenge(for: result.codeVerifier))
        #expect(query["code_challenge_method"] == "S256")
        #expect(query["state"] == result.state)
    }

    @Test func ssoAuthorizationUrlWithPKCEIsConsistent() throws {
        let publicClient = PublicClient(clientID: "client_public_123")
        let result = try publicClient.getSSOAuthorizationUrlWithPKCE(
            redirectUri: "https://example.com/callback")
        let query = queryDictionary(of: result.url)
        #expect(query["code_challenge"] == PKCE.generateCodeChallenge(for: result.codeVerifier))
        #expect(query["state"] == result.state)
    }

    @Test func authenticateWithCodeOmitsClientSecret() async throws {
        let (publicClient, recorder) = Self.makePublicClient(stubs: [
            MockURLProtocol.Stub(
                statusCode: 200, data: Data(authenticateResponseJSON.utf8), headers: [:])
        ])
        let response = try await publicClient.authenticateWithCode(
            code: "code_123", codeVerifier: "verifier_456")

        let body = try #require(recorder.lastBody)
        let json = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        #expect(json?["client_id"] as? String == "client_public_123")
        #expect(json?["code_verifier"] as? String == "verifier_456")
        #expect(json?["client_secret"] == nil)
        #expect(response.user.email == "marcelina.davis@example.com")
    }

    @Test func ssoProfileAndTokenWithPKCEOmitsClientSecret() async throws {
        let (publicClient, recorder) = Self.makePublicClient(stubs: [
            MockURLProtocol.Stub(
                statusCode: 200, data: Data(SSOHelpersTests.ssoTokenResponseJSON.utf8),
                headers: [:])
        ])
        _ = try await publicClient.getSSOProfileAndTokenWithPKCE(
            code: "code_123", codeVerifier: "verifier_456")

        let request = try #require(recorder.lastRequest)
        #expect(request.url?.path == "/sso/token")
        let body = try #require(recorder.lastBody)
        let json = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        #expect(json?["client_secret"] == nil)
    }

    @Test func createDeviceUsesConfiguredClientID() async throws {
        let (publicClient, recorder) = Self.makePublicClient(stubs: [
            MockURLProtocol.Stub(
                statusCode: 200,
                data: Data(
                    #"{"device_code":"device_abc","user_code":"BCDF-GHJK","verification_uri":"https://authkit_domain/device","verification_uri_complete":"https://authkit_domain/device?user_code=BCDF-GHJK","expires_in":300,"interval":5}"#
                        .utf8),
                headers: [:])
        ])
        let response = try await publicClient.createDevice()

        let request = try #require(recorder.lastRequest)
        #expect(request.url?.path == "/user_management/authorize/device")
        let body = try #require(recorder.lastBody)
        let json = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        #expect(json?["client_id"] as? String == "client_public_123")
        #expect(response.deviceCode == "device_abc")
    }

    @Test func jwksURLUsesConfiguredClientID() throws {
        let publicClient = PublicClient(clientID: "client_public_123")
        let url = try publicClient.jwksURL()
        #expect(url.absoluteString == "https://api.workos.com/sso/jwks/client_public_123")
    }
}
