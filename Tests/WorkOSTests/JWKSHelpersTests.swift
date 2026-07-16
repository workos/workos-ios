// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation
import Testing

@testable import WorkOS

/// Tests for the hand-maintained JWKS helpers (H13).
@Suite struct JWKSHelpersTests {
    @Test func urlBuilderUsesDefaultBaseURL() {
        let url = JWKS.url(clientID: "client_123")
        #expect(url.absoluteString == "https://api.workos.com/sso/jwks/client_123")
    }

    @Test func urlBuilderHonorsCustomBaseURL() {
        let url = JWKS.url(
            baseURL: URL(string: "https://api.example.test")!, clientID: "client_123")
        #expect(url.absoluteString == "https://api.example.test/sso/jwks/client_123")
    }

    @Test func clientJwksURLUsesConfiguredClientID() throws {
        let (client, _) = makeHelperTestClient(clientID: "client_abc")
        let url = try client.jwksURL()
        #expect(url.path == "/sso/jwks/client_abc")
    }

    @Test func clientJwksURLThrowsWithoutClientID() {
        let (client, _) = makeHelperTestClient(clientID: nil)
        #expect(throws: HelperError.missingClientID) {
            try client.jwksURL()
        }
    }

    @Test func getJwksFetchesKeySet() async throws {
        let (client, recorder) = makeHelperTestClient(
            clientID: "client_abc",
            responding:
                #"{"keys":[{"alg":"RS256","kty":"RSA","use":"sig","x5c":["MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBCwUA..."],"n":"0vx7agoebGc...eKnNs","e":"AQAB","kid":"key_01HXYZ123456789ABCDEFGHIJ","x5t#S256":"ZjQzYjI0OT...NmNjU0"}]}"#
        )
        let response = try await client.getJwks()

        let request = try #require(recorder.lastRequest)
        #expect(request.httpMethod == "GET")
        #expect(request.url?.path == "/sso/jwks/client_abc")
        #expect(response.keys.count == 1)
    }

    @Test func getJwksThrowsWithoutClientID() async {
        let (client, _) = makeHelperTestClient(clientID: nil)
        await #expect(throws: HelperError.missingClientID) {
            _ = try await client.getJwks()
        }
    }
}
