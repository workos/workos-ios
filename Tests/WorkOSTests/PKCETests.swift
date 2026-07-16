// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation
import Testing

@testable import WorkOS

/// Tests for the hand-maintained PKCE utilities (H08).
@Suite struct PKCETests {
    @Test func generateCodeVerifierDefaultLength() throws {
        let verifier = try PKCE.generateCodeVerifier()
        #expect(verifier.count == 43)
    }

    @Test func generateCodeVerifierCustomLength() throws {
        let verifier = try PKCE.generateCodeVerifier(length: 128)
        #expect(verifier.count == 128)
    }

    @Test func generateCodeVerifierUsesUnreservedCharacters() throws {
        let allowed = CharacterSet(
            charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        let verifier = try PKCE.generateCodeVerifier(length: 64)
        #expect(verifier.unicodeScalars.allSatisfy { allowed.contains($0) })
    }

    @Test func generateCodeVerifierRejectsInvalidLengths() {
        #expect(throws: PKCEError.invalidVerifierLength(42)) {
            try PKCE.generateCodeVerifier(length: 42)
        }
        #expect(throws: PKCEError.invalidVerifierLength(129)) {
            try PKCE.generateCodeVerifier(length: 129)
        }
    }

    @Test func generateCodeChallengeMatchesRFC7636Vector() {
        // RFC 7636 appendix B test vector.
        let challenge = PKCE.generateCodeChallenge(
            for: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        #expect(challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }

    @Test func generatePairIsInternallyConsistent() throws {
        let pair = try PKCE.generatePair()
        #expect(pair.codeChallengeMethod == "S256")
        #expect(pair.codeChallenge == PKCE.generateCodeChallenge(for: pair.codeVerifier))
        #expect(pair.codeVerifier.count == 43)
    }

    @Test func generatePairProducesUniqueVerifiers() throws {
        let first = try PKCE.generatePair()
        let second = try PKCE.generatePair()
        #expect(first.codeVerifier != second.codeVerifier)
    }
}
