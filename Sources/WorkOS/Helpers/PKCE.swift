// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import CryptoKit
import Foundation

/// A PKCE code verifier and its derived S256 code challenge.
public struct PKCEPair: Sendable, Equatable {
    /// The high-entropy code verifier, stored client-side until token exchange.
    public let codeVerifier: String
    /// The S256 code challenge sent on the authorization request.
    public let codeChallenge: String
    /// The challenge method. Always `"S256"`.
    public let codeChallengeMethod: String

    public init(codeVerifier: String, codeChallenge: String, codeChallengeMethod: String = "S256") {
        self.codeVerifier = codeVerifier
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
    }
}

/// Errors thrown by PKCE helpers.
public enum PKCEError: Error, Equatable, Sendable {
    /// The requested verifier length is outside the RFC 7636 range of 43-128.
    case invalidVerifierLength(Int)
}

/// PKCE (RFC 7636) utilities: code verifier, code challenge, and pair generation.
public enum PKCE {
    /// Generate a cryptographically random code verifier.
    /// The length must be between 43 and 128 characters (default 43).
    public static func generateCodeVerifier(length: Int = 43) throws -> String {
        guard (43...128).contains(length) else {
            throw PKCEError.invalidVerifierLength(length)
        }
        // Enough random bytes so that unpadded base64url yields at least
        // `length` characters: each 3 bytes produce 4 characters.
        let byteLength = (length * 3 + 3) / 4
        let encoded = HelperSupport.base64URLEncode(HelperSupport.randomBytes(byteLength))
        return String(encoded.prefix(length))
    }

    /// Compute the S256 code challenge for a code verifier.
    public static func generateCodeChallenge(for verifier: String) -> String {
        let digest = SHA256.hash(data: Data(verifier.utf8))
        return HelperSupport.base64URLEncode(Data(digest))
    }

    /// Generate a complete PKCE pair (verifier plus S256 challenge).
    public static func generatePair() throws -> PKCEPair {
        let verifier = try generateCodeVerifier()
        return PKCEPair(
            codeVerifier: verifier,
            codeChallenge: generateCodeChallenge(for: verifier)
        )
    }
}
