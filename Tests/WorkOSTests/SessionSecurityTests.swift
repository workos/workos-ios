// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import CryptoKit
import Foundation
import Security
import Testing

@testable import WorkOS

@Suite struct SessionSecurityTests {
    private static let password = String(repeating: "a", count: 32)
    // Public test-only RSA key, generated for this suite; never used by WorkOS.
    private static let privateKeyBase64 =
        "MIIEogIBAAKCAQEAxB7RX4rn8XMOe/Q8YvmQJDsybvAlGr33Y1LmvIrKKX5lAYh/MI18mrZscMaoYkZH0Wsk8iYl43bSdsGCuM6z5I//3jKzzYsPGdYoTd6vmKRcZiWghXbdrcFnto1/7FCtMiGW2vsur+yfCuU+ebSrS3rAr0cNmnj8F0lVVP1GDXKv53HzQ+ECSsFoJfymLa6GbrwdHVoXIj6XQTM91GtNH1ht0HOtNxLf0a8fKL7PIDfdsrFlHbqP5lOuGE/NdUOawbQyAW1phRXQQ9J1pB5vCYAhnUH1m5wN2cknKRjjGP+JMVTN+XIR8HNH8GhO9slTuMS5tnUBQPfzNw0BzjhodQIDAQABAoIBAFIr42fXqHT20zPGUmLZ07YKg4gN4E4DGBsqifinYirehW2OBlSOg43DL05VPgnnDoJFFTbMGwXiLC6Lx7ytBpyWZQtxTPqq8AnQPBTcX9Bh1UELNOWWtyztIwpO4TFfYCHoBu/7XEVjrAOBp5qQw1CdvwvxhlaZqG4NUM6KTAansaUHkSCSfIYK6Q8qL5WKSLTyl29EPgoHBwBfYuaiDjayXoBjVqOc/1I3JC8w1MZFAd8eCiEIVclAxVFDAR4IA+uEoWStH+N3+BOULQpMytkq76KfYU0taK/13phviYDbKihgVLU321Q8QsUmwqH/NXK3oPvlvz8uLETxeU4P6KUCgYEA8It0ABKc/eviDsYAoL0pIMgZ4poixH3Wjqoo4/mBKPi78PRjGj4Qi0K+xYaKnIzAydRJaoa6Zu/7doCEMGbxB3USkF6Chc6EOAe/Jg8ktGVHEHDWmg1HpueM/kPvRutLbhUKiEhuKnOuMNIn1uAN/BAaFFHWRy/FoH5AH4IQ+/MCgYEA0LipGZexETQTbShaFU9QVm8CjNX9FqyZxX0cDYSvykBkq0y5qjmErPde5f9ZiVW4lGKR2JtcBWiCPWkCdQXPNwPxt3ownGMCEkukeS+eFSsJDjaBtwJijkIBswy6Yyouuyc7EzFqYKEkh5sEN3Rrhi5nd6ZIy6RFrGhwRF7Oq/cCgYBJI63ew8oWbx2qLkxMk5eozw8H1qQRqM2PTW/neZrrMU48AqMLfKmdHmtRNgp5dVa9R54XFOYinH+SVZtb+ED7an59hS8crmGHg9t8IAiiDVVhS14FM1qBBlDZkyBzKOIjk6RDMfrFT608TPouHKxD40V6vjNwK7dkiF7I9cxiPwKBgChVBpgjb9vbLEXTnlSv1t5c5SlB0H4pLC21V05lbXKvrsRLNzVll/W0d2oKRcr7/Ybu5S/uFYIWB9TGDet/C+Odp3/E5M/TcfsHEuk4AlwkzMMqVTaAB3tl1d47f2jaJd2UXx3+VogFm4F4uv/cR0rOfL/qKfbv72a5Z7hOebFRAoGATQZEP0ga4h5+vOwuHDimQWhnral9doEJAI7zW8IFsXxq/aVzedom+wlzjB/FIS341bkfMpp3jmuyxJsvBiXsvDwXIXjH65LYKDe9J8+8gMSwn6twxbkKFSU/8eJJAcbokdlZRiIjYeKGjfht8UZrUa1HmLfouH+Qo4NKqsXMSSg="
    private static let modulus =
        "xB7RX4rn8XMOe_Q8YvmQJDsybvAlGr33Y1LmvIrKKX5lAYh_MI18mrZscMaoYkZH0Wsk8iYl43bSdsGCuM6z5I__3jKzzYsPGdYoTd6vmKRcZiWghXbdrcFnto1_7FCtMiGW2vsur-yfCuU-ebSrS3rAr0cNmnj8F0lVVP1GDXKv53HzQ-ECSsFoJfymLa6GbrwdHVoXIj6XQTM91GtNH1ht0HOtNxLf0a8fKL7PIDfdsrFlHbqP5lOuGE_NdUOawbQyAW1phRXQQ9J1pB5vCYAhnUH1m5wN2cknKRjjGP-JMVTN-XIR8HNH8GhO9slTuMS5tnUBQPfzNw0BzjhodQ"
    private static let exponent = "AQAB"

    private static func encode(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private static func token(
        claims: [String: Any]? = nil, header: [String: Any]? = nil
    ) throws -> String {
        let header = header ?? ["alg": "RS256", "kid": "test-key"]
        let claims =
            claims ?? [
                "sub": "user_123", "sid": "session_123", "role": "admin",
                "org_id": "org_456", "permissions": ["posts:read"],
                "exp": Int(Date().timeIntervalSince1970) + 3600,
            ]
        let input =
            try encode(JSONSerialization.data(withJSONObject: header)) + "."
            + encode(JSONSerialization.data(withJSONObject: claims))
        let key = try #require(
            SecKeyCreateWithData(
                Data(base64Encoded: privateKeyBase64)! as CFData,
                [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
                    as CFDictionary, nil))
        let signature = try #require(
            SecKeyCreateSignature(
                key, .rsaSignatureMessagePKCS1v15SHA256, Data(input.utf8) as CFData, nil))
        return input + "." + encode(signature as Data)
    }

    private static func jwks(overrides: [String: Any] = [:], duplicate: Bool = false) throws
        -> String
    {
        var key: [String: Any] = [
            "kid": "test-key", "alg": "RS256", "kty": "RSA", "use": "sig",
            "n": modulus, "e": exponent, "x5c": [], "x5t#S256": "",
        ]
        key.merge(overrides) { _, new in new }
        return String(
            data: try JSONSerialization.data(
                withJSONObject: ["keys": duplicate ? [key, key] : [key]]), encoding: .utf8)!
    }

    private static func sealed(_ token: String, user: User? = nil) throws -> String {
        try Session.sealSession(
            accessToken: token, refreshToken: "rt_123", user: user,
            impersonator: AuthenticateResponseImpersonator(email: "attacker@example.com"),
            cookiePassword: password)
    }

    @Test func verifiesSignedClaimsAndOmitsUnsignedImpersonator() async throws {
        let (client, recorder) = makeHelperTestClient(responding: try Self.jwks())
        let session = try client.loadVerifiedSession(
            sessionData: Self.sealed(Self.token()), cookiePassword: Self.password)
        let result = await session.authenticateVerified()
        #expect(result.authenticated)
        #expect(result.sessionId == "session_123")
        #expect(result.organizationId == "org_456")
        #expect(result.role == "admin")
        #expect(result.permissions == ["posts:read"])
        #expect(result.impersonator == nil)
        #expect(!result.needsRefresh)
        #expect(recorder.lastRequest?.url?.path == "/sso/jwks/client_test_123")
    }

    @Test(arguments: [
        "unsigned", "unsigned-with-exp", "missing-exp", "null-exp", "string-exp", "missing-sub",
        "tampered-payload", "tampered-signature", "unknown-kid", "hs256", "critical",
        "null-critical", "b64", "null-b64", "future-nbf", "malformed", "empty",
    ])
    func rejectsInvalidTokens(attack: String) async throws {
        var token = try Self.token()
        switch attack {
        case "unsigned":
            token = makeTestJWT(claims: [
                "sid": "session_forged", "org_id": "org_VICTIM", "role": "admin",
                "permissions": ["billing:write"],
            ])
        case "unsigned-with-exp":
            token = makeTestJWT(claims: [
                "sub": "user_123", "role": "admin", "sid": "forged", "exp": 4_102_444_800,
            ])
        case "missing-exp": token = try Self.token(claims: ["sub": "user_123"])
        case "null-exp": token = try Self.token(claims: ["sub": "user_123", "exp": NSNull()])
        case "string-exp": token = try Self.token(claims: ["sub": "user_123", "exp": "4102444800"])
        case "missing-sub":
            token = try Self.token(claims: ["exp": Int(Date().timeIntervalSince1970) + 3600])
        case "tampered-payload":
            var parts = token.components(separatedBy: ".")
            parts[1] = Self.encode(Data(#"{"sub":"victim","role":"admin","exp":4102444800}"#.utf8))
            token = parts.joined(separator: ".")
        case "tampered-signature":
            var parts = token.components(separatedBy: ".")
            parts[2] = Self.encode(Data(repeating: 0, count: 256))
            token = parts.joined(separator: ".")
        case "unknown-kid": token = try Self.token(header: ["alg": "RS256", "kid": "unknown"])
        case "hs256": token = try Self.token(header: ["alg": "HS256", "kid": "test-key"])
        case "critical":
            token = try Self.token(header: ["alg": "RS256", "kid": "test-key", "crit": ["custom"]])
        case "null-critical":
            token = try Self.token(header: ["alg": "RS256", "kid": "test-key", "crit": NSNull()])
        case "b64":
            token = try Self.token(header: ["alg": "RS256", "kid": "test-key", "b64": false])
        case "null-b64":
            token = try Self.token(header: ["alg": "RS256", "kid": "test-key", "b64": NSNull()])
        case "future-nbf":
            token = try Self.token(claims: [
                "sub": "user_123", "exp": 4_102_444_800, "nbf": 4_102_444_800,
            ])
        case "malformed": token = "a.b.c.d"
        case "empty": token = ""
        default: Issue.record("Unhandled attack")
        }
        let (client, _) = makeHelperTestClient(responding: try Self.jwks())
        let result = await Session.authenticateVerified(
            client: client, sealedSession: try Self.sealed(token), cookiePassword: Self.password)
        #expect(!result.authenticated)
        #expect(!result.needsRefresh)
        #expect(result.reason == "invalid_jwt")
        #expect(result.sessionId == nil)
        #expect(result.organizationId == nil)
        #expect(result.role == nil)
        #expect(result.permissions.isEmpty)
        #expect(result.entitlements.isEmpty)
        #expect(result.user == nil)
        #expect(result.impersonator == nil)
    }

    @Test(arguments: [
        "wrong-key", "wrong-alg", "wrong-type", "wrong-use", "duplicate", "malformed",
        "unavailable", "missing-client-id",
    ])
    func rejectsUntrustedJWKS(attack: String) async throws {
        var overrides: [String: Any] = [:]
        switch attack {
        case "wrong-key": overrides["n"] = Self.encode(Data(repeating: 0x99, count: 256))
        case "wrong-alg": overrides["alg"] = "HS256"
        case "wrong-type": overrides["kty"] = "EC"
        case "wrong-use": overrides["use"] = "enc"
        default: break
        }
        let body =
            attack == "malformed"
            ? "not-json"
            : try Self.jwks(
                overrides: overrides, duplicate: attack == "duplicate")
        let (client, _) = makeHelperTestClient(
            clientID: attack == "missing-client-id" ? nil : "client_test_123",
            statusCode: attack == "unavailable" ? 401 : 200, responding: body)
        let result = await Session.authenticateVerified(
            client: client, sealedSession: try Self.sealed(Self.token()),
            cookiePassword: Self.password)
        #expect(!result.authenticated)
        #expect(result.reason == "invalid_jwt")
        #expect(!result.needsRefresh)
        #expect(result.sessionId == nil)
        #expect(result.organizationId == nil)
        #expect(result.role == nil)
        #expect(result.permissions.isEmpty)
        #expect(result.entitlements.isEmpty)
        #expect(result.user == nil)
        #expect(result.impersonator == nil)
    }

    @Test func signedExpiredTokenCanRefreshAndLogOut() async throws {
        let token = try Self.token(claims: [
            "sub": "user_123", "sid": "session_expired",
            "exp": Int(Date().timeIntervalSince1970) - 1,
        ])
        let (client, _) = makeHelperTestClient(responding: try Self.jwks())
        let session = try client.loadVerifiedSession(
            sessionData: Self.sealed(token), cookiePassword: Self.password)
        let result = await session.authenticateVerified()
        #expect(!result.authenticated)
        #expect(result.needsRefresh)
        #expect(result.reason == "session_expired")
        let url = try await session.getVerifiedLogoutUrl(returnTo: "https://example.com")
        #expect(queryDictionary(of: url)["session_id"] == "session_expired")
        #expect(queryDictionary(of: url)["return_to"] == "https://example.com")
    }

    @Test(arguments: ["user_123", "victim"])
    func bindsCookieUserToSignedSubject(userID: String) async throws {
        let user = User(
            object: "user", id: userID, email: "test@example.com", emailVerified: true,
            createdAt: Date(), updatedAt: Date())
        let (client, _) = makeHelperTestClient(responding: try Self.jwks())
        let result = await Session.authenticateVerified(
            client: client, sealedSession: try Self.sealed(Self.token(), user: user),
            cookiePassword: Self.password)
        #expect(result.authenticated == (userID == "user_123"))
        #expect(result.user?.id == (userID == "user_123" ? userID : nil))
    }

    @Test(arguments: ["", "short", String(repeating: "a", count: 31)])
    func rejectsWeakPasswords(password: String) async throws {
        let (client, _) = makeHelperTestClient()
        #expect(throws: SessionError.invalidCookiePassword) {
            try client.loadVerifiedSession(sessionData: "cookie", cookiePassword: password)
        }
        let result = await Session.authenticateVerified(
            client: client, sealedSession: "cookie", cookiePassword: password)
        #expect(!result.authenticated)
        #expect(result.reason == "invalid_cookie_password")
        let legacy = Session(client: client, sessionData: "cookie", cookiePassword: password)
        #expect(await legacy.authenticateVerified().reason == "invalid_cookie_password")
    }

    @Test func failsClosedWithoutClientOrCookie() async throws {
        let legacy = Session(sessionData: "cookie", cookiePassword: Self.password)
        #expect(await legacy.authenticateVerified().reason == "client_required")
        let (client, _) = makeHelperTestClient()
        #expect(
            await Session.authenticateVerified(
                client: client, sealedSession: "", cookiePassword: Self.password
            ).reason == "no_session_cookie_provided")
        #expect(
            await Session.authenticateVerified(
                client: client, sealedSession: "garbage", cookiePassword: Self.password
            ).reason == "invalid_session_cookie")
    }

    @Test func opensIndependentPBKDF2Fixture() throws {
        // Produced with Node crypto: pbkdf2Sync(password, "workos-ios/session-seal/wos2",
        // 600000, 32, "sha256"), then hkdfSync("sha256", master, salt, "wos2.aes-256-gcm", 32),
        // then createCipheriv("aes-256-gcm") with salt 00...0f and nonce 00...0b.
        let fixture =
            "wos2.AAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKC+nrisKXjjw5VLgumoF9Fy734DdG+eKrPQ3J6HmlwPc="
        let decoded: [String: String] = try SessionSealing.unseal(fixture, password: Self.password)
        #expect(decoded == ["key": "value"])

        // Same independent fixture, but encrypted without the version as AAD.
        let withoutAAD =
            "wos2.AAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKC+nrisKXjjw5VLgumoF9F70Ptg2kEo7RuSo3q7FPw+s="
        #expect(throws: SessionSealingError.self) {
            let _: [String: String] = try SessionSealing.unseal(
                withoutAAD, password: Self.password)
        }
    }

    @Test func forgedSealsDoNotTriggerPasswordStretching() throws {
        // Warm the cached master key, then reject forged cookies carrying attacker-chosen
        // salts. Each rejection costs an HKDF expansion and a failed AES-GCM open, never a
        // 600,000-iteration PBKDF2, so 64 of them finish in a fraction of one PBKDF2.
        _ = try SessionSealing.seal(["key": "value"], password: Self.password)
        let forged = (0..<64).map { _ in
            "wos2."
                + SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) + Data($0) }
                .base64EncodedString()
        }
        let elapsed = ContinuousClock().measure {
            for cookie in forged {
                #expect(throws: SessionSealingError.self) {
                    let _: [String: String] = try SessionSealing.unseal(
                        cookie, password: Self.password)
                }
            }
        }
        #expect(elapsed < .seconds(2))
    }

    @Test func perSealKeysDependOnSaltAndPasswordOnly() throws {
        let other = String(repeating: "b", count: 32)
        let zero = Data(repeating: 0, count: 16)
        let one = Data(repeating: 1, count: 16)
        let master = try SessionSealing.masterKey(for: Self.password)
        #expect(try SessionSealing.masterKey(for: Self.password) == master)
        #expect(try SessionSealing.masterKey(for: other) != master)
        let key = try SessionSealing.deriveKey(Self.password, salt: zero)
        #expect(try SessionSealing.deriveKey(Self.password, salt: zero) == key)
        #expect(try SessionSealing.deriveKey(Self.password, salt: one) != key)
        #expect(try SessionSealing.deriveKey(other, salt: zero) != key)
        #expect(key != master)
    }

    @Test func verifiedLogoutRejectsForgedToken() async throws {
        let (client, _) = makeHelperTestClient(responding: try Self.jwks())
        let session = try client.loadVerifiedSession(
            sessionData: Self.sealed(makeTestJWT(claims: ["sid": "forged", "exp": 1])),
            cookiePassword: Self.password)
        await #expect(throws: SessionError.invalidJWT) {
            _ = try await session.getVerifiedLogoutUrl()
        }
        let result = await session.authenticateVerified()
        #expect(!result.authenticated)
        #expect(!result.needsRefresh)
        #expect(result.sessionId == nil)
    }

    @Test func saltedSealsAreRandomizedAndAuthenticated() throws {
        let first = try SessionSealing.seal(["key": "value"], password: Self.password)
        let second = try SessionSealing.seal(["key": "value"], password: Self.password)
        #expect(first.hasPrefix("wos2."))
        #expect(first != second)
        let raw = try #require(Data(base64Encoded: String(first.dropFirst(5))))
        let other = try #require(Data(base64Encoded: String(second.dropFirst(5))))
        #expect(raw.prefix(16) != other.prefix(16))
        let decoded: [String: String] = try SessionSealing.unseal(first, password: Self.password)
        #expect(decoded == ["key": "value"])
        for offset in [0, 16, 28, raw.count - 1] {
            var corrupt = raw
            corrupt[offset] ^= 1
            #expect(throws: SessionSealingError.self) {
                let _: [String: String] = try SessionSealing.unseal(
                    "wos2." + corrupt.base64EncodedString(), password: Self.password)
            }
        }
        #expect(throws: SessionSealingError.self) {
            let _: [String: String] = try SessionSealing.unseal(
                first, password: String(repeating: "b", count: 32))
        }
        #expect(throws: SessionSealingError.self) {
            let _: [String: String] = try SessionSealing.unseal(
                String(first.dropFirst(5)), password: Self.password)
        }
        for invalid in ["wos3." + String(first.dropFirst(5)), "wos2.AA==", "wos2.!invalid"] {
            #expect(throws: SessionSealingError.self) {
                let _: [String: String] = try SessionSealing.unseal(
                    invalid, password: Self.password)
            }
        }
    }

    @Test(arguments: [password, String(repeating: "ab", count: 32), "short", ""])
    func legacySealsMigrateWithoutLogout(password: String) throws {
        let plaintext = try Coding.makeEncoder().encode(["key": "value"])
        let legacy = try AES.GCM.seal(plaintext, using: SessionSealing.deriveKey(password))
        let sealed = try #require(legacy.combined).base64EncodedString()
        let decoded: [String: String] = try SessionSealing.unseal(sealed, password: password)
        #expect(decoded == ["key": "value"])
        // Strong passwords upgrade to wos2 on reseal; short legacy passwords stay legacy.
        let upgraded = try SessionSealing.seal(decoded, password: password)
        #expect(upgraded.hasPrefix("wos2.") == (password.count >= 32))
        let restored: [String: String] = try SessionSealing.unseal(upgraded, password: password)
        #expect(restored == decoded)
    }

    @Test(arguments: ["", "short", String(repeating: "a", count: 31)])
    func shortPasswordsNeverUseVersionedSeals(password: String) throws {
        // The fixed-salt master key is never derived for a password weak enough to
        // precompute: sealing stays on the legacy format and wos2 cookies are rejected
        // before any derivation.
        #expect(throws: SessionSealingError.self) {
            _ = try SessionSealing.masterKey(for: password)
        }
        let sealed = try SessionSealing.seal(["key": "value"], password: password)
        #expect(!sealed.hasPrefix("wos2."))
        let raw = try #require(Data(base64Encoded: sealed))
        let opened = try AES.GCM.open(
            AES.GCM.SealedBox(combined: raw), using: SessionSealing.deriveKey(password))
        #expect(
            try Coding.makeDecoder().decode([String: String].self, from: opened) == ["key": "value"]
        )
        let decoded: [String: String] = try SessionSealing.unseal(sealed, password: password)
        #expect(decoded == ["key": "value"])

        let versioned = try SessionSealing.seal(["key": "value"], password: Self.password)
        #expect(throws: SessionSealingError.self) {
            let _: [String: String] = try SessionSealing.unseal(versioned, password: password)
        }
    }
}
