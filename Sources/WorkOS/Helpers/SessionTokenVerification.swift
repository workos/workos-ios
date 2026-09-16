// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation
import Security

/// Internal RS256 verification. Only keys from the configured WorkOS client's
/// JWKS are trusted; token-provided key URLs and certificates are never used.
enum SessionTokenVerification {
    struct VerifiedClaims: Decodable {
        let sub: String
        let exp: Int
        let nbf: Int?
    }

    private struct Header: Decodable {
        let alg: String
        let kid: String

        private enum CodingKeys: String, CodingKey {
            case alg, kid, crit, b64
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            guard !container.contains(.crit), !container.contains(.b64) else {
                throw SessionError.invalidJWT
            }
            alg = try container.decode(String.self, forKey: .alg)
            kid = try container.decode(String.self, forKey: .kid)
        }
    }

    static func verify(_ token: String, client: WorkOSClient) async throws
        -> (JWTClaims, VerifiedClaims)
    {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
            let headerData = HelperSupport.base64URLDecode(String(parts[0])),
            let payload = HelperSupport.base64URLDecode(String(parts[1])),
            let signature = HelperSupport.base64URLDecode(String(parts[2])), !signature.isEmpty
        else { throw SessionError.invalidJWT }
        let header = try JSONDecoder().decode(Header.self, from: headerData)
        guard header.alg == "RS256", !header.kid.isEmpty else { throw SessionError.invalidJWT }

        let jwks = try await client.getJwks()
        let matches = jwks.keys.filter { $0.kid == header.kid }
        guard matches.count == 1, let jwk = matches.first,
            jwk.alg == "RS256", jwk.kty == "RSA", jwk.use == "sig",
            let modulus = HelperSupport.base64URLDecode(jwk.n), !modulus.isEmpty,
            let exponent = HelperSupport.base64URLDecode(jwk.e), !exponent.isEmpty
        else { throw SessionError.invalidJWT }

        // Security expects a PKCS#1 DER RSAPublicKey (SEQUENCE of two INTEGERs).
        let keyData = der(tag: 0x30, content: integer(modulus) + integer(exponent))
        guard
            let key = SecKeyCreateWithData(
                keyData as CFData,
                [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic]
                    as CFDictionary, nil),
            SecKeyIsAlgorithmSupported(key, .verify, .rsaSignatureMessagePKCS1v15SHA256),
            SecKeyVerifySignature(
                key, .rsaSignatureMessagePKCS1v15SHA256,
                Data("\(parts[0]).\(parts[1])".utf8) as CFData, signature as CFData, nil)
        else { throw SessionError.invalidJWT }

        // Parse claims only after the signature has been checked. Expiration is
        // mandatory; expired signed tokens are handled by the session caller.
        let verified = try JSONDecoder().decode(VerifiedClaims.self, from: payload)
        guard !verified.sub.isEmpty,
            verified.nbf.map({ Double($0) <= Date().timeIntervalSince1970 }) ?? true
        else { throw SessionError.invalidJWT }
        return (try JSONDecoder().decode(JWTClaims.self, from: payload), verified)
    }

    private static func integer(_ bytes: Data) -> Data {
        var value = Data(bytes.drop(while: { $0 == 0 }))
        if value.isEmpty { value.append(0) }
        if value[0] & 0x80 != 0 { value.insert(0, at: 0) }
        return der(tag: 0x02, content: value)
    }

    private static func der(tag: UInt8, content: Data) -> Data {
        var result = Data([tag])
        if content.count < 128 {
            result.append(UInt8(content.count))
        } else {
            var length = content.count
            var bytes: [UInt8] = []
            while length > 0 {
                bytes.insert(UInt8(length & 0xff), at: 0)
                length >>= 8
            }
            result.append(0x80 | UInt8(bytes.count))
            result.append(contentsOf: bytes)
        }
        result.append(content)
        return result
    }
}
