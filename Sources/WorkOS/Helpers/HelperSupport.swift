// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation

/// Errors thrown by the hand-maintained helper layer when required
/// configuration is missing.
public enum HelperError: Error, Equatable, Sendable {
    /// The operation requires a client ID, but none was provided or configured.
    case missingClientID
}

enum HelperSupport {
    /// Generate `count` cryptographically secure random bytes.
    static func randomBytes(_ count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        var data = Data(capacity: count)
        for _ in 0..<count {
            data.append(UInt8.random(in: .min ... .max, using: &generator))
        }
        return data
    }

    /// Generate a random URL-safe state value (32 random bytes, base64url).
    static func randomState() -> String {
        base64URLEncode(randomBytes(32))
    }

    /// Base64url-encode without padding.
    static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Base64url-decode, tolerating missing padding.
    static func base64URLDecode(_ string: String) -> Data? {
        var base64 =
            string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder > 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }
        return Data(base64Encoded: base64)
    }

    /// Constant-time string equality, safe for signature comparison.
    static func constantTimeEquals(_ lhs: String, _ rhs: String) -> Bool {
        let lhsBytes = Array(lhs.utf8)
        let rhsBytes = Array(rhs.utf8)
        guard lhsBytes.count == rhsBytes.count else { return false }
        var diff: UInt8 = 0
        for index in 0..<lhsBytes.count {
            diff |= lhsBytes[index] ^ rhsBytes[index]
        }
        return diff == 0
    }
}

extension WorkOSError {
    /// Extract the machine-readable error code from an API failure, checking
    /// both the `{"code": ...}` and OAuth-style `{"error": ...}` body formats.
    var helperErrorCode: String? {
        guard let apiError else { return nil }
        if let code = apiError.code { return code }
        if case .object(let object)? = apiError.raw,
            case .string(let value)? = object["error"]
        {
            return value
        }
        return nil
    }

    /// The structured API error carried by this failure, when there is one.
    var apiError: APIError? {
        switch self {
        case .badRequest(let error), .authentication(let error), .authorization(let error),
            .notFound(let error), .conflict(let error), .unprocessableEntity(let error),
            .rateLimitExceeded(let error), .server(let error), .api(let error):
            return error
        case .network, .decoding, .invalidResponse:
            return nil
        }
    }
}
