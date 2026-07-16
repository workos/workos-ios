// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import CryptoKit
import Foundation

/// Errors thrown while verifying webhook signatures.
public enum WebhookVerificationError: Error, Equatable, Sendable {
    /// The signature header could not be parsed into `t=...` and `v1=...` parts.
    case invalidHeader
    /// The signature did not match the expected value.
    case noValidSignature
    /// The request carried no signature header.
    case notSigned
    /// The timestamp in the signature header was not a valid integer.
    case invalidTimestamp
    /// The timestamp was outside the allowed tolerance window.
    case outsideTolerance
}

/// Low-level webhook signature primitives: header parsing and signature
/// computation. `WebhookVerifier` builds on these; they are public so
/// callers can implement custom verification flows.
public enum WebhookSignature {
    /// Compute the HMAC-SHA256 signature (hex) for a webhook payload.
    /// The signed message is `"<timestamp>.<body>"`.
    public static func compute(secret: String, timestamp: String, body: String) -> String {
        let key = SymmetricKey(data: Data(secret.utf8))
        let message = Data("\(timestamp).\(body)".utf8)
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: key)
        return mac.map { String(format: "%02x", $0) }.joined()
    }

    /// Parse a `"t=<timestamp>, v1=<signature>"` header into its parts.
    public static func parseHeader(_ header: String) throws -> (
        timestamp: String, signature: String
    ) {
        guard !header.isEmpty else { throw WebhookVerificationError.notSigned }

        var timestamp = ""
        var signature = ""
        for part in header.split(separator: ",") {
            let pair = part.trimmingCharacters(in: .whitespaces)
                .split(separator: "=", maxSplits: 1)
            guard pair.count == 2 else { throw WebhookVerificationError.invalidHeader }
            let key = pair[0].trimmingCharacters(in: .whitespaces)
            let value = pair[1].trimmingCharacters(in: .whitespaces)
            switch key {
            case "t": timestamp = value
            case "v1": signature = value
            default: break
            }
        }

        guard !timestamp.isEmpty, !signature.isEmpty else {
            throw WebhookVerificationError.invalidHeader
        }
        return (timestamp, signature)
    }
}

/// Verifies WorkOS webhook signatures and deserializes verified events.
public struct WebhookVerifier: Sendable {
    /// The webhook signing secret from the WorkOS dashboard.
    public let secret: String
    /// The maximum allowed age of the signature timestamp.
    public var tolerance: TimeInterval

    public init(secret: String, tolerance: TimeInterval = 180) {
        self.secret = secret
        self.tolerance = tolerance
    }

    /// Verify a signature header against the raw body and return the verified body.
    /// The header format is `"t=<timestamp>, v1=<signature>"`.
    @discardableResult
    public func verifyPayload(signatureHeader: String, body: String) throws -> String {
        guard !signatureHeader.isEmpty else { throw WebhookVerificationError.notSigned }

        let (timestamp, signature) = try WebhookSignature.parseHeader(signatureHeader)

        guard let milliseconds = Int64(timestamp) else {
            throw WebhookVerificationError.invalidTimestamp
        }
        let signedAt = Date(timeIntervalSince1970: Double(milliseconds) / 1000)
        guard abs(Date().timeIntervalSince(signedAt)) <= tolerance else {
            throw WebhookVerificationError.outsideTolerance
        }

        let expected = WebhookSignature.compute(secret: secret, timestamp: timestamp, body: body)
        guard HelperSupport.constantTimeEquals(expected, signature) else {
            throw WebhookVerificationError.noValidSignature
        }

        return body
    }

    /// Verify the webhook and return the deserialized event envelope.
    public func constructEvent(signatureHeader: String, body: String) throws -> EventSchema {
        let verified = try verifyPayload(signatureHeader: signatureHeader, body: body)
        return try Coding.makeDecoder().decode(EventSchema.self, from: Data(verified.utf8))
    }
}
