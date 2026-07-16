// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation

/// The type of an AuthKit Action.
public enum ActionType: String, Codable, Sendable {
    case authentication
    case userRegistration = "user_registration"
}

/// The verdict for an AuthKit Action response.
public enum ActionVerdict: String, Codable, Sendable {
    case allow = "Allow"
    case deny = "Deny"
}

/// A signed action response. Send `payload` and `sig` back to WorkOS as the
/// action webhook response body.
public struct ActionSignedResponse: Codable, Sendable, Equatable {
    /// The base64-encoded JSON response body.
    public let payload: String
    /// The signature header in the form `"t=<timestamp>,v1=<hex>"`.
    public let sig: String

    public init(payload: String, sig: String) {
        self.payload = payload
        self.sig = sig
    }
}

/// Helpers for AuthKit Actions: request verification and response signing.
public struct ActionsHelper: Sendable {
    /// The maximum allowed age of the signature timestamp.
    public var tolerance: TimeInterval

    public init(tolerance: TimeInterval = 30) {
        self.tolerance = tolerance
    }

    /// Verify the signature of an Actions request.
    public func verifyHeader(payload: String, signatureHeader: String, secret: String) throws {
        guard !signatureHeader.isEmpty else { throw WebhookVerificationError.notSigned }

        let (timestamp, signature) = try WebhookSignature.parseHeader(signatureHeader)

        guard let milliseconds = Int64(timestamp) else {
            throw WebhookVerificationError.invalidTimestamp
        }
        let signedAt = Date(timeIntervalSince1970: Double(milliseconds) / 1000)
        guard abs(Date().timeIntervalSince(signedAt)) <= tolerance else {
            throw WebhookVerificationError.outsideTolerance
        }

        let expected = WebhookSignature.compute(
            secret: secret, timestamp: timestamp, body: payload)
        guard HelperSupport.constantTimeEquals(expected, signature) else {
            throw WebhookVerificationError.noValidSignature
        }
    }

    /// Verify and deserialize an Actions request into the standard WorkOS
    /// event envelope. Inspect `event`/`data` to dispatch on action type.
    public func constructAction(
        payload: String, signatureHeader: String, secret: String
    ) throws -> EventSchema {
        try verifyHeader(payload: payload, signatureHeader: signatureHeader, secret: secret)
        return try Coding.makeDecoder().decode(EventSchema.self, from: Data(payload.utf8))
    }

    /// Sign an action response with the given secret.
    public func signResponse(
        actionType: ActionType, verdict: ActionVerdict, errorMessage: String = "",
        secret: String
    ) throws -> ActionSignedResponse {
        let responsePayload: [String: String] = [
            "type": actionType.rawValue,
            "verdict": verdict.rawValue,
            "error_message": errorMessage,
        ]
        let jsonData = try JSONSerialization.data(
            withJSONObject: responsePayload, options: [.sortedKeys])
        let base64Payload = jsonData.base64EncodedString()

        let timestamp = String(Int64(Date().timeIntervalSince1970 * 1000))
        let signature = WebhookSignature.compute(
            secret: secret, timestamp: timestamp, body: base64Payload)

        return ActionSignedResponse(
            payload: base64Payload,
            sig: "t=\(timestamp),v1=\(signature)"
        )
    }
}
