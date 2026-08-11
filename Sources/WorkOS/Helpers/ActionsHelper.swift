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

/// The signed payload of an action response.
public struct ActionResponsePayload: Sendable, Equatable {
    /// Milliseconds since the Unix epoch.
    public let timestamp: Int64
    /// The verdict: `.allow` or `.deny`.
    public let verdict: ActionVerdict
    /// Present (and non-empty) only when denying.
    public let errorMessage: String?

    public init(timestamp: Int64, verdict: ActionVerdict, errorMessage: String? = nil) {
        self.timestamp = timestamp
        self.verdict = verdict
        self.errorMessage = errorMessage
    }
}

/// A signed action response ready to send back to WorkOS.
///
/// Matches the `workos-node` wire format: `{object, payload, signature}`, where
/// `signature` is the HMAC-SHA256 of `"<timestamp>.<JSON(payload)>"`. Send
/// `bodyData` as the HTTP response body; it is the exact bytes the signature
/// covers, so do not re-serialize it.
public struct ActionSignedResponse: Sendable, Equatable {
    /// `authentication_action_response` or `user_registration_action_response`.
    public let object: String
    /// The signed payload.
    public let payload: ActionResponsePayload
    /// HMAC-SHA256 hex signature over `"<timestamp>.<JSON(payload)>"`.
    public let signature: String
    /// The exact JSON response body to send to WorkOS.
    public let bodyData: Data

    public init(object: String, payload: ActionResponsePayload, signature: String, bodyData: Data) {
        self.object = object
        self.payload = payload
        self.signature = signature
        self.bodyData = bodyData
    }
}

/// The provisional user data carried by a `user_registration` action context.
public struct ActionUserData: Codable, Sendable, Equatable {
    /// The discriminator `"user_data"`.
    public let object: String
    /// The email address the user is registering with.
    public let email: String
    /// The user's full name, or `nil`.
    public let name: String?
    /// The user's first name.
    public let firstName: String
    /// The user's last name.
    public let lastName: String

    public init(
        object: String,
        email: String,
        name: String? = nil,
        firstName: String,
        lastName: String
    ) {
        self.object = object
        self.email = email
        self.name = name
        self.firstName = firstName
        self.lastName = lastName
    }

    private enum CodingKeys: String, CodingKey {
        case object, email, name
        case firstName = "first_name"
        case lastName = "last_name"
    }
}

/// A verified, deserialized AuthKit Action request.
///
/// WorkOS sends a flat context object discriminated by `object`, not the
/// webhook event envelope:
/// - `authentication_action_context`: `user`, `organization`,
///   `organizationMembership`, `issuer`
/// - `user_registration_action_context`: `userData`, `invitation`
///
/// `ipAddress`, `userAgent`, and `deviceFingerprint` are shared by both
/// context types; fields specific to the other variant are `nil`.
public struct ActionContext: Codable, Sendable, Equatable {
    /// Discriminates the action context type.
    public let object: String
    /// Unique identifier for the action context.
    public let id: String
    /// Caller IP address (both context types).
    public let ipAddress: String?
    /// Caller user agent (both context types).
    public let userAgent: String?
    /// Caller device fingerprint (both context types).
    public let deviceFingerprint: String?
    /// Present when `object == "authentication_action_context"`.
    public let user: User?
    /// Present when `object == "authentication_action_context"`.
    public let organization: Organization?
    /// Present when `object == "authentication_action_context"`.
    public let organizationMembership: OrganizationMembership?
    /// Present when `object == "authentication_action_context"`.
    public let issuer: String?
    /// Present when `object == "user_registration_action_context"`.
    public let userData: ActionUserData?
    /// Present when `object == "user_registration_action_context"`.
    public let invitation: Invitation?

    public init(
        object: String,
        id: String,
        ipAddress: String? = nil,
        userAgent: String? = nil,
        deviceFingerprint: String? = nil,
        user: User? = nil,
        organization: Organization? = nil,
        organizationMembership: OrganizationMembership? = nil,
        issuer: String? = nil,
        userData: ActionUserData? = nil,
        invitation: Invitation? = nil
    ) {
        self.object = object
        self.id = id
        self.ipAddress = ipAddress
        self.userAgent = userAgent
        self.deviceFingerprint = deviceFingerprint
        self.user = user
        self.organization = organization
        self.organizationMembership = organizationMembership
        self.issuer = issuer
        self.userData = userData
        self.invitation = invitation
    }

    private enum CodingKeys: String, CodingKey {
        case object, id
        case ipAddress = "ip_address"
        case userAgent = "user_agent"
        case deviceFingerprint = "device_fingerprint"
        case user, organization
        case organizationMembership = "organization_membership"
        case issuer
        case userData = "user_data"
        case invitation
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

    /// Verify and deserialize an Actions request into an `ActionContext`.
    /// Dispatch on `object` to read the type-specific fields.
    public func constructAction(
        payload: String, signatureHeader: String, secret: String
    ) throws -> ActionContext {
        try verifyHeader(payload: payload, signatureHeader: signatureHeader, secret: secret)
        return try Coding.makeDecoder().decode(ActionContext.self, from: Data(payload.utf8))
    }

    /// Sign an action response with the given secret.
    ///
    /// Returns the `{object, payload, signature}` body to send back to WorkOS,
    /// matching `workos-node`. The signature is the HMAC-SHA256 of
    /// `"<timestamp>.<JSON(payload)>"`. Send `bodyData` as the HTTP response
    /// body; do not re-serialize it, or the signature may not verify.
    public func signResponse(
        actionType: ActionType, verdict: ActionVerdict, errorMessage: String = "",
        secret: String
    ) throws -> ActionSignedResponse {
        let object: String
        switch actionType {
        case .authentication: object = "authentication_action_response"
        case .userRegistration: object = "user_registration_action_response"
        }

        let timestampMs = Int64(Date().timeIntervalSince1970 * 1000)
        let timestamp = String(timestampMs)
        let includeError = verdict == .deny && !errorMessage.isEmpty
        let payload = ActionResponsePayload(
            timestamp: timestampMs,
            verdict: verdict,
            errorMessage: includeError ? errorMessage : nil
        )

        let payloadJSON = ActionsHelper.encodeResponsePayload(payload)
        let signature = WebhookSignature.compute(
            secret: secret, timestamp: timestamp, body: payloadJSON)

        let body =
            "{\"object\":\"\(object)\","
            + "\"payload\":\(payloadJSON),"
            + "\"signature\":\"\(signature)\"}"
        return ActionSignedResponse(
            object: object,
            payload: payload,
            signature: signature,
            bodyData: Data(body.utf8)
        )
    }

    /// Encodes an `ActionResponsePayload` to the exact JSON bytes `workos-node`
    /// produces: `timestamp`, `verdict`, then `error_message` when present.
    static func encodeResponsePayload(_ payload: ActionResponsePayload) -> String {
        let verdict = payload.verdict.rawValue
        if let errorMessage = payload.errorMessage, !errorMessage.isEmpty {
            let escaped = ActionsHelper.jsonEscape(errorMessage)
            return "{\"timestamp\":\(payload.timestamp),\"verdict\":\"\(verdict)\","
                + "\"error_message\":\"\(escaped)\"}"
        }
        return "{\"timestamp\":\(payload.timestamp),\"verdict\":\"\(verdict)\"}"
    }

    /// Escapes a string for inclusion in a JSON string literal.
    static func jsonEscape(_ string: String) -> String {
        var out = ""
        for scalar in string.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out
    }
}
