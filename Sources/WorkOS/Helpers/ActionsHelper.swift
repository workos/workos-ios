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
