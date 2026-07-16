// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.
// The passwordless endpoints are not in the OpenAPI spec, so this resource is
// maintained by hand alongside the generated ones.

import Foundation

/// The type of a passwordless session.
public enum PasswordlessSessionType: String, Codable, Sendable {
    case magicLink = "MagicLink"
}

/// A passwordless (Magic Link) session.
public struct PasswordlessSession: Codable, Sendable, Equatable {
    /// Unique identifier for the session.
    public let id: String
    /// The email address the magic link is sent to.
    public let email: String
    /// When the session expires.
    public let expiresAt: Date
    /// The magic-link URL.
    public let link: String
    /// Distinguishes the PasswordlessSession object.
    public let object: String

    public init(id: String, email: String, expiresAt: Date, link: String, object: String) {
        self.id = id
        self.email = email
        self.expiresAt = expiresAt
        self.link = link
        self.object = object
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case email
        case expiresAt = "expires_at"
        case link
        case object
    }
}

/// Operations for the Passwordless (Magic Link) API.
public struct Passwordless: Sendable {
    let transport: Transport

    /// Create a passwordless session.
    public func createSession(
        email: String,
        type: PasswordlessSessionType = .magicLink,
        redirectUri: String? = nil,
        state: String? = nil,
        expiresIn: Int? = nil,
        requestOptions: RequestOptions? = nil
    ) async throws -> PasswordlessSession {
        var body = EncodableBody()
        body.set("email", email)
        body.set("type", type.rawValue)
        body.set("redirect_uri", redirectUri)
        body.set("state", state)
        body.set("expires_in", expiresIn)
        return try await transport.request(
            method: "POST",
            path: "passwordless/sessions",
            query: [],
            body: body,
            options: requestOptions,
            as: PasswordlessSession.self
        )
    }

    /// Send the magic-link email for a session.
    public func sendSession(
        sessionId: String,
        requestOptions: RequestOptions? = nil
    ) async throws {
        try await transport.requestVoid(
            method: "POST",
            path: "passwordless/sessions/\(PathEncoding.segment(sessionId))/send",
            query: [],
            body: nil,
            options: requestOptions
        )
    }
}

extension WorkOSClient {
    /// Operations for the Passwordless (Magic Link) API.
    public var passwordless: Passwordless { Passwordless(transport: transport) }
}
