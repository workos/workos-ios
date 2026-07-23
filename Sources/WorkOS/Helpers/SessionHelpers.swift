// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation

/// The unsealed session cookie payload.
public struct SessionData: Codable, Sendable {
    public let accessToken: String
    public let refreshToken: String
    public let user: User?
    public let impersonator: AuthenticateResponseImpersonator?

    public init(
        accessToken: String,
        refreshToken: String,
        user: User? = nil,
        impersonator: AuthenticateResponseImpersonator? = nil
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.user = user
        self.impersonator = impersonator
    }

    private enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case user
        case impersonator
    }
}

/// The claims extracted from a session access-token JWT payload.
public struct JWTClaims: Codable, Sendable, Equatable {
    public let sessionId: String?
    public let organizationId: String?
    public let role: String?
    public let permissions: [String]?
    public let entitlements: [String]?
    /// The `exp` claim, in seconds since the Unix epoch.
    public let exp: Int?

    private enum CodingKeys: String, CodingKey {
        case sessionId = "sid"
        case organizationId = "org_id"
        case role
        case permissions
        case entitlements
        case exp
    }
}

/// The result of authenticating a sealed session.
public struct AuthenticateSessionResult: Sendable {
    public let authenticated: Bool
    public let sessionId: String?
    public let organizationId: String?
    public let role: String?
    public let permissions: [String]
    public let entitlements: [String]
    public let user: User?
    public let impersonator: AuthenticateResponseImpersonator?
    /// True when the session cookie was structurally valid but the
    /// access-token JWT has expired. Refresh the session before treating
    /// the user as unauthenticated.
    public let needsRefresh: Bool
    /// Populated on failure: `no_session_cookie_provided`,
    /// `invalid_session_cookie`, `invalid_jwt`, or `session_expired`.
    public let reason: String?

    init(
        authenticated: Bool,
        sessionId: String? = nil,
        organizationId: String? = nil,
        role: String? = nil,
        permissions: [String] = [],
        entitlements: [String] = [],
        user: User? = nil,
        impersonator: AuthenticateResponseImpersonator? = nil,
        needsRefresh: Bool = false,
        reason: String? = nil
    ) {
        self.authenticated = authenticated
        self.sessionId = sessionId
        self.organizationId = organizationId
        self.role = role
        self.permissions = permissions
        self.entitlements = entitlements
        self.user = user
        self.impersonator = impersonator
        self.needsRefresh = needsRefresh
        self.reason = reason
    }
}

/// The result of refreshing a sealed session.
public struct RefreshSessionResult: Sendable {
    public let authenticated: Bool
    public let sealedSession: String?
    public let session: SessionData?
    /// Populated on failure: `no_session_cookie_provided`,
    /// `invalid_session_cookie`, `no_refresh_token`,
    /// `refresh_token_revoked`, or `refresh_failed`.
    public let reason: String?

    init(
        authenticated: Bool,
        sealedSession: String? = nil,
        session: SessionData? = nil,
        reason: String? = nil
    ) {
        self.authenticated = authenticated
        self.sealedSession = sealedSession
        self.session = session
        self.reason = reason
    }
}

/// Errors thrown by session helpers.
public enum SessionError: Error, Equatable, Sendable {
    /// The session has no sealed data to operate on.
    case noSessionData
    /// The session cookie carried no session ID.
    case missingSessionID
    /// The operation requires a `WorkOSClient`, but the session was created without one.
    case clientRequired
}

/// Session-cookie management: load a sealed session, authenticate it,
/// refresh it, and derive its logout URL.
public struct Session: Sendable {
    let client: WorkOSClient?
    /// The password used to seal and unseal the session cookie.
    public let cookiePassword: String
    /// The sealed session cookie value.
    public let sessionData: String

    public init(client: WorkOSClient? = nil, sessionData: String, cookiePassword: String) {
        self.client = client
        self.sessionData = sessionData
        self.cookiePassword = cookiePassword
    }

    /// Validate the sealed session: unseal it, check the access token, and
    /// extract the JWT claims. Never throws — failures are reported through
    /// `authenticated == false` plus `reason`.
    public func authenticate() -> AuthenticateSessionResult {
        guard !sessionData.isEmpty else {
            return AuthenticateSessionResult(
                authenticated: false, reason: "no_session_cookie_provided")
        }

        guard
            let session = try? SessionSealing.unseal(
                sessionData, password: cookiePassword, as: SessionData.self)
        else {
            return AuthenticateSessionResult(
                authenticated: false, reason: "invalid_session_cookie")
        }

        guard !session.accessToken.isEmpty,
            let claims = try? Session.parseJWTPayload(session.accessToken)
        else {
            return AuthenticateSessionResult(authenticated: false, reason: "invalid_jwt")
        }

        // Enforce JWT expiration: an expired access token signals the caller
        // to refresh the session rather than treat the user as logged out.
        if let exp = claims.exp, Date().timeIntervalSince1970 >= Double(exp) {
            return AuthenticateSessionResult(
                authenticated: false,
                sessionId: claims.sessionId,
                organizationId: claims.organizationId,
                role: claims.role,
                permissions: claims.permissions ?? [],
                entitlements: claims.entitlements ?? [],
                user: session.user,
                impersonator: session.impersonator,
                needsRefresh: true,
                reason: "session_expired"
            )
        }

        return AuthenticateSessionResult(
            authenticated: true,
            sessionId: claims.sessionId,
            organizationId: claims.organizationId,
            role: claims.role,
            permissions: claims.permissions ?? [],
            entitlements: claims.entitlements ?? [],
            user: session.user,
            impersonator: session.impersonator
        )
    }

    /// Refresh the session using its refresh token, returning a newly sealed
    /// session on success. Authentication-level failures (revoked refresh
    /// token, upstream errors) are reported through `authenticated == false`
    /// plus `reason`; check `authenticated`, not just the absence of a throw.
    public func refresh(requestOptions: RequestOptions? = nil) async throws
        -> RefreshSessionResult
    {
        guard !sessionData.isEmpty else {
            return RefreshSessionResult(
                authenticated: false, reason: "no_session_cookie_provided")
        }

        guard
            let session = try? SessionSealing.unseal(
                sessionData, password: cookiePassword, as: SessionData.self)
        else {
            return RefreshSessionResult(
                authenticated: false, reason: "invalid_session_cookie")
        }

        guard !session.refreshToken.isEmpty else {
            return RefreshSessionResult(authenticated: false, reason: "no_refresh_token")
        }

        guard let client else {
            throw SessionError.clientRequired
        }

        // Carry the organization forward from the current access token.
        var organizationId: String?
        if !session.accessToken.isEmpty,
            let claims = try? Session.parseJWTPayload(session.accessToken)
        {
            organizationId = claims.organizationId
        }

        let response: AuthenticateResponse
        do {
            response = try await client.userManagement.authenticateWithRefreshToken(
                refreshToken: session.refreshToken,
                organizationId: organizationId,
                requestOptions: requestOptions
            )
        } catch let error as WorkOSError {
            // A terminal refresh failure surfaces as OAuth `invalid_grant` (the
            // refresh token is expired, revoked, or reused past the grace
            // window). The WorkOS token endpoint returns it at HTTP 400, so
            // detection must key off the error code rather than a specific
            // status. Any other failure (429, 5xx, network) stays the generic
            // `refresh_failed`: the refresh token is still valid and the caller
            // can retry rather than signing the user out.
            var reason = "refresh_failed"
            if error.helperErrorCode == "invalid_grant" {
                reason = "refresh_token_revoked"
            }
            return RefreshSessionResult(authenticated: false, reason: reason)
        }

        let newSession = SessionData(
            accessToken: response.accessToken,
            refreshToken: response.refreshToken,
            user: response.user,
            impersonator: response.impersonator
        )
        let sealed = try SessionSealing.seal(newSession, password: cookiePassword)

        return RefreshSessionResult(
            authenticated: true, sealedSession: sealed, session: newSession)
    }

    /// Build the logout URL for this session. An expired access token is
    /// fine — the logout endpoint only needs the session ID.
    public func getLogoutUrl(returnTo: String? = nil) throws -> URL {
        guard !sessionData.isEmpty else { throw SessionError.noSessionData }

        let result = authenticate()
        guard let sessionId = result.sessionId, !sessionId.isEmpty else {
            throw SessionError.missingSessionID
        }

        let baseURL = client?.configuration.baseURL ?? Configuration.defaultBaseURL
        var urlString = baseURL.absoluteString
        if urlString.hasSuffix("/") { urlString.removeLast() }
        var components = URLComponents(string: "\(urlString)/user_management/sessions/logout")!
        var query = [URLQueryItem(name: "session_id", value: sessionId)]
        if let returnTo {
            query.append(URLQueryItem(name: "return_to", value: returnTo))
        }
        components.queryItems = query
        return components.url!
    }

    /// One-shot session authentication that needs no client — only the
    /// sealed session and the cookie password.
    public static func authenticate(
        sealedSession: String, cookiePassword: String
    ) -> AuthenticateSessionResult {
        Session(sessionData: sealedSession, cookiePassword: cookiePassword).authenticate()
    }

    /// Seal a session cookie directly from a successful authentication response.
    public static func seal(
        from response: AuthenticateResponse, cookiePassword: String
    ) throws -> String {
        try sealSession(
            accessToken: response.accessToken,
            refreshToken: response.refreshToken,
            user: response.user,
            impersonator: response.impersonator,
            cookiePassword: cookiePassword
        )
    }

    /// Seal a session cookie from its component parts.
    public static func sealSession(
        accessToken: String,
        refreshToken: String,
        user: User? = nil,
        impersonator: AuthenticateResponseImpersonator? = nil,
        cookiePassword: String
    ) throws -> String {
        let session = SessionData(
            accessToken: accessToken,
            refreshToken: refreshToken,
            user: user,
            impersonator: impersonator
        )
        return try SessionSealing.seal(session, password: cookiePassword)
    }

    /// Decode the payload (claims) of a JWT without verifying its signature.
    /// Acceptable because the token was sealed by us and is trusted after
    /// unsealing.
    static func parseJWTPayload(_ token: String) throws -> JWTClaims {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else {
            throw SessionSealingError.cryptoFailure(
                "invalid JWT format: expected 3 parts, got \(parts.count)")
        }
        guard let payload = HelperSupport.base64URLDecode(String(parts[1])) else {
            throw SessionSealingError.cryptoFailure("failed to decode JWT payload")
        }
        return try JSONDecoder().decode(JWTClaims.self, from: payload)
    }
}

extension WorkOSClient {
    /// Load a sealed session cookie into a `Session` bound to this client.
    public func loadSealedSession(sessionData: String, cookiePassword: String) -> Session {
        Session(client: self, sessionData: sessionData, cookiePassword: cookiePassword)
    }

    /// One-shot refresh of a sealed session.
    public func refreshSession(
        sealedSession: String, cookiePassword: String, requestOptions: RequestOptions? = nil
    ) async throws -> RefreshSessionResult {
        try await Session(
            client: self, sessionData: sealedSession, cookiePassword: cookiePassword
        ).refresh(requestOptions: requestOptions)
    }
}
