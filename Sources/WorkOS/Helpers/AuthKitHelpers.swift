// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation

/// An authorization URL with the auto-generated PKCE verifier and state that
/// must be stored client-side until the code exchange.
public struct PKCEAuthorizationUrlResult: Sendable {
    public let url: URL
    public let codeVerifier: String
    public let state: String

    public init(url: URL, codeVerifier: String, state: String) {
        self.url = url
        self.codeVerifier = codeVerifier
        self.state = state
    }
}

extension WorkOSClient {
    /// Build an AuthKit authorization URL client-side, without an HTTP request.
    public func getAuthKitAuthorizationUrl(
        redirectUri: String,
        clientId: String? = nil,
        provider: String? = nil,
        connectionId: String? = nil,
        organizationId: String? = nil,
        domainHint: String? = nil,
        loginHint: String? = nil,
        state: String? = nil,
        codeChallenge: String? = nil,
        codeChallengeMethod: String? = nil,
        screenHint: String? = nil
    ) throws -> URL {
        guard let resolvedClientId = clientId ?? configuration.clientID else {
            throw HelperError.missingClientID
        }

        var query: [URLQueryItem] = [
            URLQueryItem(name: "client_id", value: resolvedClientId),
            URLQueryItem(name: "redirect_uri", value: redirectUri),
            URLQueryItem(name: "response_type", value: "code"),
        ]
        if let provider { query.append(URLQueryItem(name: "provider", value: provider)) }
        if let connectionId {
            query.append(URLQueryItem(name: "connection_id", value: connectionId))
        }
        if let organizationId {
            query.append(URLQueryItem(name: "organization_id", value: organizationId))
        }
        if let domainHint { query.append(URLQueryItem(name: "domain_hint", value: domainHint)) }
        if let loginHint { query.append(URLQueryItem(name: "login_hint", value: loginHint)) }
        if let state { query.append(URLQueryItem(name: "state", value: state)) }
        if let codeChallenge {
            query.append(URLQueryItem(name: "code_challenge", value: codeChallenge))
        }
        if let codeChallengeMethod {
            query.append(
                URLQueryItem(name: "code_challenge_method", value: codeChallengeMethod))
        }
        if let screenHint { query.append(URLQueryItem(name: "screen_hint", value: screenHint)) }

        return transport.buildURL(path: "user_management/authorize", query: query)
    }

    /// Build an AuthKit authorization URL with auto-generated PKCE parameters
    /// and state. Store the returned code verifier for the code exchange.
    public func getAuthKitAuthorizationUrlWithPKCE(
        redirectUri: String,
        clientId: String? = nil,
        provider: String? = nil,
        connectionId: String? = nil,
        organizationId: String? = nil,
        domainHint: String? = nil,
        loginHint: String? = nil,
        state: String? = nil,
        screenHint: String? = nil
    ) throws -> PKCEAuthorizationUrlResult {
        let pair = try PKCE.generatePair()
        let resolvedState = state ?? HelperSupport.randomState()

        let url = try getAuthKitAuthorizationUrl(
            redirectUri: redirectUri,
            clientId: clientId,
            provider: provider,
            connectionId: connectionId,
            organizationId: organizationId,
            domainHint: domainHint,
            loginHint: loginHint,
            state: resolvedState,
            codeChallenge: pair.codeChallenge,
            codeChallengeMethod: pair.codeChallengeMethod,
            screenHint: screenHint
        )

        return PKCEAuthorizationUrlResult(
            url: url, codeVerifier: pair.codeVerifier, state: resolvedState)
    }

    /// Exchange an authorization code with a PKCE code verifier. Works for
    /// both confidential clients (API key configured) and public clients —
    /// the client secret is only sent when an API key is present.
    public func authKitPKCECodeExchange(
        code: String, codeVerifier: String, requestOptions: RequestOptions? = nil
    ) async throws -> AuthenticateResponse {
        var body = EncodableBody()
        body.set("code", code)
        body.set("code_verifier", codeVerifier)
        body.set("grant_type", "authorization_code")
        body.set("client_id", configuration.clientID)
        if !configuration.apiKey.isEmpty {
            body.set("client_secret", configuration.apiKey)
        }
        return try await transport.request(
            method: "POST",
            path: "user_management/authenticate",
            query: [],
            body: body,
            options: requestOptions,
            as: AuthenticateResponse.self
        )
    }

    /// Initiate a device authorization flow (RFC 8628, part 1).
    public func authKitStartDeviceAuthorization(
        clientId: String? = nil, requestOptions: RequestOptions? = nil
    ) async throws -> DeviceAuthorizationResponse {
        guard let resolvedClientId = clientId ?? configuration.clientID else {
            throw HelperError.missingClientID
        }
        return try await userManagement.createDevice(
            clientId: resolvedClientId, requestOptions: requestOptions)
    }

    /// Poll for device-code completion (RFC 8628, part 2). Blocks until the
    /// user completes authorization, a non-pending error occurs, or the task
    /// is cancelled.
    public func authKitPollDeviceCode(
        deviceCode: String, interval: Int = 5, requestOptions: RequestOptions? = nil
    ) async throws -> AuthenticateResponse {
        let seconds = interval > 0 ? interval : 5
        while true {
            try await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000)
            do {
                return try await userManagement.authenticateWithDeviceCode(
                    deviceCode: deviceCode, requestOptions: requestOptions)
            } catch let error as WorkOSError {
                if error.helperErrorCode == "authorization_pending" { continue }
                throw error
            }
        }
    }
}
