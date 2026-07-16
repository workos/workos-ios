// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation

/// An SSO authorization URL with the auto-generated PKCE verifier and state.
public struct SSOPKCEAuthorizationUrlResult: Sendable {
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
    /// Build an SSO authorization URL client-side, without an HTTP request.
    public func getSSOAuthorizationUrl(
        redirectUri: String,
        clientId: String? = nil,
        provider: String? = nil,
        connectionId: String? = nil,
        organizationId: String? = nil,
        domainHint: String? = nil,
        loginHint: String? = nil,
        state: String? = nil,
        codeChallenge: String? = nil,
        codeChallengeMethod: String? = nil
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

        return transport.buildURL(path: "sso/authorize", query: query)
    }

    /// Build an SSO authorization URL with auto-generated PKCE parameters
    /// and state. Store the returned code verifier for the code exchange.
    public func getSSOAuthorizationUrlWithPKCE(
        redirectUri: String,
        clientId: String? = nil,
        provider: String? = nil,
        connectionId: String? = nil,
        organizationId: String? = nil,
        domainHint: String? = nil,
        loginHint: String? = nil,
        state: String? = nil
    ) throws -> SSOPKCEAuthorizationUrlResult {
        let pair = try PKCE.generatePair()
        let resolvedState = state ?? HelperSupport.randomState()

        let url = try getSSOAuthorizationUrl(
            redirectUri: redirectUri,
            clientId: clientId,
            provider: provider,
            connectionId: connectionId,
            organizationId: organizationId,
            domainHint: domainHint,
            loginHint: loginHint,
            state: resolvedState,
            codeChallenge: pair.codeChallenge,
            codeChallengeMethod: pair.codeChallengeMethod
        )

        return SSOPKCEAuthorizationUrlResult(
            url: url, codeVerifier: pair.codeVerifier, state: resolvedState)
    }

    /// Exchange an SSO authorization code with a PKCE code verifier for a
    /// profile and token. The client secret is only sent when an API key is
    /// configured, so this works for public clients too.
    public func ssoPKCECodeExchange(
        code: String, codeVerifier: String, requestOptions: RequestOptions? = nil
    ) async throws -> SSOTokenResponse {
        var body = EncodableBody()
        body.set("grant_type", "authorization_code")
        body.set("code", code)
        body.set("code_verifier", codeVerifier)
        body.set("client_id", configuration.clientID)
        if !configuration.apiKey.isEmpty {
            body.set("client_secret", configuration.apiKey)
        }
        return try await transport.request(
            method: "POST",
            path: "sso/token",
            query: [],
            body: body,
            options: requestOptions,
            as: SSOTokenResponse.self
        )
    }

    /// Run the SSO logout flow: obtain a logout token for the session, then
    /// build the logout redirect URL to send the user to.
    public func ssoLogout(
        sessionId: String, returnTo: String? = nil, requestOptions: RequestOptions? = nil
    ) async throws -> URL {
        let logoutResponse = try await sso.authorizeLogout(
            profileId: sessionId, requestOptions: requestOptions)

        var query = [URLQueryItem(name: "token", value: logoutResponse.logoutToken)]
        if let returnTo {
            query.append(URLQueryItem(name: "return_to", value: returnTo))
        }
        return transport.buildURL(path: "sso/logout", query: query)
    }
}
