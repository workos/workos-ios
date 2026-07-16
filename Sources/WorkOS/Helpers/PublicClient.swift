// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation

/// A client preset for PKCE-only / public-client usage: no API key or client
/// secret is required or ever sent. It exposes only the helper surface that
/// is safe for public clients (native apps, CLIs, browsers).
public struct PublicClient: Sendable {
    let client: WorkOSClient

    /// Create a public client for the given client ID. No API key is required.
    public init(clientID: String, baseURL: URL? = nil) {
        let configuration = Configuration(apiKey: "", baseURL: baseURL, clientID: clientID)
        self.init(client: WorkOSClient(configuration: configuration))
    }

    init(client: WorkOSClient) {
        self.client = client
    }

    /// Build an AuthKit authorization URL.
    public func getAuthorizationUrl(
        redirectUri: String,
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
        try client.getAuthKitAuthorizationUrl(
            redirectUri: redirectUri,
            provider: provider,
            connectionId: connectionId,
            organizationId: organizationId,
            domainHint: domainHint,
            loginHint: loginHint,
            state: state,
            codeChallenge: codeChallenge,
            codeChallengeMethod: codeChallengeMethod,
            screenHint: screenHint
        )
    }

    /// Build an AuthKit authorization URL with auto-generated PKCE and state.
    public func getAuthorizationUrlWithPKCE(
        redirectUri: String,
        provider: String? = nil,
        connectionId: String? = nil,
        organizationId: String? = nil,
        domainHint: String? = nil,
        loginHint: String? = nil,
        state: String? = nil,
        screenHint: String? = nil
    ) throws -> PKCEAuthorizationUrlResult {
        try client.getAuthKitAuthorizationUrlWithPKCE(
            redirectUri: redirectUri,
            provider: provider,
            connectionId: connectionId,
            organizationId: organizationId,
            domainHint: domainHint,
            loginHint: loginHint,
            state: state,
            screenHint: screenHint
        )
    }

    /// Exchange an authorization code with a PKCE code verifier. No client
    /// secret is sent.
    public func authenticateWithCode(
        code: String, codeVerifier: String, requestOptions: RequestOptions? = nil
    ) async throws -> AuthenticateResponse {
        try await client.authKitPKCECodeExchange(
            code: code, codeVerifier: codeVerifier, requestOptions: requestOptions)
    }

    /// Build an SSO authorization URL.
    public func getSSOAuthorizationUrl(
        redirectUri: String,
        provider: String? = nil,
        connectionId: String? = nil,
        organizationId: String? = nil,
        domainHint: String? = nil,
        loginHint: String? = nil,
        state: String? = nil,
        codeChallenge: String? = nil,
        codeChallengeMethod: String? = nil
    ) throws -> URL {
        try client.getSSOAuthorizationUrl(
            redirectUri: redirectUri,
            provider: provider,
            connectionId: connectionId,
            organizationId: organizationId,
            domainHint: domainHint,
            loginHint: loginHint,
            state: state,
            codeChallenge: codeChallenge,
            codeChallengeMethod: codeChallengeMethod
        )
    }

    /// Build an SSO authorization URL with auto-generated PKCE and state.
    public func getSSOAuthorizationUrlWithPKCE(
        redirectUri: String,
        provider: String? = nil,
        connectionId: String? = nil,
        organizationId: String? = nil,
        domainHint: String? = nil,
        loginHint: String? = nil,
        state: String? = nil
    ) throws -> SSOPKCEAuthorizationUrlResult {
        try client.getSSOAuthorizationUrlWithPKCE(
            redirectUri: redirectUri,
            provider: provider,
            connectionId: connectionId,
            organizationId: organizationId,
            domainHint: domainHint,
            loginHint: loginHint,
            state: state
        )
    }

    /// Exchange an SSO authorization code with PKCE for a profile and token.
    /// No client secret is sent.
    public func getSSOProfileAndTokenWithPKCE(
        code: String, codeVerifier: String, requestOptions: RequestOptions? = nil
    ) async throws -> SSOTokenResponse {
        try await client.ssoPKCECodeExchange(
            code: code, codeVerifier: codeVerifier, requestOptions: requestOptions)
    }

    /// Initiate a device authorization flow.
    public func createDevice(requestOptions: RequestOptions? = nil) async throws
        -> DeviceAuthorizationResponse
    {
        try await client.authKitStartDeviceAuthorization(requestOptions: requestOptions)
    }

    /// Poll for device-code completion.
    public func pollDeviceAuthorization(
        deviceCode: String, interval: Int = 5, requestOptions: RequestOptions? = nil
    ) async throws -> AuthenticateResponse {
        try await client.authKitPollDeviceCode(
            deviceCode: deviceCode, interval: interval, requestOptions: requestOptions)
    }

    /// Fetch the JSON Web Key Set used to verify access tokens.
    public func getJwks(requestOptions: RequestOptions? = nil) async throws -> JwksResponse {
        try await client.getJwks(requestOptions: requestOptions)
    }

    /// The JWKS URL for this public client.
    public func jwksURL() throws -> URL {
        try client.jwksURL()
    }
}
