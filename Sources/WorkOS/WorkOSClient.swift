// @oagen-ignore-file

import Foundation

/// The WorkOS API client.
///
/// ```swift
/// let client = WorkOSClient(apiKey: "sk_...")
/// ```
///
/// The spec-driven resource accessors (`client.organizations`, `client.sso`,
/// ...) are generated into `WorkOSClient+Resources.swift`; this file owns the
/// hand-maintained client core.
public final class WorkOSClient: Sendable {
    /// The configuration this client was created with.
    public let configuration: Configuration
    let transport: Transport

    init(configuration: Configuration, transport: Transport) {
        self.configuration = configuration
        self.transport = transport
    }

    /// Create a client from a full configuration.
    public convenience init(configuration: Configuration) {
        self.init(configuration: configuration, transport: Transport(configuration: configuration))
    }

    /// Create a client with an API key and an optional base URL override.
    public convenience init(apiKey: String, baseURL: URL? = nil) {
        self.init(configuration: Configuration(apiKey: apiKey, baseURL: baseURL))
    }
}
