// @oagen-ignore-file

import Foundation

/// Per-request overrides applied on top of the client configuration.
public struct RequestOptions: Sendable {
    /// Extra headers merged into (and overriding) the default request headers.
    public var additionalHeaders: [String: String]
    /// An explicit idempotency key for this request.
    public var idempotencyKey: String?
    /// A per-request timeout override, in seconds.
    public var timeout: TimeInterval?

    public init(
        additionalHeaders: [String: String] = [:],
        idempotencyKey: String? = nil,
        timeout: TimeInterval? = nil
    ) {
        self.additionalHeaders = additionalHeaders
        self.idempotencyKey = idempotencyKey
        self.timeout = timeout
    }
}
