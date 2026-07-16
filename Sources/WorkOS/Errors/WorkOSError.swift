// @oagen-ignore-file

import Foundation

/// The structured error payload returned by the API on a non-2xx response.
public struct APIError: Error, Sendable, Equatable {
    /// The HTTP status code of the response.
    public let statusCode: Int
    /// A human-readable error message.
    public let message: String
    /// A machine-readable error code, when provided.
    public let code: String?
    /// The request identifier, useful when contacting support.
    public let requestID: String?
    /// The raw decoded error body, when available.
    public let raw: AnyCodable?

    public init(
        statusCode: Int, message: String, code: String? = nil, requestID: String? = nil,
        raw: AnyCodable? = nil
    ) {
        self.statusCode = statusCode
        self.message = message
        self.code = code
        self.requestID = requestID
        self.raw = raw
    }
}

/// The error type thrown by WorkOS SDK operations.
public enum WorkOSError: Error, Sendable {
    /// 400 — BadRequest error.
    case badRequest(APIError)
    /// 401 — Authentication error.
    case authentication(APIError)
    /// 403 — Authorization error.
    case authorization(APIError)
    /// 404 — NotFound error.
    case notFound(APIError)
    /// 409 — Conflict error.
    case conflict(APIError)
    /// 422 — UnprocessableEntity error.
    case unprocessableEntity(APIError)
    /// 429 — RateLimitExceeded error.
    case rateLimitExceeded(APIError)
    /// A 5xx server error.
    case server(APIError)
    /// A non-2xx response that did not match a known status.
    case api(APIError)
    /// A transport-level networking failure.
    case network(URLError)
    /// The response body could not be decoded into the expected type.
    case decoding(any Error)
    /// The response was not a valid HTTP response.
    case invalidResponse

    /// Map an HTTP status code and decoded payload to the appropriate case.
    public static func from(statusCode: Int, apiError: APIError) -> WorkOSError {
        switch statusCode {
        case 400: return .badRequest(apiError)
        case 401: return .authentication(apiError)
        case 403: return .authorization(apiError)
        case 404: return .notFound(apiError)
        case 409: return .conflict(apiError)
        case 422: return .unprocessableEntity(apiError)
        case 429: return .rateLimitExceeded(apiError)
        case 500...599: return .server(apiError)
        default: return .api(apiError)
        }
    }
}
