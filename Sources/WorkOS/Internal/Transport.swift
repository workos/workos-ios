// @oagen-ignore-file

import Foundation

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// The HTTP transport: request assembly, retries with backoff, and error mapping.
public struct Transport: Sendable {
    public let configuration: Configuration
    let session: URLSession

    public init(configuration: Configuration, session: URLSession = .shared) {
        self.configuration = configuration
        self.session = session
    }

    func request<T: Decodable>(
        method: String,
        path: String,
        query: [URLQueryItem],
        body: (any Encodable & Sendable)?,
        options: RequestOptions?,
        as type: T.Type
    ) async throws -> T {
        let data = try await perform(
            method: method, path: path, query: query, body: body, options: options)
        do {
            return try Coding.makeDecoder().decode(T.self, from: data)
        } catch {
            throw WorkOSError.decoding(error)
        }
    }

    func requestVoid(
        method: String,
        path: String,
        query: [URLQueryItem],
        body: (any Encodable & Sendable)?,
        options: RequestOptions?
    ) async throws {
        _ = try await perform(
            method: method, path: path, query: query, body: body, options: options)
    }

    /// Assemble the absolute URL for a path and query against the configured
    /// base URL. Used for every request and exposed to the generated
    /// URL-builder methods (browser-redirect endpoints that never issue a
    /// request themselves).
    func buildURL(path: String, query: [URLQueryItem]) -> URL {
        var urlString = configuration.baseURL.absoluteString
        if urlString.hasSuffix("/") { urlString.removeLast() }
        urlString += "/" + path
        var components = URLComponents(string: urlString) ?? URLComponents()
        if !query.isEmpty {
            components.queryItems = (components.queryItems ?? []) + query
        }
        return components.url ?? configuration.baseURL
    }

    private func perform(
        method: String,
        path: String,
        query: [URLQueryItem],
        body: (any Encodable & Sendable)?,
        options: RequestOptions?
    ) async throws -> Data {
        let url = buildURL(path: path, query: query)

        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("WorkOS swift/1.0", forHTTPHeaderField: "User-Agent")
        request.setValue("Bearer \(configuration.apiKey)", forHTTPHeaderField: "Authorization")
        request.timeoutInterval = options?.timeout ?? configuration.timeout

        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try Coding.makeEncoder().encode(AnyEncodable(body))
        }

        if method == "POST" {
            request.setValue(
                options?.idempotencyKey ?? UUID().uuidString, forHTTPHeaderField: "Idempotency-Key")
        }

        if let options {
            for (name, value) in options.additionalHeaders {
                request.setValue(value, forHTTPHeaderField: name)
            }
        }

        var attempt = 0
        while true {
            do {
                let (data, response) = try await session.data(for: request)
                guard let http = response as? HTTPURLResponse else {
                    throw WorkOSError.invalidResponse
                }
                if (200..<300).contains(http.statusCode) {
                    return data
                }
                if configuration.retryableStatusCodes.contains(http.statusCode),
                    attempt < configuration.maxRetries
                {
                    attempt += 1
                    let delay = backoffNanoseconds(
                        attempt: attempt, retryAfter: http.value(forHTTPHeaderField: "Retry-After"))
                    try await Task.sleep(nanoseconds: delay)
                    continue
                }
                throw makeError(
                    statusCode: http.statusCode,
                    data: data,
                    requestID: http.value(forHTTPHeaderField: "X-Request-ID")
                )
            } catch let error as URLError {
                if attempt < configuration.maxRetries {
                    attempt += 1
                    let delay = backoffNanoseconds(attempt: attempt, retryAfter: nil)
                    try await Task.sleep(nanoseconds: delay)
                    continue
                }
                throw WorkOSError.network(error)
            }
        }
    }

    private func backoffNanoseconds(attempt: Int, retryAfter: String?) -> UInt64 {
        if let retryAfter, let seconds = Double(retryAfter) {
            return UInt64(max(0, seconds) * 1_000_000_000)
        }
        let base = 1.0 * pow(2.0, Double(attempt - 1))
        let capped = min(base, 30.0)
        let jitter = capped * 0.5 * Double.random(in: -1...1)
        let delay = max(0, capped + jitter)
        return UInt64(delay * 1_000_000_000)
    }

    private func makeError(statusCode: Int, data: Data, requestID: String?) -> WorkOSError {
        let decoder = Coding.makeDecoder()
        let body = try? decoder.decode(APIErrorBody.self, from: data)
        let raw = try? decoder.decode(AnyCodable.self, from: data)
        let message = body?.message ?? body?.errorDescription ?? body?.error ?? "HTTP \(statusCode)"
        let apiError = APIError(
            statusCode: statusCode,
            message: message,
            code: body?.code,
            requestID: requestID ?? body?.requestID,
            raw: raw
        )
        return WorkOSError.from(statusCode: statusCode, apiError: apiError)
    }
}

private struct APIErrorBody: Decodable {
    let message: String?
    let error: String?
    let errorDescription: String?
    let code: String?
    let requestID: String?

    enum CodingKeys: String, CodingKey {
        case message
        case error
        case code
        case errorDescription = "error_description"
        case requestID = "request_id"
    }
}
