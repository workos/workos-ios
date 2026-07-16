// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation

/// JWKS helpers: build the JWKS URL used to verify WorkOS-issued access tokens.
public enum JWKS {
    /// Build the JWKS URL for a client ID against a base URL.
    public static func url(
        baseURL: URL = Configuration.defaultBaseURL, clientID: String
    ) -> URL {
        var urlString = baseURL.absoluteString
        if urlString.hasSuffix("/") { urlString.removeLast() }
        return URL(string: "\(urlString)/sso/jwks/\(PathEncoding.segment(clientID))")
            ?? baseURL
    }
}

extension WorkOSClient {
    /// The JWKS URL for this client's configured base URL and client ID.
    public func jwksURL(clientID: String? = nil) throws -> URL {
        guard let resolvedClientID = clientID ?? configuration.clientID else {
            throw HelperError.missingClientID
        }
        return JWKS.url(baseURL: configuration.baseURL, clientID: resolvedClientID)
    }

    /// Fetch the JSON Web Key Set used to verify access tokens.
    public func getJwks(
        clientID: String? = nil, requestOptions: RequestOptions? = nil
    ) async throws -> JwksResponse {
        guard let resolvedClientID = clientID ?? configuration.clientID else {
            throw HelperError.missingClientID
        }
        return try await userManagement.getJwks(
            clientId: resolvedClientID, requestOptions: requestOptions)
    }
}
