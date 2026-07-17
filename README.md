# Official WorkOS iOS SDK

The WorkOS iOS SDK provides convenient access to AuthKit and the WorkOS API from Swift applications. It includes public-client helpers for native authentication with PKCE, async API clients, typed models and errors, automatic retries, and pagination helpers.

## Get started with WorkOS

1. [Sign up for a WorkOS account](https://dashboard.workos.com/).
2. Create or select an application in the WorkOS Dashboard, then configure its redirect URI.
3. Copy the application's client ID and follow the [AuthKit documentation](https://workos.com/docs/authkit).

## Installation

### Requirements

- iOS 17+ / Mac Catalyst 17+ / macOS 14+ / tvOS 17+ / watchOS 10+ / visionOS 1+
- Xcode 26+
- Swift 6.2+

### Swift Package Manager

In Xcode, open your project and choose **File > Add Package Dependencies**, then enter:

```text
https://github.com/workos/workos-ios
```

Alternatively, add the package to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/workos/workos-ios", from: "0.1.0")
],
targets: [
    .target(
        name: "YourApp",
        dependencies: [
            .product(name: "WorkOS", package: "workos-ios")
        ]
    )
]
```

## Quickstart

### AuthKit in a native app

Use `PublicClient` for native authentication. It requires only your application's client ID and uses PKCE, so no API key or client secret is embedded in your app.

```swift
import WorkOS

let workos = PublicClient(clientID: "client_...")

let authorization = try workos.getAuthorizationUrlWithPKCE(
    redirectUri: "https://example.com/auth/callback",
    provider: "authkit"
)

// Present authorization.url with ASWebAuthenticationSession. After WorkOS
// redirects back to your app, validate the returned state, then exchange the
// authorization code using the original PKCE verifier.
let authentication = try await workos.authenticateWithCode(
    code: authorizationCode,
    codeVerifier: authorization.codeVerifier
)
```

Store `authorization.codeVerifier` securely until the callback completes, and verify that the returned state matches `authorization.state` before exchanging the code.

> [!IMPORTANT]
> Never include a WorkOS API key in an iOS, macOS, watchOS, tvOS, or visionOS app. API keys must only be used in trusted server environments.

### WorkOS API in a trusted environment

For server-side Swift, initialize the full client with an API key:

```swift
import Foundation
import WorkOS

let workos = WorkOSClient(
    apiKey: ProcessInfo.processInfo.environment["WORKOS_API_KEY"]!
)

let organization = try await workos.organizations.create(name: "Acme, Inc.")
print(organization.id)
```

## Documentation

- [AuthKit documentation](https://workos.com/docs/authkit)
- [WorkOS API reference](https://workos.com/docs/reference)
- [Client library reference](https://workos.com/docs/reference/client-libraries)

## Release notes

See [GitHub Releases](https://github.com/workos/workos-ios/releases) for details about each release.

## SDK versioning

The WorkOS iOS SDK follows [Semantic Versioning](https://semver.org/). Breaking changes are released only in major versions; review the release notes before upgrading across a major version boundary.

## Contributing

Contributions are welcome. To run formatting checks, build the package, and execute the test suite locally:

```sh
script/ci
```

