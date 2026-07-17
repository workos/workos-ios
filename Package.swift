// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "WorkOS",
    platforms: [
        .iOS(.v17),
        .macCatalyst(.v17),
        .macOS(.v14),
        .watchOS(.v10),
        .tvOS(.v17),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "WorkOS", targets: ["WorkOS"])
    ],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.1.0")
    ],
    targets: [
        .target(name: "WorkOS"),
        .testTarget(name: "WorkOSTests", dependencies: ["WorkOS"]),
    ],
    swiftLanguageModes: [.v5]
)
