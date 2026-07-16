// @oagen-ignore-file

import Foundation

/// A dynamically-keyed, order-preserving JSON request-body builder. Optional
/// values that are `nil` are skipped so absent parameters are not serialized.
public struct EncodableBody: Encodable, Sendable {
    private var entries: [(String, any Encodable & Sendable)]

    public init() {
        entries = []
    }

    public mutating func set(_ key: String, _ value: (any Encodable & Sendable)?) {
        guard let value else { return }
        entries.append((key, value))
    }

    public var isEmpty: Bool { entries.isEmpty }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: DynamicCodingKey.self)
        for (key, value) in entries {
            try container.encode(AnyEncodable(value), forKey: DynamicCodingKey(stringValue: key))
        }
    }
}

/// Wraps an existential `Encodable` so it can be encoded through a concrete type.
struct AnyEncodable: Encodable {
    private let value: any Encodable
    init(_ value: any Encodable) { self.value = value }
    func encode(to encoder: Encoder) throws { try value.encode(to: encoder) }
}

/// A coding key created from an arbitrary string, for dynamic JSON objects.
struct DynamicCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?
    init(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }
    init?(intValue: Int) {
        self.stringValue = String(intValue)
        self.intValue = intValue
    }
}
