// @oagen-ignore-file

import Foundation

/// Per-segment path percent-encoding. Every path-parameter value MUST be routed
/// through this helper: without it a caller-supplied id containing "../" is
/// silently normalized before transmission, forging a request to a different
/// endpoint under the same credentials.
public enum PathEncoding {
    public static func segment(_ value: String) -> String {
        var allowed = CharacterSet.urlPathAllowed
        allowed.remove(charactersIn: "/")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }

    public static func segment(_ value: some CustomStringConvertible) -> String {
        segment(String(describing: value))
    }
}
