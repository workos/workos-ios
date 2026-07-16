// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import CryptoKit
import Foundation

/// Errors thrown by the raw seal/unseal helpers.
public enum SessionSealingError: Error, Equatable, Sendable {
    /// The sealed string is not valid base64.
    case invalidSealedData
    /// The sealed payload is too short to contain a nonce and ciphertext.
    case sealedDataTooShort
    /// AES-GCM encryption or decryption failed (wrong password or corrupt data).
    case cryptoFailure(String)
}

/// Raw seal/unseal helpers for session payloads.
///
/// `seal` encrypts any JSON-serializable value with AES-256-GCM and returns a
/// base64 string of `nonce(12) || ciphertext || tag`. The password is used
/// directly as the key when it is a hex-encoded 32-byte string (64 hex
/// characters); otherwise it is hashed with SHA-256 to derive the key.
public enum SessionSealing {
    /// Encrypt a JSON-serializable value into a sealed base64 string.
    public static func seal<T: Encodable>(_ value: T, password: String) throws -> String {
        let plaintext = try Coding.makeEncoder().encode(value)
        return try sealBytes(plaintext, password: password)
    }

    /// Decrypt a sealed string back into a typed value.
    public static func unseal<T: Decodable>(
        _ sealed: String, password: String, as type: T.Type = T.self
    ) throws -> T {
        let plaintext = try unsealBytes(sealed, password: password)
        return try Coding.makeDecoder().decode(T.self, from: plaintext)
    }

    /// Encrypt raw bytes with AES-256-GCM using the derived key.
    static func sealBytes(_ plaintext: Data, password: String) throws -> String {
        let key = deriveKey(password)
        do {
            let sealedBox = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce())
            var output = Data(sealedBox.nonce)
            output.append(sealedBox.ciphertext)
            output.append(sealedBox.tag)
            return output.base64EncodedString()
        } catch {
            throw SessionSealingError.cryptoFailure("encryption failed: \(error)")
        }
    }

    /// Decrypt a sealed base64 string back to raw bytes.
    static func unsealBytes(_ sealed: String, password: String) throws -> Data {
        guard let raw = Data(base64Encoded: sealed) else {
            throw SessionSealingError.invalidSealedData
        }
        // nonce(12) plus tag(16) with at least some ciphertext.
        guard raw.count > 28 else {
            throw SessionSealingError.sealedDataTooShort
        }

        let key = deriveKey(password)
        do {
            let sealedBox = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: raw.prefix(12)),
                ciphertext: raw.dropFirst(12).dropLast(16),
                tag: raw.suffix(16)
            )
            return try AES.GCM.open(sealedBox, using: key)
        } catch {
            throw SessionSealingError.cryptoFailure("decryption failed: \(error)")
        }
    }

    /// Derive a 32-byte AES key from the password: hex-decode when the
    /// password is exactly 64 hex characters, otherwise SHA-256 the UTF-8 bytes.
    static func deriveKey(_ password: String) -> SymmetricKey {
        if password.count == 64, let decoded = decodeHex(password), decoded.count == 32 {
            return SymmetricKey(data: decoded)
        }
        return SymmetricKey(data: Data(SHA256.hash(data: Data(password.utf8))))
    }

    private static func decodeHex(_ string: String) -> Data? {
        guard string.count % 2 == 0 else { return nil }
        var data = Data(capacity: string.count / 2)
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: 2)
            guard let byte = UInt8(string[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        return data
    }
}
