// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import CommonCrypto
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
/// New seals use `wos2.` followed by base64 `salt(16) || nonce(12) || ciphertext || tag`.
/// Keys are derived with PBKDF2-HMAC-SHA256 (600,000 iterations), costing roughly
/// 100–300 ms of CPU per seal/unseal depending on the device. These synchronous
/// operations should run off the UI thread. Legacy seals remain readable and
/// are upgraded the next time the session is sealed.
/// Use a cryptographically random password of at least 32 characters.
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
        let salt = SymmetricKey(size: .bits128).withUnsafeBytes { Data($0) }
        let key = try deriveKey(password, salt: salt)
        do {
            let sealedBox = try AES.GCM.seal(
                plaintext, using: key, authenticating: Data("wos2.".utf8))
            var output = salt
            output.append(contentsOf: sealedBox.nonce)
            output.append(sealedBox.ciphertext)
            output.append(sealedBox.tag)
            return "wos2." + output.base64EncodedString()
        } catch {
            throw SessionSealingError.cryptoFailure("encryption failed: \(error)")
        }
    }

    /// Decrypt a sealed base64 string back to raw bytes.
    static func unsealBytes(_ sealed: String, password: String) throws -> Data {
        let versioned = sealed.hasPrefix("wos2.")
        guard let raw = Data(base64Encoded: versioned ? String(sealed.dropFirst(5)) : sealed) else {
            throw SessionSealingError.invalidSealedData
        }
        // nonce(12) plus tag(16) with at least some ciphertext.
        guard raw.count > (versioned ? 44 : 28) else {
            throw SessionSealingError.sealedDataTooShort
        }

        let key =
            versioned ? try deriveKey(password, salt: Data(raw.prefix(16))) : deriveKey(password)
        let payload = versioned ? Data(raw.dropFirst(16)) : raw
        do {
            let sealedBox = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: payload.prefix(12)),
                ciphertext: payload.dropFirst(12).dropLast(16),
                tag: payload.suffix(16)
            )
            return try AES.GCM.open(
                sealedBox, using: key, authenticating: versioned ? Data("wos2.".utf8) : Data())
        } catch {
            throw SessionSealingError.cryptoFailure("decryption failed: \(error)")
        }
    }

    private static func deriveKey(_ password: String, salt: Data) throws -> SymmetricKey {
        let passwordBytes = Array(password.utf8)
        var key = [UInt8](repeating: 0, count: 32)
        let status = passwordBytes.withUnsafeBytes { passwordBuffer in
            salt.withUnsafeBytes { saltBuffer in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordBuffer.baseAddress?.assumingMemoryBound(to: Int8.self),
                    passwordBytes.count,
                    saltBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 600_000, &key, key.count)
            }
        }
        guard status == kCCSuccess else {
            throw SessionSealingError.cryptoFailure("key derivation failed")
        }
        return SymmetricKey(data: key)
    }

    /// Legacy read-only derivation. Derive a 32-byte AES key from the password: hex-decode when the
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
