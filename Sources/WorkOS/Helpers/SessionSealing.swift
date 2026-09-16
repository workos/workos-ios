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
/// Passwords of at least ``minimumPasswordLength`` characters produce `wos2.` seals: `wos2.`
/// followed by base64 `salt(16) || nonce(12) || ciphertext || tag`. The password is stretched
/// once with PBKDF2-HMAC-SHA256 (600,000 iterations, roughly 100–300 ms of CPU depending on the
/// device) into a master key that is cached per process, and each seal derives its AES-256-GCM
/// key from that master key with HKDF-SHA256 over the per-seal salt, which is cheap. Untrusted
/// cookie bytes never reach the expensive derivation, so a forged cookie costs only an HKDF
/// expansion and a failed AES-GCM open. The first seal/unseal for a given password is
/// synchronous and should run off the UI thread.
///
/// Shorter legacy passwords keep producing and reading legacy `nonce(12) || ciphertext || tag`
/// seals keyed by SHA-256 of the password, so existing deployments are not logged out. They
/// never receive `wos2.` seals, and verified authentication rejects them. Legacy seals under a
/// password of at least ``minimumPasswordLength`` characters are upgraded to `wos2.` the next
/// time the session is sealed. Use a cryptographically random password of at least 32 characters.
public enum SessionSealing {
    /// Minimum password length for verified sessions and for `wos2.` seals. The fixed-salt
    /// master-key derivation is only ever applied to passwords at least this long.
    static let minimumPasswordLength = 32

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
        guard password.count >= minimumPasswordLength else {
            return try sealLegacyBytes(plaintext, password: password)
        }
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

    /// Legacy `nonce(12) || ciphertext || tag` seal for passwords shorter than
    /// ``minimumPasswordLength``. Deployments on short legacy passwords keep refreshing
    /// sessions without forced logouts, and because they never receive `wos2.` seals the
    /// fixed-salt master-key derivation never runs on a password weak enough to precompute.
    private static func sealLegacyBytes(_ plaintext: Data, password: String) throws -> String {
        let sealedBox: AES.GCM.SealedBox
        do {
            sealedBox = try AES.GCM.seal(plaintext, using: deriveKey(password))
        } catch {
            throw SessionSealingError.cryptoFailure("encryption failed: \(error)")
        }
        guard let combined = sealedBox.combined else {
            throw SessionSealingError.cryptoFailure("encryption failed: non-standard nonce")
        }
        return combined.base64EncodedString()
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

    /// Derive the per-seal AES-256-GCM key by expanding the cached master key over the
    /// per-seal salt with HKDF-SHA256. This is the only derivation that untrusted cookie
    /// bytes can influence, and it costs a few HMAC invocations.
    static func deriveKey(_ password: String, salt: Data) throws -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: try masterKey(for: password), salt: salt,
            info: Data("wos2.aes-256-gcm".utf8), outputByteCount: 32)
    }

    /// The PBKDF2-stretched master key for a password, derived at most once per process and
    /// cached. The PBKDF2 salt is a fixed domain-separation constant rather than a per-cookie
    /// value, so the cost can never be triggered by request data. That is only safe for
    /// passwords of at least ``minimumPasswordLength`` characters, where a precomputed
    /// dictionary is infeasible, so shorter passwords are rejected here before any derivation;
    /// per-seal key separation comes from HKDF instead.
    static func masterKey(for password: String) throws -> SymmetricKey {
        guard password.count >= minimumPasswordLength else {
            throw SessionSealingError.cryptoFailure(
                "wos2 seals require a password of at least \(minimumPasswordLength) characters")
        }
        return try masterKeys.key(for: password)
    }

    private static let masterKeys = MasterKeyCache()

    /// PBKDF2-HMAC-SHA256 with 600,000 iterations over the password and the fixed
    /// `wos2` domain salt.
    fileprivate static func stretch(_ password: String) throws -> SymmetricKey {
        let passwordBytes = Array(password.utf8)
        let salt = Data("workos-ios/session-seal/wos2".utf8)
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

    /// Legacy derivation, used to read every legacy seal and to write seals for passwords shorter
    /// than ``minimumPasswordLength``. Derive a 32-byte AES key from the password: hex-decode
    /// when the password is exactly 64 hex characters, otherwise SHA-256 the UTF-8 bytes.
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

/// Bounded cache of PBKDF2 master keys keyed by SHA-256 of the password, so the raw password
/// is not retained. Only server-configured passwords ever reach the cache; cookie contents
/// cannot add or evict entries. Concurrent first-use callers for one password share a single
/// stretch, and lookups for already-cached passwords never wait behind a stretch in progress.
private final class MasterKeyCache: @unchecked Sendable {
    private static let capacity = 16
    private let lock = NSLock()
    private var keys: [Data: SymmetricKey] = [:]
    private var insertionOrder: [Data] = []
    private var pendingStretches: [Data: NSLock] = [:]

    func key(for password: String) throws -> SymmetricKey {
        let id = Data(SHA256.hash(data: Data(password.utf8)))
        if let cached = lock.withLock({ keys[id] }) { return cached }

        // Serialize first-use callers per password so exactly one of them stretches
        // while the others wait for its result, without holding the cache lock.
        let stretchLock: NSLock = lock.withLock {
            if let pending = pendingStretches[id] { return pending }
            let pending = NSLock()
            pendingStretches[id] = pending
            return pending
        }
        stretchLock.lock()
        defer { stretchLock.unlock() }
        if let cached = lock.withLock({ keys[id] }) { return cached }

        let key = try SessionSealing.stretch(password)
        lock.withLock {
            if insertionOrder.count >= Self.capacity {
                keys.removeValue(forKey: insertionOrder.removeFirst())
            }
            keys[id] = key
            insertionOrder.append(id)
            pendingStretches.removeValue(forKey: id)
        }
        return key
    }
}
