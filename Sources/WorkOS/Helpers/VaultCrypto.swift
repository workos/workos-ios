// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import CryptoKit
import Foundation

/// The result of a `Vault.encrypt` call.
public struct VaultEncryptResult: Sendable, Equatable {
    /// The base64-encoded ciphertext (LEB128 header + encrypted keys + nonce + AES-GCM output).
    public let encryptedData: String
    /// The encryption key context used for this operation.
    public let keyContext: [String: String]
    /// The base64-encoded encrypted key blob for later decryption via the API.
    public let encryptedKeys: String

    public init(encryptedData: String, keyContext: [String: String], encryptedKeys: String) {
        self.encryptedData = encryptedData
        self.keyContext = keyContext
        self.encryptedKeys = encryptedKeys
    }
}

/// Errors thrown by the client-side Vault crypto helpers.
public enum VaultCryptoError: Error, Equatable, Sendable {
    /// A base64 field could not be decoded.
    case invalidBase64(field: String)
    /// The LEB128 length prefix could not be decoded.
    case invalidLEB128
    /// The encrypted payload is truncated or structurally invalid.
    case malformedPayload(String)
    /// AES-GCM encryption or decryption failed.
    case cryptoFailure(String)
    /// The decrypted plaintext is not valid UTF-8.
    case invalidPlaintext
}

extension Vault {
    /// Generate a data key and encrypt `data` locally using AES-256-GCM.
    public func encrypt(
        data: String,
        context: [String: String],
        associatedData: String = "",
        requestOptions: RequestOptions? = nil
    ) async throws -> VaultEncryptResult {
        let keyPair = try await createDataKey(context: context, requestOptions: requestOptions)
        let encrypted = try VaultLocalCrypto.encrypt(
            data, keyPair: keyPair, associatedData: associatedData)
        return VaultEncryptResult(
            encryptedData: encrypted,
            keyContext: keyPair.context,
            encryptedKeys: keyPair.encryptedKeys
        )
    }

    /// Decrypt locally encrypted data by first decrypting its data key via the API.
    public func decrypt(
        encryptedData: String,
        associatedData: String = "",
        requestOptions: RequestOptions? = nil
    ) async throws -> String {
        guard let raw = Data(base64Encoded: encryptedData) else {
            throw VaultCryptoError.invalidBase64(field: "encryptedData")
        }

        let (keysLength, bytesRead) = try VaultLocalCrypto.decodeLEB128(raw)
        guard raw.count - bytesRead >= Int(keysLength) else {
            throw VaultCryptoError.malformedPayload(
                "encrypted data too short for declared key length")
        }

        let encryptedKeys = raw.subdata(in: bytesRead..<(bytesRead + Int(keysLength)))
        let dataKey = try await createDecrypt(
            keys: encryptedKeys.base64EncodedString(), requestOptions: requestOptions)

        return try VaultLocalCrypto.decrypt(
            encryptedData, dataKey: dataKey, associatedData: associatedData)
    }
}

/// Client-side AES-256-GCM primitives for Vault data, usable with pre-fetched
/// data keys. Wire format (before base64):
/// `LEB128(len(encryptedKeys)) || encryptedKeys || nonce(12) || ciphertext+tag`.
public enum VaultLocalCrypto {
    /// Encrypt data with AES-256-GCM using a pre-fetched data key pair.
    public static func encrypt(
        _ data: String, keyPair: CreateDataKeyResponse, associatedData: String = ""
    ) throws -> String {
        guard let rawKey = Data(base64Encoded: keyPair.dataKey) else {
            throw VaultCryptoError.invalidBase64(field: "dataKey")
        }
        guard let encryptedKeys = Data(base64Encoded: keyPair.encryptedKeys) else {
            throw VaultCryptoError.invalidBase64(field: "encryptedKeys")
        }

        let key = SymmetricKey(data: rawKey)
        let nonce = AES.GCM.Nonce()
        let sealedBox: AES.GCM.SealedBox
        do {
            if associatedData.isEmpty {
                sealedBox = try AES.GCM.seal(Data(data.utf8), using: key, nonce: nonce)
            } else {
                sealedBox = try AES.GCM.seal(
                    Data(data.utf8), using: key, nonce: nonce,
                    authenticating: Data(associatedData.utf8))
            }
        } catch {
            throw VaultCryptoError.cryptoFailure("encryption failed: \(error)")
        }

        var buffer = encodeLEB128(UInt32(encryptedKeys.count))
        buffer.append(encryptedKeys)
        buffer.append(Data(nonce))
        buffer.append(sealedBox.ciphertext)
        buffer.append(sealedBox.tag)
        return buffer.base64EncodedString()
    }

    /// Decrypt data with AES-256-GCM using a pre-fetched data key.
    public static func decrypt(
        _ encryptedData: String, dataKey: DecryptResponse, associatedData: String = ""
    ) throws -> String {
        guard let raw = Data(base64Encoded: encryptedData) else {
            throw VaultCryptoError.invalidBase64(field: "encryptedData")
        }

        let (keysLength, bytesRead) = try decodeLEB128(raw)
        let offset = bytesRead + Int(keysLength)
        guard offset + 12 <= raw.count else {
            throw VaultCryptoError.malformedPayload("encrypted data too short: missing nonce")
        }

        let nonceData = raw.subdata(in: offset..<(offset + 12))
        let ciphertextAndTag = raw.subdata(in: (offset + 12)..<raw.count)
        // The GCM tag is 16 bytes; anything shorter has no ciphertext at all.
        guard ciphertextAndTag.count > 16 else {
            throw VaultCryptoError.malformedPayload("encrypted data too short: missing ciphertext")
        }

        guard let rawKey = Data(base64Encoded: dataKey.dataKey) else {
            throw VaultCryptoError.invalidBase64(field: "dataKey")
        }

        let key = SymmetricKey(data: rawKey)
        do {
            let sealedBox = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: nonceData),
                ciphertext: ciphertextAndTag.dropLast(16),
                tag: ciphertextAndTag.suffix(16)
            )
            let plaintext: Data
            if associatedData.isEmpty {
                plaintext = try AES.GCM.open(sealedBox, using: key)
            } else {
                plaintext = try AES.GCM.open(
                    sealedBox, using: key, authenticating: Data(associatedData.utf8))
            }
            guard let result = String(data: plaintext, encoding: .utf8) else {
                throw VaultCryptoError.invalidPlaintext
            }
            return result
        } catch let error as VaultCryptoError {
            throw error
        } catch {
            throw VaultCryptoError.cryptoFailure("decryption failed: \(error)")
        }
    }

    /// Encode a value as unsigned LEB128.
    static func encodeLEB128(_ value: UInt32) -> Data {
        if value == 0 { return Data([0]) }
        var remaining = value
        var buffer = Data()
        while remaining > 0 {
            var byte = UInt8(remaining & 0x7f)
            remaining >>= 7
            if remaining > 0 { byte |= 0x80 }
            buffer.append(byte)
        }
        return buffer
    }

    /// Decode an unsigned LEB128 value from the start of `data`.
    /// Returns the decoded value and the number of bytes consumed.
    static func decodeLEB128(_ data: Data) throws -> (value: UInt32, bytesRead: Int) {
        var result: UInt32 = 0
        var shift: UInt32 = 0
        for (index, byte) in data.enumerated() {
            result |= UInt32(byte & 0x7f) << shift
            if byte & 0x80 == 0 {
                return (result, index + 1)
            }
            shift += 7
            if shift >= 35 {
                throw VaultCryptoError.invalidLEB128
            }
        }
        throw VaultCryptoError.invalidLEB128
    }
}
