// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation
import Testing

@testable import WorkOS

/// Tests for the hand-maintained client-side Vault crypto helpers (H18).
@Suite struct VaultCryptoTests {
    // 32 zero-to-31 bytes, a valid AES-256 key.
    static let dataKeyBase64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
    static let encryptedKeysBase64 = "dGVzdC1lbmNyeXB0ZWQta2V5cw=="

    static var keyPair: CreateDataKeyResponse {
        CreateDataKeyResponse(
            context: ["tenant": "acme"],
            dataKey: dataKeyBase64,
            encryptedKeys: encryptedKeysBase64,
            id: "key_123"
        )
    }

    @Test func localEncryptDecryptRoundTrip() throws {
        let encrypted = try VaultLocalCrypto.encrypt(
            "hello vault", keyPair: Self.keyPair, associatedData: "aad-1")
        let decrypted = try VaultLocalCrypto.decrypt(
            encrypted,
            dataKey: DecryptResponse(dataKey: Self.dataKeyBase64, id: "key_123"),
            associatedData: "aad-1"
        )
        #expect(decrypted == "hello vault")
    }

    @Test func localRoundTripWithoutAssociatedData() throws {
        let encrypted = try VaultLocalCrypto.encrypt("no aad", keyPair: Self.keyPair)
        let decrypted = try VaultLocalCrypto.decrypt(
            encrypted, dataKey: DecryptResponse(dataKey: Self.dataKeyBase64, id: "key_123"))
        #expect(decrypted == "no aad")
    }

    @Test func decryptWithWrongAssociatedDataThrows() throws {
        let encrypted = try VaultLocalCrypto.encrypt(
            "hello", keyPair: Self.keyPair, associatedData: "right")
        #expect(throws: VaultCryptoError.self) {
            try VaultLocalCrypto.decrypt(
                encrypted,
                dataKey: DecryptResponse(dataKey: Self.dataKeyBase64, id: "key_123"),
                associatedData: "wrong"
            )
        }
    }

    @Test func decryptTamperedPayloadThrows() throws {
        let encrypted = try VaultLocalCrypto.encrypt("hello", keyPair: Self.keyPair)
        var raw = Data(base64Encoded: encrypted)!
        raw[raw.count - 1] ^= 0xff
        #expect(throws: VaultCryptoError.self) {
            try VaultLocalCrypto.decrypt(
                raw.base64EncodedString(),
                dataKey: DecryptResponse(dataKey: Self.dataKeyBase64, id: "key_123")
            )
        }
    }

    @Test func leb128RoundTrips() throws {
        for value: UInt32 in [0, 1, 127, 128, 300, 16384, 100_000, 4_294_967_295] {
            let encoded = VaultLocalCrypto.encodeLEB128(value)
            let (decoded, bytesRead) = try VaultLocalCrypto.decodeLEB128(encoded)
            #expect(decoded == value)
            #expect(bytesRead == encoded.count)
        }
    }

    @Test func wireFormatEmbedsEncryptedKeys() throws {
        let encrypted = try VaultLocalCrypto.encrypt("payload", keyPair: Self.keyPair)
        let raw = Data(base64Encoded: encrypted)!
        let (keysLength, bytesRead) = try VaultLocalCrypto.decodeLEB128(raw)
        let embedded = raw.subdata(in: bytesRead..<(bytesRead + Int(keysLength)))
        #expect(embedded.base64EncodedString() == Self.encryptedKeysBase64)
    }

    @Test func encryptCallsDataKeyEndpoint() async throws {
        let (client, recorder) = makeTestClient(
            responding:
                #"{"context":{"tenant":"acme"},"data_key":"\#(Self.dataKeyBase64)","encrypted_keys":"\#(Self.encryptedKeysBase64)","id":"key_123"}"#
        )
        let result = try await client.vault.encrypt(
            data: "secret-value", context: ["tenant": "acme"])

        let request = try #require(recorder.lastRequest)
        #expect(request.httpMethod == "POST")
        #expect(request.url?.path == "/vault/v1/keys/data-key")
        #expect(result.keyContext == ["tenant": "acme"])
        #expect(result.encryptedKeys == Self.encryptedKeysBase64)

        // The ciphertext decrypts locally with the same data key.
        let plaintext = try VaultLocalCrypto.decrypt(
            result.encryptedData,
            dataKey: DecryptResponse(dataKey: Self.dataKeyBase64, id: "key_123")
        )
        #expect(plaintext == "secret-value")
    }

    @Test func decryptCallsDecryptEndpoint() async throws {
        let encrypted = try VaultLocalCrypto.encrypt("round-trip", keyPair: Self.keyPair)

        let (client, recorder) = makeTestClient(
            responding: #"{"data_key":"\#(Self.dataKeyBase64)","id":"key_123"}"#
        )
        let plaintext = try await client.vault.decrypt(encryptedData: encrypted)

        let request = try #require(recorder.lastRequest)
        #expect(request.httpMethod == "POST")
        #expect(request.url?.path == "/vault/v1/keys/decrypt")
        let body = try #require(recorder.lastBody)
        let json = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        #expect(json?["keys"] as? String == Self.encryptedKeysBase64)
        #expect(plaintext == "round-trip")
    }
}
