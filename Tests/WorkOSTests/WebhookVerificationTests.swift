// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation
import Testing

@testable import WorkOS

/// Tests for the hand-maintained webhook verification helpers (H01/H02).
@Suite struct WebhookVerificationTests {
    static let secret = "whsec_test_secret"

    static func makeHeader(body: String, at date: Date = Date()) -> String {
        let timestamp = String(Int64(date.timeIntervalSince1970 * 1000))
        let signature = WebhookSignature.compute(
            secret: secret, timestamp: timestamp, body: body)
        return "t=\(timestamp), v1=\(signature)"
    }

    @Test func computeSignatureMatchesKnownVector() {
        // Externally computed: HMAC-SHA256("whsec_test_secret",
        // "1700000000000.{\"event\":\"user.created\"}").
        let signature = WebhookSignature.compute(
            secret: "whsec_test_secret",
            timestamp: "1700000000000",
            body: #"{"event":"user.created"}"#
        )
        #expect(signature == "aac9c4bb7a043a65cb8e1737624288845e680a530558c87a1623d35fbb7c7655")
    }

    @Test func parseHeaderExtractsTimestampAndSignature() throws {
        let (timestamp, signature) = try WebhookSignature.parseHeader("t=1700000000000, v1=abc123")
        #expect(timestamp == "1700000000000")
        #expect(signature == "abc123")
    }

    @Test func parseHeaderRejectsMalformedHeader() {
        #expect(throws: WebhookVerificationError.invalidHeader) {
            try WebhookSignature.parseHeader("t=1700000000000")
        }
        #expect(throws: WebhookVerificationError.invalidHeader) {
            try WebhookSignature.parseHeader("nonsense")
        }
    }

    @Test func verifyPayloadAcceptsValidSignature() throws {
        let body = #"{"event":"user.created","data":{"id":"user_123"}}"#
        let verifier = WebhookVerifier(secret: Self.secret)
        let verified = try verifier.verifyPayload(
            signatureHeader: Self.makeHeader(body: body), body: body)
        #expect(verified == body)
    }

    @Test func verifyPayloadRejectsBadSignature() {
        let body = #"{"event":"user.created"}"#
        let timestamp = String(Int64(Date().timeIntervalSince1970 * 1000))
        let verifier = WebhookVerifier(secret: Self.secret)
        #expect(throws: WebhookVerificationError.noValidSignature) {
            try verifier.verifyPayload(
                signatureHeader: "t=\(timestamp), v1=badsignature", body: body)
        }
    }

    @Test func verifyPayloadRejectsExpiredTimestamp() {
        let body = #"{"event":"user.created"}"#
        let header = Self.makeHeader(body: body, at: Date().addingTimeInterval(-600))
        let verifier = WebhookVerifier(secret: Self.secret)
        #expect(throws: WebhookVerificationError.outsideTolerance) {
            try verifier.verifyPayload(signatureHeader: header, body: body)
        }
    }

    @Test func verifyPayloadRejectsMissingHeader() {
        let verifier = WebhookVerifier(secret: Self.secret)
        #expect(throws: WebhookVerificationError.notSigned) {
            try verifier.verifyPayload(signatureHeader: "", body: "{}")
        }
    }

    @Test func verifyPayloadHonorsCustomTolerance() throws {
        let body = #"{"event":"user.created"}"#
        let header = Self.makeHeader(body: body, at: Date().addingTimeInterval(-600))
        let verifier = WebhookVerifier(secret: Self.secret, tolerance: 3600)
        let verified = try verifier.verifyPayload(signatureHeader: header, body: body)
        #expect(verified == body)
    }

    @Test func constructEventReturnsDeserializedEnvelope() throws {
        let body = #"""
            {"object":"event","id":"event_01ABC","event":"user.created","data":{"id":"user_123"},"created_at":"2026-01-15T12:00:00.000Z"}
            """#
        let verifier = WebhookVerifier(secret: Self.secret)
        let event = try verifier.constructEvent(
            signatureHeader: Self.makeHeader(body: body), body: body)
        #expect(event.id == "event_01ABC")
        #expect(event.event == "user.created")
        #expect(event.data["id"] == .string("user_123"))
    }
}
