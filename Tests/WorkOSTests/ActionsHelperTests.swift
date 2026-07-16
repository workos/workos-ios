// @oagen-ignore-file — hand-maintained; oagen must never overwrite this file.

import Foundation
import Testing

@testable import WorkOS

/// Tests for the hand-maintained AuthKit Actions helper (H03).
@Suite struct ActionsHelperTests {
    static let secret = "actions_test_secret"

    @Test func signResponseProducesVerifiableSignature() throws {
        let helper = ActionsHelper()
        let signed = try helper.signResponse(
            actionType: .authentication, verdict: .allow, secret: Self.secret)

        // The signature verifies against the base64 payload.
        try helper.verifyHeader(
            payload: signed.payload, signatureHeader: signed.sig, secret: Self.secret)

        // The payload decodes to the expected response body.
        let decoded =
            try JSONSerialization.jsonObject(
                with: Data(base64Encoded: signed.payload)!) as? [String: Any]
        #expect(decoded?["type"] as? String == "authentication")
        #expect(decoded?["verdict"] as? String == "Allow")
        #expect(decoded?["error_message"] as? String == "")
    }

    @Test func signResponseCarriesDenyVerdictAndErrorMessage() throws {
        let helper = ActionsHelper()
        let signed = try helper.signResponse(
            actionType: .userRegistration, verdict: .deny,
            errorMessage: "Registration blocked", secret: Self.secret)

        let decoded =
            try JSONSerialization.jsonObject(
                with: Data(base64Encoded: signed.payload)!) as? [String: Any]
        #expect(decoded?["type"] as? String == "user_registration")
        #expect(decoded?["verdict"] as? String == "Deny")
        #expect(decoded?["error_message"] as? String == "Registration blocked")
    }

    @Test func constructActionVerifiesAndDeserializes() throws {
        let payload = #"""
            {"object":"event","id":"event_01ACTION","event":"authentication.action_required","data":{"user":{"id":"user_123"}},"created_at":"2026-01-15T12:00:00.000Z"}
            """#
        let timestamp = String(Int64(Date().timeIntervalSince1970 * 1000))
        let signature = WebhookSignature.compute(
            secret: Self.secret, timestamp: timestamp, body: payload)

        let helper = ActionsHelper()
        let action = try helper.constructAction(
            payload: payload,
            signatureHeader: "t=\(timestamp), v1=\(signature)",
            secret: Self.secret
        )
        #expect(action.id == "event_01ACTION")
        #expect(action.event == "authentication.action_required")
    }

    @Test func verifyHeaderRejectsExpiredTimestamp() {
        let payload = "{}"
        let old = Date().addingTimeInterval(-60)
        let timestamp = String(Int64(old.timeIntervalSince1970 * 1000))
        let signature = WebhookSignature.compute(
            secret: Self.secret, timestamp: timestamp, body: payload)

        let helper = ActionsHelper()
        #expect(throws: WebhookVerificationError.outsideTolerance) {
            try helper.verifyHeader(
                payload: payload,
                signatureHeader: "t=\(timestamp), v1=\(signature)",
                secret: Self.secret
            )
        }
    }

    @Test func verifyHeaderRejectsBadSignature() {
        let timestamp = String(Int64(Date().timeIntervalSince1970 * 1000))
        let helper = ActionsHelper()
        #expect(throws: WebhookVerificationError.noValidSignature) {
            try helper.verifyHeader(
                payload: "{}",
                signatureHeader: "t=\(timestamp), v1=nope",
                secret: Self.secret
            )
        }
    }
}
