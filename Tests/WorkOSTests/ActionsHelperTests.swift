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
            {"object":"authentication_action_context","id":"action_01","user":{"object":"user","id":"user_01","email":"test@example.com","email_verified":true,"created_at":"2024-01-01T00:00:00.000Z","updated_at":"2024-01-01T00:00:00.000Z"},"ip_address":"1.2.3.4","user_agent":"curl/8","device_fingerprint":"fp_123","issuer":"https://auth.example.com"}
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
        #expect(action.object == "authentication_action_context")
        #expect(action.id == "action_01")
        #expect(action.user?.id == "user_01")
        #expect(action.user?.email == "test@example.com")
        #expect(action.ipAddress == "1.2.3.4")
        #expect(action.issuer == "https://auth.example.com")
    }

    @Test func constructActionDeserializesUserRegistration() throws {
        let payload = #"""
            {"object":"user_registration_action_context","id":"action_02","user_data":{"object":"user_data","email":"new@example.com","first_name":"New","last_name":"User","name":null},"ip_address":"5.6.7.8","device_fingerprint":"fp_456"}
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
        #expect(action.object == "user_registration_action_context")
        #expect(action.userData?.email == "new@example.com")
        #expect(action.userData?.firstName == "New")
        #expect(action.user == nil)
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
