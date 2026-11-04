// @oagen-ignore-file

import Foundation
import Testing

@testable import WorkOS

@Suite struct OptionalOccurredAtTests {
    @Test func createEventOmitsDefaultedTimestamp() async throws {
        let (client, recorder) = makeTestClient(responding: #"{"success":true}"#)
        let event = AuditLogEvent(
            action: "user.signed_in",
            actor: AuditLogEventActor(id: "user_test", type: "user"),
            targets: [AuditLogEventTarget(id: "team_test", type: "team")],
            context: AuditLogEventContext(location: "192.0.2.1"))

        _ = try await client.auditLogs.createEvent(organizationId: "org_test", event: event)

        let body = try #require(recorder.lastBody)
        let json = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
        let encodedEvent = try #require(json["event"] as? [String: Any])
        #expect(json["organization_id"] as? String == "org_test")
        #expect(!encodedEvent.keys.contains("occurred_at"))
    }

    @Test func createEventOmitsExplicitNilTimestamp() async throws {
        let (client, recorder) = makeTestClient(responding: #"{"success":true}"#)
        let event = AuditLogEvent(
            action: "user.signed_in", occurredAt: nil,
            actor: AuditLogEventActor(id: "user_test", type: "user"),
            targets: [AuditLogEventTarget(id: "team_test", type: "team")],
            context: AuditLogEventContext(location: "192.0.2.1"))

        _ = try await client.auditLogs.createEvent(organizationId: "org_test", event: event)

        let body = try #require(recorder.lastBody)
        let json = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
        let encodedEvent = try #require(json["event"] as? [String: Any])
        #expect(!encodedEvent.keys.contains("occurred_at"))
    }

    @Test func createEventPreservesTimestampInExistingInitializerOrder() async throws {
        let expected = "2026-11-03T12:34:56.789Z"
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let timestamp = try #require(formatter.date(from: expected))
        let (client, recorder) = makeTestClient(responding: #"{"success":true}"#)
        let event = AuditLogEvent(
            action: "user.signed_in", occurredAt: timestamp,
            actor: AuditLogEventActor(id: "user_test", type: "user"),
            targets: [AuditLogEventTarget(id: "team_test", type: "team")],
            context: AuditLogEventContext(location: "192.0.2.1"))

        _ = try await client.auditLogs.createEvent(organizationId: "org_test", event: event)

        let body = try #require(recorder.lastBody)
        let json = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
        let encodedEvent = try #require(json["event"] as? [String: Any])
        #expect(encodedEvent["occurred_at"] as? String == expected)
    }
}
