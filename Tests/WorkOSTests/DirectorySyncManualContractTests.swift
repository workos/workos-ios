// @oagen-ignore-file

import Foundation
import Testing

@testable import WorkOS

@Suite struct DirectorySyncManualContractTests {
    @Test func accepts202WithoutARequestBody() async throws {
        let (client, recorder) = makeTestClient(
            statusCode: 202, responding: #"{"status":"queued"}"#)

        let result = try await client.directorySync.sync(id: "directory_123")

        #expect(result.status == "queued")
        let request = try #require(recorder.lastRequest)
        #expect(request.httpMethod == "POST")
        #expect(request.url?.path == "/directories/directory_123/sync")
        #expect(recorder.lastBody == nil || recorder.lastBody?.isEmpty == true)
    }

    @Test func runningSyncIsAConflictNotAQueuedResponse() async throws {
        let (client, _) = makeTestClient(
            statusCode: 409,
            responding: #"{"code":"directory_sync_in_progress","message":"A sync is running."}"#
        )

        do {
            _ = try await client.directorySync.sync(id: "directory_123")
            Issue.record("Expected a conflict instead of a queued response")
        } catch WorkOSError.conflict(let error) {
            #expect(error.statusCode == 409)
            #expect(error.code == "directory_sync_in_progress")
        }
    }
}
