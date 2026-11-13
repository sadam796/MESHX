import Foundation
import XCTest
@testable import MESHXKit

final class KeychainMLSStateStoreTests: XCTestCase {
    func testSaveLoadAndDeleteOpaqueMLSState() throws {
        let service = "org.meshx.tests.\(UUID().uuidString)"
        let store = KeychainMLSStateStore(service: service)
        let groupID = "test-group-\(UUID().uuidString)"
        let expected = Data([0x4d, 0x45, 0x53, 0x48, 0x58, 0x00, 0xff])
        defer { try? store.delete(for: groupID) }

        XCTAssertNil(try store.load(for: groupID))
        try store.save(expected, for: groupID)
        XCTAssertEqual(try store.load(for: groupID), expected)
        try store.delete(for: groupID)
        XCTAssertNil(try store.load(for: groupID))
    }

    func testSavingAgainReplacesExistingState() throws {
        let service = "org.meshx.tests.\(UUID().uuidString)"
        let store = KeychainMLSStateStore(service: service)
        let groupID = "replace-\(UUID().uuidString)"
        defer { try? store.delete(for: groupID) }

        try store.save(Data([1, 2, 3]), for: groupID)
        try store.save(Data([4, 5, 6]), for: groupID)
        XCTAssertEqual(try store.load(for: groupID), Data([4, 5, 6]))
    }
}
