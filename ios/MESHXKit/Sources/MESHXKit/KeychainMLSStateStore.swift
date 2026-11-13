import Foundation
import Security

/// Stores opaque serialized MLS provider state as a device-only Keychain item.
/// The Rust/OpenMLS adapter must serialize its provider state and pass those
/// bytes here; this type does not implement MLS or encrypt data independently.
public struct KeychainMLSStateStore: Sendable {
    private let service: String
    private let accountPrefix: String

    public init(service: String = "org.meshx.app.mls", accountPrefix: String = "group-state") {
        self.service = service
        self.accountPrefix = accountPrefix
    }

    public func save(_ data: Data, for groupID: String) throws {
        let key = accountPrefix + "." + Self.safeIdentifier(groupID)
        let base = query(account: key)
        let update: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let status = SecItemUpdate(base as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var insert = base
            update.forEach { insert[$0.key] = $0.value }
            let addStatus = SecItemAdd(insert as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw KeychainStoreError.status(addStatus) }
        } else if status != errSecSuccess {
            throw KeychainStoreError.status(status)
        }
    }

    public func load(for groupID: String) throws -> Data? {
        var request = query(account: accountPrefix + "." + Self.safeIdentifier(groupID))
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeychainStoreError.status(status) }
        guard let data = result as? Data else { throw KeychainStoreError.invalidResult }
        return data
    }

    public func delete(for groupID: String) throws {
        let status = SecItemDelete(query(account: accountPrefix + "." + Self.safeIdentifier(groupID)) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainStoreError.status(status)
        }
    }

    private func query(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }

    private static func safeIdentifier(_ value: String) -> String {
        // Hashing avoids placing user-controlled group identifiers in Keychain account names.
        let bytes = Data(value.utf8)
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
}

public enum KeychainStoreError: Error, Equatable {
    case status(OSStatus)
    case invalidResult
}
