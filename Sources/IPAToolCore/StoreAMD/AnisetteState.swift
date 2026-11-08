import CryptoKit
import Foundation
import Security

/// Store 鉴权链路上的本地软件身份。
///
/// 对应 Go 侧 `internal/storeauth/anisette.go` 的 `anisetteState`：持久化 JSON
/// 使用 `Identifier` / `Provisioning` / `RoutingInfo` 三个字段，以便与
/// ipatool-go 共用同一份状态。
struct AnisetteState: Codable, Equatable {
    static let anisetteLimit = 1 << 20

    /// 机器预置使用的 DSID，与 Go 侧 `^uint64(1)` 一致。
    static let machineDSID = UInt64.max &- 1

    /// Store 预置使用的 DSID，与 Go 侧 `^uint64(0)` 一致。
    static let storeDSID = UInt64.max

    static let clientInfo = "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
    static let userAgent = "akd/1.0 CFNetwork/811.5.4 Darwin/16.7.0"

    var identifier: Data
    var provisioning: Data?
    var routingInfo: UInt64

    enum CodingKeys: String, CodingKey {
        case identifier = "Identifier"
        case provisioning = "Provisioning"
        case routingInfo = "RoutingInfo"
    }

    init(identifier: Data, provisioning: Data? = nil, routingInfo: UInt64 = 0) {
        self.identifier = identifier
        self.provisioning = provisioning
        self.routingInfo = routingInfo
    }

    /// 解码持久化状态；空数据会生成一个新的 16 字节身份。
    static func decode(_ encoded: Data?) throws -> AnisetteState {
        guard let encoded, !encoded.isEmpty else {
            return AnisetteState(identifier: randomIdentifier())
        }

        guard let state = try? JSONDecoder().decode(AnisetteState.self, from: encoded),
              state.identifier.count == 16,
              (state.provisioning?.count ?? 0) <= anisetteLimit else {
            throw StoreAuthError.failure("invalid persisted anisette state")
        }

        return state
    }

    func encoded() throws -> Data {
        do {
            return try JSONEncoder().encode(self)
        } catch {
            throw StoreAuthError.failure("encode anisette state")
        }
    }

    /// 生成 `X-Apple-I-MD-LU` 与 `X-Mme-Device-Id`。
    func identityHeaders() -> (localUserID: String, deviceID: String) {
        let digest = SHA256.hash(data: identifier).map { String(format: "%02x", $0) }.joined()
        let hex = Array(identifier.map { String(format: "%02x", $0) }.joined())

        let deviceID = String(hex[0 ..< 8]) + "-"
            + String(hex[8 ..< 12]) + "-"
            + String(hex[12 ..< 16]) + "-"
            + String(hex[16 ..< 20]) + "-"
            + String(hex[20 ..< 32])

        return (digest, deviceID)
    }

    /// 生成一次机器校验证明所需的 AuthKit 头。
    func headers(otp: Data, mid: Data, now: Date = Date()) -> [String: String] {
        let identity = identityHeaders()

        return [
            "X-Apple-I-Client-Time": Self.clientTime(now),
            "X-Apple-I-MD": otp.base64EncodedString(),
            "X-Apple-I-MD-M": mid.base64EncodedString(),
            "X-Apple-I-MD-RINFO": String(routingInfo),
            "X-Apple-I-MD-LU": identity.localUserID,
            "X-Apple-I-SRL-NO": "0",
            "X-Apple-I-TimeZone": "Local",
            "X-Apple-Locale": "en_US",
            "X-Mme-Device-Id": identity.deviceID,
            "X-MMe-Client-Info": Self.clientInfo,
        ]
    }

    /// 校验可以放进 HTTP 头的 ASCII 值，与 Go 侧 `headerValue` 对齐。
    static func isValidHeaderValue(_ value: String, limit: Int) -> Bool {
        guard !value.isEmpty, value.utf8.count <= limit else {
            return false
        }

        return value.unicodeScalars.allSatisfy { $0.value >= 0x20 && $0.value <= 0x7e }
    }

    private static func clientTime(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        return formatter.string(from: date)
    }

    private static func randomIdentifier() -> Data {
        var identifier = [UInt8]()
        identifier.reserveCapacity(16)
        var generator = SystemRandomNumberGenerator()
        for _ in 0 ..< 16 {
            identifier.append(UInt8.random(in: 0 ... 255, using: &generator))
        }

        return Data(identifier)
    }
}

public enum StoreAuthError: Error, LocalizedError, CustomStringConvertible {
    case failure(String)

    public var errorDescription: String? {
        description
    }

    public var description: String {
        switch self {
        case let .failure(message):
            return message
        }
    }
}

/// 与 ipatool-go 相同，把 Anisette 状态放在系统钥匙串里，按服务名隔离。
final class AnisetteStateStore {
    private let service: String
    private let account = "anisette-v4"

    init(service: String = "IPAToolKit") {
        self.service = service
    }

    func load() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else {
            return nil
        }

        return item as? Data
    }

    func save(_ data: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]

        let status = SecItemUpdate(
            query as CFDictionary,
            [kSecValueData as String: data] as CFDictionary
        )

        if status == errSecItemNotFound {
            var attributes = query
            attributes[kSecValueData as String] = data
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
            let added = SecItemAdd(attributes as CFDictionary, nil)
            guard added == errSecSuccess else {
                throw StoreAuthError.failure("save anisette state (\(added))")
            }
            return
        }

        guard status == errSecSuccess else {
            throw StoreAuthError.failure("update anisette state (\(status))")
        }
    }
}
