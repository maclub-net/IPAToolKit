import Foundation
import CSAP

/// App Store 鉴权端点的白名单与 Store 设备证明。
///
/// Apple 对较新的 macOS 客户端会在 bag 里下发专用鉴权主机
/// `auth.itunes.apple.com`，该主机只接受原始路径，并且只在 `darwin`
/// 上可以通过 AppleMediaServices 取到 Store 设备证明。
enum StoreAuthenticationEndpoint {
    static let nativeHost = "auth.itunes.apple.com"

    static let nativePaths: Set<String> = [
        "/auth/v1/native",
        "/auth/v1/native/",
        "/auth/v1/native/fast",
        "/auth/v1/native/fast/",
    ]

    /// 是否为 bag 下发的原生鉴权端点。
    static func isNative(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == "https",
              url.host?.lowercased() == nativeHost,
              url.user == nil,
              url.fragment == nil,
              url.port == nil || url.port == 443,
              url.absoluteString.range(of: "%") == nil,
              nativePaths.contains(url.path) else {
            return false
        }

        return true
    }

    /// 是否能接受签过名的鉴权请求体。
    static func isAllowed(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == "https",
              url.user == nil,
              url.fragment == nil,
              url.port == nil || url.port == 443,
              let host = url.host?.lowercased() else {
            return false
        }

        if host == nativeHost {
            return isNative(url)
        }

        if host == legacyHost {
            return true
        }

        guard let suffix = host.range(of: "-" + legacyHost, options: .backwards),
              suffix.upperBound == host.endIndex else {
            return false
        }

        let pod = String(host[host.startIndex..<suffix.lowerBound])
        return pod.count >= 2 && pod.first == "p" && pod.dropFirst().allSatisfy(\.isNumber)
    }

    static let legacyHost = "buy.itunes.apple.com"

    /// 取 Store 设备证明。证明不可用时返回空字典，不影响登录重试。
    static func storeAMDHeaders(for endpoint: URL) -> [String: String] {
        #if os(macOS)
        var amd: UnsafeMutablePointer<CChar>?
        var proof: UnsafeMutablePointer<CChar>?
        defer {
            csap_store_amd_headers_free(amd)
            csap_store_amd_headers_free(proof)
        }

        guard csap_store_amd_headers(endpoint.absoluteString, &amd, &proof) == 0,
              let amd, let proof else {
            return [:]
        }

        return [
            "X-Apple-AMD": String(cString: amd),
            "X-Apple-AMD-M": String(cString: proof),
        ]
        #else
        // AppleMediaServices 只在 macOS 上可用。
        return [:]
        #endif
    }
}
