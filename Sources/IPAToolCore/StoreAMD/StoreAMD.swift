import Foundation

/// AppleMediaServices 的 type-2 anisette 流程。
///
/// 对应 Go 侧 `internal/storeauth/store_amd.go`：预置过的状态先打开 ModernADI，
/// 再在 Store emulator 里执行 `+[AMSAnisette _headersForRequest:account:type:]`，
/// 其中的 `com.apple.adid` XPC 往返交给 ModernADI 处理。
enum StoreAMD {
    static func headers(state encoded: Data?, endpoint: String,
                        hardwareID: Data) throws -> (headers: [String: String], state: Data) {
        var state = try AnisetteState.decode(encoded)

        guard let provisioning = state.provisioning, !provisioning.isEmpty else {
            throw StoreAuthError.failure("store AMD state is not provisioned")
        }

        guard hardwareID.count == 6 else {
            throw StoreAuthError.failure("invalid Store AMD hardware identity")
        }

        let assets = try StoreAssets()
        let adi = try StoreADI(assets: assets, identifier: state.identifier, provisioning: provisioning)
        defer {
            adi.close()
        }

        let prepared = try StoreProfileAssets.load()
        let runtime = try StoreRuntime.open(imageData: assets.appleMediaServices, prepared: prepared)
        defer {
            try? runtime.close()
        }

        let headers = try runtime.storeAMDHeaders(
            endpoint: endpoint,
            hardwareID: [UInt8](hardwareID)
        ) { service, request in
            guard service == "com.apple.adid" else {
                throw StoreAuthError.failure("unsupported Store AMD XPC service \(service)")
            }

            return [UInt8](try adi.exchangeXPC(Data(request)))
        }

        state.provisioning = try adi.state()

        return (headers, try state.encoded())
    }
}
