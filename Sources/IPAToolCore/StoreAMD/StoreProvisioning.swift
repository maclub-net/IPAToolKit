import CSAP
import Foundation

/// 资产缓存与 Modern ADI 的 Swift 封装。
/// 对应 Go 侧 `internal/sap/assets`、`internal/sap/machine/modern_adi.go`
/// 与 `internal/storeauth/{anisette,store_provisioning}.go`。

// MARK: - 资产缓存

final class StoreAssets {
    static let cacheDirectoryName = "ipatool/sap/apple-assets-macos-27-26A434-arm64-v4"

    let pointer: UnsafeMutablePointer<csap_store_assets_t>

    init(directory: String? = nil) throws {
        let path: String
        if let directory {
            path = directory
        } else {
            path = try StoreAssets.cacheDirectory()
        }

        let pointer = UnsafeMutablePointer<csap_store_assets_t>.allocate(capacity: 1)
        pointer.initialize(to: csap_store_assets_t())

        var errorBuffer = [CChar](repeating: 0, count: 512)
        let capacity = errorBuffer.count
        let status = errorBuffer.withUnsafeMutableBufferPointer { error in
            path.withCString { directoryPointer in
                csap_store_assets_load(directoryPointer, pointer, error.baseAddress, capacity)
            }
        }

        guard status == 0 else {
            let message = StoreADI.errorMessage(errorBuffer, fallback: "load cached Apple assets")
            pointer.deinitialize(count: 1)
            pointer.deallocate()
            throw StoreAuthError.failure(message)
        }

        self.pointer = pointer
    }

    deinit {
        csap_store_assets_free(pointer)
        pointer.deinitialize(count: 1)
        pointer.deallocate()
    }

    /// 内置 AppleMediaServices 镜像，供 Store emulator 使用。
    var appleMediaServices: [UInt8] {
        guard let base = pointer.pointee.apple_media_services,
              pointer.pointee.apple_media_services_size > 0 else {
            return []
        }

        return Array(UnsafeBufferPointer(start: base, count: Int(pointer.pointee.apple_media_services_size)))
    }

    static func cacheDirectory() throws -> String {
        guard let root = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first else {
            throw StoreAuthError.failure("find user cache directory")
        }

        return root.appendingPathComponent(cacheDirectoryName, isDirectory: true).path
    }

    /// 优先装载已有缓存；缺失时从固定 IPSW 补齐后再装载。
    static func prepare(session: URLSession = .shared) async throws -> StoreAssets {
        let directory = try cacheDirectory()
        if let cached = try? StoreAssets(directory: directory) {
            return cached
        }

        try await Task.detached(priority: .utility) {
            try IPSWAssetInstaller.installIfNeeded(directory: directory, session: session)
        }.value

        return try StoreAssets(directory: directory)
    }
}

// MARK: - Modern ADI

final class StoreADI {
    private let handle: OpaquePointer
    private var closed = false

    init(assets: StoreAssets, identifier: Data, provisioning: Data? = nil) throws {
        guard identifier.count == 16 else {
            throw StoreAuthError.failure("anisette identifier must be 16 bytes")
        }

        // ModernADI 使用 CSAP 的 Unicorn 引擎，必须先完成动态库加载。
        try UCEngine.load()

        let identifierBytes = [UInt8](identifier)
        let stateBytes = [UInt8](provisioning ?? Data())
        var errorBuffer = [CChar](repeating: 0, count: 512)
        let capacity = errorBuffer.count

        let opened = identifierBytes.withUnsafeBufferPointer { identity in
            stateBytes.withUnsafeBufferPointer { state in
                errorBuffer.withUnsafeMutableBufferPointer { error in
                    csap_adi_open(
                        assets.pointer,
                        identity.baseAddress,
                        state.isEmpty ? nil : state.baseAddress,
                        UInt64(state.count),
                        error.baseAddress,
                        capacity
                    )
                }
            }
        }

        guard let opened else {
            throw StoreAuthError.failure(Self.errorMessage(errorBuffer, fallback: "open modern ADI runtime"))
        }

        handle = opened
    }

    deinit {
        close()
    }

    func close() {
        guard !closed else {
            return
        }

        closed = true
        csap_adi_close(handle)
    }

    func startProvisioning(dsid: UInt64, spim: Data) throws -> (cpim: Data, session: UInt32) {
        try requireOpen()

        var output: UnsafeMutablePointer<UInt8>?
        var outputSize: UInt64 = 0
        var session: UInt32 = 0
        var errorBuffer = [CChar](repeating: 0, count: 512)
        let capacity = errorBuffer.count
        let input = [UInt8](spim)

        let status = input.withUnsafeBufferPointer { bytes in
            csap_adi_start_provisioning(
                handle,
                dsid,
                bytes.baseAddress,
                UInt64(bytes.count),
                &output,
                &outputSize,
                &session,
                &errorBuffer,
                capacity
            )
        }

        let cpim = take(output, outputSize)
        guard status == 0 else {
            throw StoreAuthError.failure(Self.errorMessage(errorBuffer, fallback: "start modern ADI provisioning"))
        }

        return (cpim, session)
    }

    func endProvisioning(session: UInt32, settingInfo: Data, transportKey: Data) throws {
        try requireOpen()

        let settingBytes = [UInt8](settingInfo)
        let transportBytes = [UInt8](transportKey)
        var errorBuffer = [CChar](repeating: 0, count: 512)
        let capacity = errorBuffer.count

        let status = settingBytes.withUnsafeBufferPointer { setting in
            transportBytes.withUnsafeBufferPointer { transport in
                csap_adi_end_provisioning(
                    handle,
                    session,
                    setting.baseAddress,
                    UInt64(setting.count),
                    transport.baseAddress,
                    UInt64(transport.count),
                    &errorBuffer,
                    capacity
                )
            }
        }

        guard status == 0 else {
            throw StoreAuthError.failure(Self.errorMessage(errorBuffer, fallback: "finish modern ADI provisioning"))
        }
    }

    func requestOTP(dsid: UInt64) throws -> (mid: Data, otp: Data) {
        try requireOpen()

        var midPointer: UnsafeMutablePointer<UInt8>?
        var midSize: UInt64 = 0
        var otpPointer: UnsafeMutablePointer<UInt8>?
        var otpSize: UInt64 = 0
        var errorBuffer = [CChar](repeating: 0, count: 512)
        let capacity = errorBuffer.count

        let status = csap_adi_request_otp(
            handle,
            dsid,
            &midPointer,
            &midSize,
            &otpPointer,
            &otpSize,
            &errorBuffer,
            capacity
        )

        let mid = take(midPointer, midSize)
        let otp = take(otpPointer, otpSize)
        guard status == 0 else {
            throw StoreAuthError.failure(Self.errorMessage(errorBuffer, fallback: "generate anisette proof"))
        }

        return (mid, otp)
    }

    func importKeyBag(hardwareID: Data, keyBag: Data) throws {
        try requireOpen()

        let hardwareBytes = [UInt8](hardwareID)
        let keyBagBytes = [UInt8](keyBag)
        var errorBuffer = [CChar](repeating: 0, count: 512)
        let capacity = errorBuffer.count

        let status = hardwareBytes.withUnsafeBufferPointer { hardware in
            keyBagBytes.withUnsafeBufferPointer { bag in
                csap_adi_import_keybag(
                    handle,
                    hardware.baseAddress,
                    UInt64(hardware.count),
                    bag.baseAddress,
                    UInt64(bag.count),
                    &errorBuffer,
                    capacity
                )
            }
        }

        guard status == 0 else {
            throw StoreAuthError.failure(Self.errorMessage(errorBuffer, fallback: "import Apple Store FairPlay keybag"))
        }
    }

    func exchangeXPC(_ request: Data) throws -> Data {
        try requireOpen()

        var output: UnsafeMutablePointer<UInt8>?
        var outputSize: UInt64 = 0
        var errorBuffer = [CChar](repeating: 0, count: 512)
        let capacity = errorBuffer.count
        let input = [UInt8](request)

        let status = input.withUnsafeBufferPointer { bytes in
            csap_adi_exchange_xpc(
                handle,
                bytes.baseAddress,
                UInt64(bytes.count),
                &output,
                &outputSize,
                &errorBuffer,
                capacity
            )
        }

        let reply = take(output, outputSize)
        guard status == 0 else {
            throw StoreAuthError.failure(Self.errorMessage(errorBuffer, fallback: "run modern ADI XPC exchange"))
        }

        return reply
    }

    func state() throws -> Data {
        try requireOpen()

        var output: UnsafeMutablePointer<UInt8>?
        var outputSize: UInt64 = 0
        var errorBuffer = [CChar](repeating: 0, count: 512)
        let capacity = errorBuffer.count

        let status = csap_adi_state(handle, &output, &outputSize, &errorBuffer, capacity)
        let data = take(output, outputSize)
        guard status == 0 else {
            throw StoreAuthError.failure(Self.errorMessage(errorBuffer, fallback: "read modern ADI state"))
        }

        return data
    }

    private func requireOpen() throws {
        guard !closed else {
            throw StoreAuthError.failure("modern ADI runtime is closed")
        }
    }

    private func take(_ pointer: UnsafeMutablePointer<UInt8>?, _ size: UInt64) -> Data {
        defer {
            csap_adi_free(pointer)
        }

        guard let pointer, size > 0 else {
            return Data()
        }

        return Data(bytes: pointer, count: Int(size))
    }

    fileprivate static func errorMessage(_ buffer: [CChar], fallback: String) -> String {
        let message = String(cString: buffer)
        return message.isEmpty ? fallback : message
    }
}

// MARK: - plist 与 HTTP

enum StoreAuthWire {
    static func encodePlist(_ object: Any) throws -> Data {
        do {
            return try PropertyListSerialization.data(fromPropertyList: object, format: .xml, options: 0)
        } catch {
            throw StoreAuthError.failure("encode anisette provisioning request")
        }
    }

    static func decodePlist(_ data: Data) throws -> [String: Any] {
        guard let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dictionary = plist as? [String: Any] else {
            throw StoreAuthError.failure("decode anisette provisioning response")
        }

        return dictionary
    }

    static func post(_ request: URLRequest, session: URLSession) async throws -> (data: Data, response: HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw StoreAuthError.failure("anisette provisioning returned no HTTP response")
        }

        return (data, http)
    }

    static func validate(endpoint: String) throws -> URL {
        guard let url = URL(string: endpoint),
              url.scheme == "https",
              let host = url.host, !host.isEmpty else {
            throw StoreAuthError.failure("invalid provisioning endpoint")
        }

        return url
    }

    static func string(_ values: [String: Any], _ key: String) throws -> String {
        guard let value = values[key] as? String,
              AnisetteState.isValidHeaderValue(value, limit: 32768) else {
            throw StoreAuthError.failure("missing anisette \(key)")
        }

        return value
    }

    static func base64Field(_ values: [String: Any], _ key: String) throws -> Data {
        let encoded = try string(values, key)
        guard let decoded = Data(base64Encoded: encoded),
              !decoded.isEmpty,
              decoded.count <= AnisetteState.anisetteLimit else {
            throw StoreAuthError.failure("decode anisette \(key)")
        }

        return decoded
    }
}

// MARK: - 机器预置

enum AnisetteProvisioner {
    static let startURL = "https://gsa.apple.com/grandslam/MidService/startMachineProvisioning"
    static let finishURL = "https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning"

    /// 从持久化身份开始，完成一次机器预置并返回新的 AuthKit 头。
    static func headers(state encoded: Data?, session: URLSession = .shared)
        async throws -> (headers: [String: String], state: Data) {
        var state = try AnisetteState.decode(encoded)

        // Store 预置会替换 ADI 数据库；旧证明无法复用时重新走机器预置。
        state.provisioning = nil
        state.routingInfo = 0

        let assets = try await StoreAssets.prepare(session: session)
        let adi = try StoreADI(assets: assets, identifier: state.identifier)
        defer {
            adi.close()
        }

        try await provisionMachine(state: &state, adi: adi, session: session)

        let (mid, otp) = try adi.requestOTP(dsid: AnisetteState.machineDSID)
        state.provisioning = try adi.state()

        return (state.headers(otp: otp, mid: mid), try state.encoded())
    }

    private static func provisionMachine(state: inout AnisetteState, adi: StoreADI,
                                         session: URLSession) async throws {
        let start = try await sendMachineProvisioning(
            endpoint: startURL,
            identifier: state.identifier,
            values: [:],
            session: session
        )

        let spim = try StoreAuthWire.base64Field(start, "spim")
        let (cpim, provisioningSession) = try adi.startProvisioning(dsid: AnisetteState.machineDSID, spim: spim)

        let finish = try await sendMachineProvisioning(
            endpoint: finishURL,
            identifier: state.identifier,
            values: ["cpim": cpim.base64EncodedString()],
            session: session
        )

        let ptm = try StoreAuthWire.base64Field(finish, "ptm")
        let trustKey = try StoreAuthWire.base64Field(finish, "tk")
        let routing = try StoreAuthWire.string(finish, "X-Apple-I-MD-RINFO")
        guard let routingInfo = UInt64(routing), routingInfo != 0 else {
            throw StoreAuthError.failure("decode anisette routing information")
        }

        state.routingInfo = routingInfo
        try adi.endProvisioning(session: provisioningSession, settingInfo: ptm, transportKey: trustKey)
    }

    private static func sendMachineProvisioning(endpoint: String, identifier: Data,
                                                values: [String: Any],
                                                session: URLSession) async throws -> [String: Any] {
        let url = try StoreAuthWire.validate(endpoint: endpoint)
        let body = try StoreAuthWire.encodePlist([
            "Header": [String: Any](),
            "Request": values,
        ])

        let identity = AnisetteState(identifier: identifier).identityHeaders()

        var request = URLRequest(url: url, timeoutInterval: 30)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        request.setValue("close", forHTTPHeaderField: "Connection")
        request.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        request.setValue(AnisetteState.userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue(identity.localUserID, forHTTPHeaderField: "X-Apple-I-MD-LU")
        request.setValue(AnisetteState.clientInfo, forHTTPHeaderField: "X-MMe-Client-Info")
        request.setValue(identity.deviceID, forHTTPHeaderField: "X-Mme-Device-Id")

        let (data, response) = try await StoreAuthWire.post(request, session: session)
        guard response.statusCode == 200,
              data.count <= AnisetteState.anisetteLimit else {
            throw StoreAuthError.failure("anisette provisioning returned HTTP \(response.statusCode)")
        }

        let envelope = try StoreAuthWire.decodePlist(data)
        guard let values = envelope["Response"] as? [String: Any] else {
            throw StoreAuthError.failure("decode anisette provisioning response")
        }

        return values
    }
}

// MARK: - Store 预置

enum StoreProvisioning {
    static let endpoint = "https://auth.itunes.apple.com/auth/v1/otp/1.5/finish"
    static let userAgent = "Configurator/2.21 (Macintosh; OS X 27.0.1; 26A434) AppleWebKit/0625.2.5.11.6"

    /// 完成 Apple 在鉴权响应里下发的 Store 预置动作，返回更新后的状态。
    static func provision(state encoded: Data?, challenge: String,
                          endpoint: String = StoreProvisioning.endpoint,
                          userAgent: String = StoreProvisioning.userAgent,
                          kbsync: String?, hardwareID: Data,
                          identity: [String: String],
                          session: URLSession = .shared) async throws -> Data {
        var state = try AnisetteState.decode(encoded)

        guard let spim = Data(base64Encoded: challenge.trimmingCharacters(in: .whitespacesAndNewlines)),
              !spim.isEmpty,
              spim.count <= AnisetteState.anisetteLimit else {
            throw StoreAuthError.failure("decode Apple Store provisioning data")
        }

        let assets = try await StoreAssets.prepare(session: session)
        let adi = try StoreADI(assets: assets, identifier: state.identifier)
        defer {
            adi.close()
        }

        let (cpim, provisioningSession) = try adi.startProvisioning(dsid: AnisetteState.storeDSID, spim: spim)

        var payload: [String: Any] = ["clientData": cpim.base64EncodedString()]
        if let kbsync, !kbsync.isEmpty {
            payload["kbsync"] = kbsync
        }

        let finish = try await finishStoreProvisioning(
            payload: payload,
            endpoint: endpoint,
            userAgent: userAgent,
            identity: identity,
            session: session
        )

        let settingInfo = try decodeValue(finish.settingInfo, key: "settingInfo")
        let transportKey = try decodeValue(finish.transportKey, key: "transportKey")

        do {
            try adi.endProvisioning(
                session: provisioningSession,
                settingInfo: settingInfo,
                transportKey: transportKey
            )
        } catch {
            throw StoreAuthError.failure(
                "finish Apple Store provisioning (setting info \(settingInfo.count) bytes, "
                    + "transport key \(transportKey.count) bytes): \(error)"
            )
        }

        if !finish.keyBag.isEmpty {
            try adi.importKeyBag(hardwareID: hardwareID, keyBag: finish.keyBag)
        }

        state.provisioning = try adi.state()

        return try state.encoded()
    }

    private static func finishStoreProvisioning(payload: [String: Any], endpoint: String,
                                                userAgent: String, identity: [String: String],
                                                session: URLSession)
        async throws -> (settingInfo: String, transportKey: String, keyBag: Data) {
        let url = try StoreAuthWire.validate(endpoint: endpoint)
        let body = try StoreAuthWire.encodePlist(payload)

        var request = URLRequest(url: url, timeoutInterval: 30)
        request.httpMethod = "POST"
        request.httpBody = body

        for (key, value) in identity where !["X-APPLE-I-MD", "X-APPLE-I-MD-M", "X-APPLE-I-MD-RINFO"]
            .contains(key.uppercased()) {
            request.setValue(value, forHTTPHeaderField: key)
        }

        request.setValue("*/*", forHTTPHeaderField: "Accept")
        request.setValue("application/x-apple-plist", forHTTPHeaderField: "Content-Type")
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")

        let (data, response) = try await StoreAuthWire.post(request, session: session)
        guard response.statusCode == 200,
              data.count <= AnisetteState.anisetteLimit else {
            throw StoreAuthError.failure("apple Store provisioning returned HTTP \(response.statusCode)")
        }

        let result = try StoreAuthWire.decodePlist(data)

        guard let settingInfo = result["settingInfo"] as? String,
              AnisetteState.isValidHeaderValue(settingInfo, limit: AnisetteState.anisetteLimit) else {
            throw StoreAuthError.failure("apple Store provisioning response is missing settingInfo")
        }

        guard let transportKey = result["transportKey"] as? String,
              AnisetteState.isValidHeaderValue(transportKey, limit: AnisetteState.anisetteLimit) else {
            throw StoreAuthError.failure("apple Store provisioning response is missing transportKey")
        }

        var keyBag = Data()
        if let data = result["keybag"] as? Data {
            keyBag = data
        } else if let encoded = result["keybag"] as? String {
            keyBag = Data(base64Encoded: encoded) ?? Data()
        }

        guard keyBag.count <= AnisetteState.anisetteLimit else {
            throw StoreAuthError.failure("apple Store provisioning response contains an invalid keybag")
        }

        return (settingInfo, transportKey, keyBag)
    }

    private static func decodeValue(_ value: String, key: String) throws -> Data {
        guard let decoded = Data(base64Encoded: value),
              !decoded.isEmpty,
              decoded.count <= AnisetteState.anisetteLimit else {
            throw StoreAuthError.failure("decode Apple Store provisioning \(key)")
        }

        return decoded
    }
}
