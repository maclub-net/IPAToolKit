import Foundation
import CSAP

/// CSAP 的 libunicorn 薄封装。Store emulator 只使用 ARM64。
final class UCEngine {
    private var handle: OpaquePointer?
    private static var loaded = false

    private init(handle: OpaquePointer) {
        self.handle = handle
    }

    static func load() throws {
        if loaded {
            return
        }

        guard let path = unicornPath() else {
            throw StoreRuntimeError.failure("libunicorn is not available")
        }

        guard path.withCString({ csap_uc_load($0) }) == 0 else {
            throw StoreRuntimeError.failure("load libunicorn")
        }

        loaded = true
    }

    static func open() throws -> UCEngine {
        try load()

        guard let handle = csap_uc_open(Int32(CSAP_UC_ARCH_ARM64), Int32(CSAP_UC_MODE_ARM)) else {
            throw StoreRuntimeError.failure("open unicorn engine")
        }

        _ = csap_uc_set_max_cpu_model(handle)

        return UCEngine(handle: handle)
    }

    private static func unicornPath() -> String? {
        if let environment = ProcessInfo.processInfo.environment["CSAP_UNICORN_DYLIB"],
           !environment.isEmpty {
            return environment
        }

        for path in ["/opt/homebrew/lib/libunicorn.2.dylib",
                     "/usr/local/lib/libunicorn.2.dylib",
                     "/usr/lib/libunicorn.2.dylib"]
        where FileManager.default.fileExists(atPath: path) {
            return path
        }

        // 最后交给 dyld 的默认搜索路径。
        return "libunicorn.2.dylib"
    }

    func close() throws {
        guard let handle else {
            return
        }

        self.handle = nil
        guard csap_uc_close(handle) == 0 else {
            throw StoreRuntimeError.failure("close unicorn engine")
        }
    }

    func memMap(_ address: UInt64, _ size: UInt64) throws {
        guard let handle else {
            throw StoreRuntimeError.failure("engine is closed")
        }

        guard csap_uc_mem_map(handle, address, size, UInt32(CSAP_UC_PROT_ALL)) == 0 else {
            throw StoreRuntimeError.failure("map guest memory \(String(address, radix: 16))")
        }
    }

    func memRead(_ address: UInt64, _ size: UInt64) throws -> [UInt8] {
        guard let handle else {
            throw StoreRuntimeError.failure("engine is closed")
        }

        guard size <= UInt64(Int.max) else {
            throw StoreRuntimeError.failure("guest read exceeds host address space")
        }

        var buffer = [UInt8](repeating: 0, count: Int(size))
        let result: Int32 = buffer.withUnsafeMutableBytes { bytes in
            guard let base = bytes.baseAddress else {
                return -1
            }

            return csap_uc_mem_read(handle, address, base, size)
        }

        guard result == 0 else {
            throw StoreRuntimeError.failure("read guest memory \(String(address, radix: 16)) (\(size) bytes)")
        }

        return buffer
    }

    func memWrite(_ address: UInt64, _ data: [UInt8]) throws {
        guard let handle else {
            throw StoreRuntimeError.failure("engine is closed")
        }

        if data.isEmpty {
            return
        }

        let result: Int32 = data.withUnsafeBytes { bytes in
            guard let base = bytes.baseAddress else {
                return -1
            }

            return csap_uc_mem_write(handle, address, base, UInt64(data.count))
        }

        guard result == 0 else {
            throw StoreRuntimeError.failure("write guest memory \(String(address, radix: 16))")
        }
    }

    func regRead(_ register: Int32) throws -> UInt64 {
        guard let handle else {
            throw StoreRuntimeError.failure("engine is closed")
        }

        var value: UInt64 = 0
        guard csap_uc_reg_read(handle, register, &value) == 0 else {
            throw StoreRuntimeError.failure("read guest register \(register)")
        }

        return value
    }

    func regWrite(_ register: Int32, _ value: UInt64) throws {
        guard let handle else {
            throw StoreRuntimeError.failure("engine is closed")
        }

        guard csap_uc_reg_write(handle, register, value) == 0 else {
            throw StoreRuntimeError.failure("write guest register \(register)")
        }
    }

    func regRead128(_ register: Int32) throws -> [UInt8] {
        guard let handle else {
            throw StoreRuntimeError.failure("engine is closed")
        }

        var value = [UInt8](repeating: 0, count: 16)
        let result: Int32 = value.withUnsafeMutableBytes { bytes in
            guard let base = bytes.baseAddress else {
                return -1
            }

            return csap_uc_reg_read128(handle, register, base)
        }

        guard result == 0 else {
            throw StoreRuntimeError.failure("read guest vector register \(register)")
        }

        return value
    }

    func regWrite128(_ register: Int32, _ value: [UInt8]) throws {
        guard let handle else {
            throw StoreRuntimeError.failure("engine is closed")
        }

        guard value.count == 16 else {
            throw StoreRuntimeError.failure("vector register value must be 16 bytes")
        }

        let result: Int32 = value.withUnsafeBytes { bytes in
            guard let base = bytes.baseAddress else {
                return -1
            }

            return csap_uc_reg_write128(handle, register, base)
        }

        guard result == 0 else {
            throw StoreRuntimeError.failure("write guest vector register \(register)")
        }
    }

    /// Go 侧 `StartBounded`：超时单位为微秒，count 为指令上限。
    func startBounded(begin: UInt64, end: UInt64, timeoutMicroseconds: UInt64, count: UInt64) throws {
        guard let handle else {
            throw StoreRuntimeError.failure("engine is closed")
        }

        let result = csap_uc_emu_start(handle, begin, end, timeoutMicroseconds, count)
        guard result == 0 else {
            throw StoreRuntimeError.failure("guest stopped: \(String(cString: csap_uc_strerror(result)))")
        }
    }

    func stop() {
        guard let handle else {
            return
        }

        _ = csap_uc_emu_stop(handle)
    }

    func addCodeHook(begin: UInt64, end: UInt64,
                     callback: csap_uc_hook_cb, userData: UnsafeMutableRawPointer) throws -> UInt {
        guard let handle else {
            throw StoreRuntimeError.failure("engine is closed")
        }

        var hook = UInt(0)
        guard csap_uc_hook_add(handle, &hook, Int32(CSAP_UC_HOOK_CODE), callback, userData, begin, end) == 0 else {
            throw StoreRuntimeError.failure("install guest code hook")
        }

        return hook
    }

    func deleteHook(_ hook: UInt) throws {
        guard let handle else {
            throw StoreRuntimeError.failure("engine is closed")
        }

        guard csap_uc_hook_del(handle, hook) == 0 else {
            throw StoreRuntimeError.failure("remove guest code hook")
        }
    }
}
