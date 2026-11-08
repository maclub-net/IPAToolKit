import Foundation
import CSAP
import CryptoKit

// Store emulator 的 ARM64 运行时。
// 对应 Go 侧 internal/store/emulator/{runtime,memory,hashing}.go。
//
// 供 Bridge.swift / SwiftRuntime.swift / Network.swift 使用的接口约定：
// - arg(_:) / set(_:) / read64(_:) / write64(_:_:) / write32(_:_:)
// - memRead(_:_:) / memWrite(_:_:) / alloc(_:) / selectorAddress(for:)
// - cstring(_:) / guestString(_:) / newObject(_:_:) / setIvar(_:_:_:)
// - lookup(_:_:_:) / invoke(_:_:_:) / call(_:_:) / jump(_:_:_:)
// - message(_:_:_:) / symbol(_:) / delegateCall(_:_:_:) / hostBlock(_:) / hostBlockFunction(_:)
// - kindOf(_:_:) / responds(_:_:) / classAddress(_:) / importValue(_:) / export(_:)
// 全部可能失败的方法都使用 `throws`。

/// 既有的 guest 值。除 Go 的 nil 外一一对应。
enum GuestValue {
    case none
    case string(String)
    case int(Int64)
    case bool(Bool)
    case double(Double)
    case data([UInt8])
    case dictionary([String: UInt64])
    case array([UInt64])
}

/// 导出给宿主的值，不含 guest 指针。
indirect enum ExportValue {
    case null
    case string(String)
    case int(Int64)
    case bool(Bool)
    case double(Double)
    case data([UInt8])
    case dictionary([String: ExportValue])
    case array([ExportValue])
}

/// 一个 guest 对象。
final class GuestObject {
    var cls: String
    var value: GuestValue
    var properties: [String: UInt64]

    init(cls: String, value: GuestValue, properties: [String: UInt64] = [:]) {
        self.cls = cls
        self.value = value
        self.properties = properties
    }
}

enum StoreRuntimeError: Error, CustomStringConvertible {
    case failure(String)

    var description: String {
        switch self {
        case let .failure(message):
            return message
        }
    }
}

struct FrameworkError: Error, CustomStringConvertible {
    var domain: String
    var code: Int64
    var message: String?

    var description: String {
        "framework error \(domain) \(code)\(message.map { ": \($0)" } ?? "")"
    }
}

struct TaskLocalBinding {
    let key: UInt64
    let value: UInt64
}

final class AsyncTask {
    var continuation: UInt64 = 0
    var handle: UInt64 = 0
    var context: UInt64 = 0
    var entry: UInt64 = 0
    var closure: UInt64 = 0
    var result: UInt64 = 0
    var executor: (UInt64, UInt64) = (0, 0)
    var done = false
}

struct TimerEntry {
    let at: UInt64
    let block: UInt64
}

final class InflateStream {
    var bits: Int64
    var input: [UInt8] = []
    var output: [UInt8] = []
    var position: Int = 0
    var decoded = false

    init(bits: Int64) {
        self.bits = bits
    }
}

struct StoreHTTPRequest {
    var url: String
    var method: String
    var headers: [String: String]
    var body: [UInt8]
}

struct StoreHTTPResponse {
    var status: Int
    var headers: [String: [String]]
    var body: [UInt8]
}

enum StoreRuntimeConstants {
    static let heapBase: UInt64 = 0x400000000000
    static let heapSize: UInt64 = 64 << 20
    static let stackBase: UInt64 = 0x500000000000
    static let stackSize: UInt64 = 8 << 20
    static let returnPC: UInt64 = 0x100000000
}

let ucRegX0 = Int32(CSAP_ARM64_REG_X0.rawValue)
let ucRegSP = Int32(CSAP_ARM64_REG_SP.rawValue)
let ucRegLR = Int32(CSAP_ARM64_REG_X30.rawValue)
let ucRegPC = Int32(CSAP_ARM64_REG_PC.rawValue)
let ucRegX29 = Int32(CSAP_ARM64_REG_X29.rawValue)

final class StoreRuntime {
    var lastResponse: StoreHTTPResponse?
    var transportError: Error?
    var streamResponse = false
    var noRedirects = false
    var authRequest = false

    var taskLocalFrames: [UInt64: [TaskLocalBinding]] = [:]
    var transport: ((StoreHTTPRequest) throws -> StoreHTTPResponse)?
    var xpcSyncHandler: ((String, [UInt8]) throws -> [UInt8])?
    var inflaters: [UInt64: InflateStream] = [:]
    var responseHeaders: [UInt64: [String: [String]]] = [:]
    var tasks: [UInt64: AsyncTask] = [:]
    var currentTask: AsyncTask?
    var nullObject: UInt64 = 0
    var associations: [UInt64: [UInt64: UInt64]] = [:]
    var currentQueue: UInt64 = 0
    var selectedQueue: UInt64 = 0
    var preferences: [String: UInt64] = [:]
    var notificationCenter: UInt64 = 0
    var observers: [UInt64: GuestObject] = [:]
    var pendingQueues: [UInt64: UInt64] = [:]
    var allocations: [UInt64: UInt64] = [:]
    var codeRanges: [(UInt64, UInt64)] = []
    var steps: UInt64 = 0
    var timers: [TimerEntry] = []
    var callbacks: [UInt64: () throws -> Void] = [:]
    var pending: [UInt64] = []

    var hardwareID: [UInt8] = []
    var engine: UCEngine!
    var profile: StoreProfile
    var classes: [String: ProfileClass]
    var classNames: [UInt64: String]
    var methods: [String: UInt64]
    var calls: [UInt64: ProfileCall]
    var selectors: [UInt64: String]
    var selectorAddresses: [String: UInt64]
    var objects: [UInt64: GuestObject]
    var pages: [UInt64: Bool] = [:]
    var cursor: UInt64 = 0
    var fault: Error?
    var trace: [String] = []
    var entries: [UInt64: String]
    var hook: UInt = 0

    var deadline: Date
    var cancelled = false

    private init(tables: ProfileTables, timeout: TimeInterval) {
        profile = tables.profile
        classes = tables.classes
        classNames = tables.classNames
        methods = tables.methods
        calls = tables.calls
        selectors = tables.selectors
        selectorAddresses = tables.selectorAddresses
        objects = [:]
        entries = tables.entries
        deadline = Date().addingTimeInterval(timeout)

        for (address, template) in tables.objects {
            var value = template.value
            if case let .dictionary(fields) = value {
                value = .dictionary(fields)
            } else if case let .array(items) = value {
                value = .array(items)
            }

            objects[address] = GuestObject(cls: template.cls, value: value)
        }
    }

    // MARK: - 打开运行时

    static func open(imageData: [UInt8], prepared: StoreProfileAssets.Loaded,
                     timeout: TimeInterval = 120) throws -> StoreRuntime {
        let digest = SHA256.hash(data: Data(imageData)).map { String(format: "%02x", $0) }.joined()
        guard digest == "95f4558aa2c0ccd9f96ed479e336b630b46bf4b4e0baabc1c1ac8c7d55e21ab4" else {
            throw StoreRuntimeError.failure("AppleMediaServices does not match the pinned 26A434 image")
        }

        let tables = try StoreProfileMetadata.prepare(metadata: prepared.metadata)
        let runtime = StoreRuntime(tables: tables, timeout: timeout)

        runtime.engine = try UCEngine.open()
        var ready = false
        defer {
            if !ready {
                runtime.closeQuietly()
            }
        }

        for region in [(StoreRuntimeConstants.heapBase, StoreRuntimeConstants.heapSize),
                       (StoreRuntimeConstants.stackBase, StoreRuntimeConstants.stackSize),
                       (StoreRuntimeConstants.returnPC, UInt64(4096))] {
            try runtime.memMap(region.0, region.1)
        }

        var images: [(String, [UInt8])] = [("AppleMediaServices", imageData)]
        if !runtime.profile.PluginUUID.isEmpty {
            guard runtime.profile.PluginUUID == "B8C07F94-4868-3CD7-A59A-F01E8C24C1B7" else {
                throw StoreRuntimeError.failure("unsupported authentication plugin UUID")
            }

            let pluginDigest = SHA256.hash(data: Data(prepared.plugin)).map { String(format: "%02x", $0) }.joined()
            guard pluginDigest == "e33fff05a6e6593dd91e33fd103b5d3068b62a787c680df33b859f19b3acc4ea" else {
                throw StoreRuntimeError.failure("authentication plugin does not match the pinned image")
            }

            images.append(("AMSAccountAuthenticationPlugin", prepared.plugin))
        }

        for (name, data) in images {
            guard let image = name.withCString({ csap_macho_open_arm64($0, data, UInt64(data.count)) }) else {
                throw StoreRuntimeError.failure("open Mach-O image \(name)")
            }

            defer { csap_macho_free(image) }

            let context = Unmanaged.passUnretained(runtime).toOpaque()
            guard csap_macho_prepare_prelinked(image, nil, 0, rejectRelocation, context) == 0 else {
                throw StoreRuntimeError.failure("prepare prelinked image \(name)")
            }

            guard csap_macho_load(image, machoMemMap, machoMemWrite, context) == 0 else {
                throw StoreRuntimeError.failure("load image \(name)")
            }

            runtime.collectCodeAndIvarMetadata(image)
        }

        var addresses: [UInt64] = []
        for page in tables.profile.Pages where runtime.pages[page.Address] != true {
            addresses.append(page.Address)
        }

        for call in tables.callsList {
            let page = call.Address & ~UInt64(4095)
            if runtime.pages[page] != true {
                addresses.append(page)
            }
        }

        for region in try groupPages(addresses) {
            try runtime.memMap(region.address, region.size)
        }

        for page in tables.profile.Pages {
            guard page.Offset + 4096 <= UInt64(prepared.pages.count) else {
                throw StoreRuntimeError.failure("profile page exceeds data")
            }

            let start = Int(page.Offset)
            try runtime.memWrite(page.Address, Array(prepared.pages[start ..< start + 4096]))
        }

        for call in tables.callsList {
            let page = call.Address & ~UInt64(4095)
            if runtime.pages[page] != true {
                try runtime.memMap(page, 4096)
            }

            try runtime.memWrite(call.Address, [0xc0, 0x03, 0x5f, 0xd6])
        }

        for patch in tables.profile.MetadataPatches {
            try runtime.memWrite(patch.Address, [UInt8](patch.Data))
        }

        runtime.hook = try runtime.engine.addCodeHook(
            begin: 0,
            end: UInt64.max,
            callback: storeRuntimeStepThunk,
            userData: Unmanaged.passUnretained(runtime).toOpaque()
        )

        ready = true

        return runtime
    }

    private func collectCodeAndIvarMetadata(_ image: UnsafeMutablePointer<csap_macho_image_t>) {
        let sAttrPureInstructions: UInt32 = 0x8000_0000
        let sAttrSomeInstructions: UInt32 = 0x0000_0400

        let count = Int(image.pointee.section_count)
        if count > 0, let sections = image.pointee.sections {
            for index in 0 ..< count {
                let section = sections[index]
                if section.flags & sAttrPureInstructions != 0 ||
                    section.flags & sAttrSomeInstructions != 0 {
                    codeRanges.append((section.address, section.address + section.size))
                }
            }
        }

        guard let symtab = image.pointee.symtab,
              let strtab = image.pointee.strtab else {
            return
        }

        let prefix = "_OBJC_IVAR_$_"
        for index in 0 ..< Int(image.pointee.symtab_count) {
            let symbol = symtab[index]
            guard symbol.n_strx < image.pointee.strtab_size else {
                continue
            }

            let name = String(cString: strtab + Int(symbol.n_strx))
            guard name.hasPrefix(prefix) else {
                continue
            }

            let rest = String(name.dropFirst(prefix.count))
            guard let dot = rest.firstIndex(of: ".") else {
                continue
            }

            let className = String(rest[rest.startIndex ..< dot])
            let ivarName = String(rest[rest.index(after: dot)...])
            guard let klass = classes[className], let offset = klass.Ivars[ivarName] else {
                continue
            }

            try? memWrite(symbol.n_value, withUnsafeBytes(of: UInt32(offset).littleEndian) { Array($0) })
        }
    }

    func close() throws {
        guard let engine else {
            return
        }

        if hook != 0 {
            try? engine.deleteHook(hook)
            hook = 0
        }

        objects.removeAll()
        callbacks.removeAll()
        responseHeaders.removeAll()
        inflaters.removeAll()
        preferences.removeAll()
        associations.removeAll()
        observers.removeAll()
        tasks.removeAll()
        pending.removeAll()
        timers.removeAll()
        self.engine = nil
        try engine.close()
    }

    private func closeQuietly() {
        try? engine?.close()
        engine = nil
    }

    // MARK: - 内存

    func memMap(_ address: UInt64, _ size: UInt64) throws {
        var overlap = false
        var page = address
        while page < address + size {
            if pages[page] == true {
                overlap = true
            }
            page += 4096
        }

        if !overlap {
            try engine.memMap(address, size)
            page = address
            while page < address + size {
                pages[page] = true
                page += 4096
            }
            return
        }

        page = address
        while page < address + size {
            if pages[page] == true {
                page += 4096
                continue
            }

            var end = page + 4096
            while end < address + size && pages[end] != true {
                end += 4096
            }

            try engine.memMap(page, end - page)
            while page < end {
                pages[page] = true
                page += 4096
            }
        }
    }

    func memRead(_ address: UInt64, _ size: UInt64) throws -> [UInt8] {
        try engine.memRead(address, size)
    }

    func memWrite(_ address: UInt64, _ data: [UInt8]) throws {
        try engine.memWrite(address, data)
    }

    func alloc(_ requested: UInt64) throws -> UInt64 {
        var size = requested
        guard size <= StoreRuntimeConstants.heapSize else {
            throw StoreRuntimeError.failure("guest allocation exceeds heap budget")
        }

        size = (size + 15) & ~UInt64(15)
        if size == 0 {
            size = 16
        }

        guard size <= StoreRuntimeConstants.heapSize - cursor else {
            throw StoreRuntimeError.failure("guest heap exhausted")
        }

        let address = StoreRuntimeConstants.heapBase + cursor
        cursor += size
        allocations[address] = size

        return address
    }

    func read64(_ address: UInt64) throws -> UInt64 {
        let bytes = try memRead(address, 8)
        var value: UInt64 = 0
        for index in 0 ..< 8 {
            value |= UInt64(bytes[index]) << (index * 8)
        }
        return value
    }

    func write64(_ address: UInt64, _ value: UInt64) throws {
        var little = value.littleEndian
        try withUnsafeBytes(of: &little) { try memWrite(address, Array($0)) }
    }

    func write32(_ address: UInt64, _ value: UInt32) throws {
        var little = value.littleEndian
        try withUnsafeBytes(of: &little) { try memWrite(address, Array($0)) }
    }

    func arg(_ index: Int) throws -> UInt64 {
        if index >= 8 {
            let sp = try engine.regRead(ucRegSP)
            return try read64(sp + UInt64(index - 8) * 8)
        }

        return try engine.regRead(ucRegX0 + Int32(index))
    }

    func set(_ value: UInt64) throws {
        try engine.regWrite(ucRegX0, value)
    }

    func cstring(_ address: UInt64) throws -> String {
        if address == 0 {
            return ""
        }

        if let value = selectors[address] {
            return value
        }

        var bytes: [UInt8] = []
        for offset in UInt64(0) ..< 16384 {
            let value = try memRead(address + offset, 1)
            if value[0] == 0 {
                return String(decoding: bytes, as: UTF8.self)
            }
            bytes.append(value[0])
        }

        throw StoreRuntimeError.failure("unterminated guest string")
    }

    func selectorAddress(for value: String) throws -> UInt64 {
        if let address = selectorAddresses[value], address != 0 {
            return address
        }

        let address = try alloc(UInt64(value.utf8.count + 1))
        var bytes = Array(value.utf8)
        bytes.append(0)
        try memWrite(address, bytes)
        selectorAddresses[value] = address
        selectors[address] = value

        return address
    }

    func newObject(_ className: String, _ value: GuestValue) throws -> UInt64 {
        var size: UInt64 = 256
        if let klass = classes[className] {
            size = max(klass.Size, 16)
        }

        let address = try alloc(size)
        objects[address] = GuestObject(cls: className, value: value)
        if let klass = classes[className] {
            try write64(address, klass.Address)
        }

        return address
    }

    func setIvar(_ object: UInt64, _ name: String, _ value: UInt64) throws {
        guard let instance = objects[object] else {
            throw StoreRuntimeError.failure("unknown guest object")
        }

        var className = instance.cls
        while !className.isEmpty {
            guard let klass = classes[className] else {
                break
            }

            if let offset = klass.Ivars[name] {
                try write64(object + offset, value)
                return
            }

            className = klass.Super
        }

        throw StoreRuntimeError.failure("unknown ivar \(instance.cls).\(name)")
    }

    func guestString(_ address: UInt64) throws -> String {
        if address == 0 {
            return ""
        }

        guard let object = objects[address] else {
            throw StoreRuntimeError.failure("unknown string object \(String(address, radix: 16))")
        }

        guard case let .string(value) = object.value else {
            throw StoreRuntimeError.failure("object \(object.cls) is not a string")
        }

        return value
    }

    func classAddress(_ name: String) -> UInt64 {
        classes[name]?.Address ?? 0
    }

    func lookup(_ className: String, _ selector: String, _ meta: Bool) -> UInt64 {
        var className = className
        while !className.isEmpty {
            if let address = methods[profileMethodKey(className, selector, meta)], address != 0 {
                return address
            }

            guard let klass = classes[className] else {
                break
            }

            className = klass.Super
        }

        return 0
    }

    // MARK: - 调用

    func invoke(_ object: UInt64, _ selector: String, _ args: [UInt64] = []) throws -> UInt64 {
        var className: String
        var meta = false

        if let name = classNames[object] {
            className = name
            meta = true
        } else if let instance = objects[object] {
            className = instance.cls
        } else {
            throw StoreRuntimeError.failure("unknown receiver \(String(object, radix: 16)) for \(selector)")
        }

        var entry = lookup(className, selector, meta)
        if entry == 0 {
            let block = try hostBlock {
                try self.message(object, selector, false)
            }
            entry = try read64(block + 16)
        }

        var arguments: [UInt64] = [object, try selectorAddress(for: selector)]
        arguments.append(contentsOf: args)

        return try call(entry, arguments)
    }

    func call(_ entry: UInt64, _ arguments: [UInt64]) throws -> UInt64 {
        for index in 0 ..< 8 {
            try engine.regWrite(ucRegX0 + Int32(index), index < arguments.count ? arguments[index] : 0)
        }

        let sp = StoreRuntimeConstants.stackBase + StoreRuntimeConstants.stackSize - 4096
        if arguments.count > 8 {
            for index in 8 ..< arguments.count {
                try write64(sp + UInt64(index - 8) * 8, arguments[index])
            }
        }

        try engine.regWrite(ucRegSP, sp)
        try engine.regWrite(ucRegLR, StoreRuntimeConstants.returnPC)
        fault = nil

        var stopped: Error?
        do {
            try engine.startBounded(
                begin: entry,
                end: StoreRuntimeConstants.returnPC,
                timeoutMicroseconds: UInt64(max(0, deadline.timeIntervalSinceNow) * 1_000_000),
                count: 20_000_000
            )
        } catch {
            stopped = error
        }

        if let fault {
            throw fault
        }

        let pc = try engine.regRead(ucRegPC)
        if let stopped {
            let lr = try? engine.regRead(ucRegLR)
            throw StoreRuntimeError.failure(
                "guest stopped at \(String(pc, radix: 16)) from \(lr.map { String($0, radix: 16) } ?? "?"): \(stopped); recent=\(trace)"
            )
        }

        guard pc == StoreRuntimeConstants.returnPC else {
            throw StoreRuntimeError.failure("instruction budget exhausted at \(String(pc, radix: 16))")
        }

        return try engine.regRead(ucRegX0)
    }

    func jump(_ entry: UInt64, _ receiver: UInt64, _ selector: String) throws {
        try engine.regWrite(ucRegX0, receiver)
        try engine.regWrite(ucRegX0 + 1, try selectorAddress(for: selector))
        try engine.regWrite(ucRegPC, entry)
    }

    // MARK: - 单步 hook

    func step(_ address: UInt64, _ size: UInt32) {
        do {
            if let callback = callbacks[address] {
                try callback()
                return
            }

            if let name = entries[address] {
                trace.append(name)
                if trace.count > 12 {
                    trace.removeFirst(trace.count - 12)
                }
            }

            guard let call = calls[address] else {
                var allowed = false
                for region in codeRanges where address >= region.0 && address < region.1 {
                    allowed = true
                    break
                }

                guard allowed else {
                    throw StoreRuntimeError.failure("execution outside the pinned image at \(String(address, radix: 16))")
                }

                steps += 1
                if steps % 4096 == 0, isCancelled() {
                    throw StoreRuntimeError.failure("cancelled")
                }

                return
            }

            if !call.Selector.isEmpty {
                try message(try arg(0), call.Selector, false)
                return
            }

            var symbolName = call.Symbol
            while symbolName.hasPrefix("_") {
                symbolName.removeFirst()
            }
            try symbol(symbolName)
        } catch {
            fault = StoreRuntimeError.failure("guest bridge at \(String(address, radix: 16)): \(error); recent=\(trace)")
            engine.stop()
        }
    }

    // MARK: - 导出

    func export(_ address: UInt64) throws -> ExportValue {
        var active: Set<UInt64> = []
        return try export(address, &active, 0)
    }

    private func export(_ address: UInt64, _ active: inout Set<UInt64>, _ depth: Int) throws -> ExportValue {
        if address == 0 {
            return .null
        }

        if depth > 32 || active.contains(address) {
            throw StoreRuntimeError.failure("cyclic or excessively nested guest value")
        }

        guard let object = objects[address] else {
            throw StoreRuntimeError.failure("unknown exported object \(String(address, radix: 16))")
        }

        active.insert(address)
        defer { active.remove(address) }

        switch object.value {
        case .none:
            return .null
        case let .string(value):
            return .string(value)
        case let .int(value):
            return .int(value)
        case let .bool(value):
            return .bool(value)
        case let .double(value):
            return .double(value)
        case let .data(value):
            return .data(value)
        case let .dictionary(fields):
            var result: [String: ExportValue] = [:]
            for (key, pointer) in fields {
                result[key] = try export(pointer, &active, depth + 1)
            }
            return .dictionary(result)
        case let .array(items):
            var result: [ExportValue] = []
            result.reserveCapacity(items.count)
            for pointer in items {
                result.append(try export(pointer, &active, depth + 1))
            }
            return .array(result)
        }
    }

    // MARK: - 取消 / 队列

    func isCancelled() -> Bool {
        cancelled || Date() >= deadline
    }

    func queuePending(_ block: UInt64, _ queue: UInt64) {
        pendingQueues[block] = queue
        pending.append(block)
    }

    func nextPending() -> UInt64 {
        for index in pending.indices {
            let block = pending[index]
            if let queue = objects[pendingQueues[block] ?? 0], queue.properties["suspendCount"] != 0 {
                continue
            }

            pending.remove(at: index)
            selectedQueue = pendingQueues[block] ?? 0
            pendingQueues.removeValue(forKey: block)

            return block
        }

        return 0
    }

    func queueIsWithin(_ queue: UInt64, _ target: UInt64) throws -> Bool {
        var queue = queue
        for _ in 0 ..< 32 {
            if queue == target {
                return true
            }

            guard let object = objects[queue] else {
                return false
            }

            queue = object.properties["targetQueue"] ?? 0
            if queue == 0 {
                return false
            }
        }

        throw StoreRuntimeError.failure("cyclic dispatch queue targets")
    }
}

// MARK: - C 回调

private func rejectRelocation(_ name: UnsafePointer<CChar>?, _ address: UnsafeMutablePointer<UInt64>?,
                              _ context: UnsafeMutableRawPointer?) -> Int32 {
    -1
}

private func machoMemMap(_ address: UInt64, _ size: UInt64, _ context: UnsafeMutableRawPointer?) -> Int32 {
    guard let context else {
        return -1
    }

    let runtime = Unmanaged<StoreRuntime>.fromOpaque(context).takeUnretainedValue()
    do {
        try runtime.memMap(address, size)
        return 0
    } catch {
        runtime.fault = error
        return -1
    }
}

private func machoMemWrite(_ address: UInt64, _ data: UnsafeRawPointer?, _ size: UInt64,
                           _ context: UnsafeMutableRawPointer?) -> Int32 {
    guard let context, let data else {
        return -1
    }

    let runtime = Unmanaged<StoreRuntime>.fromOpaque(context).takeUnretainedValue()
    do {
        try runtime.memWrite(address, Array(UnsafeRawBufferPointer(start: data, count: Int(size))))
        return 0
    } catch {
        runtime.fault = error
        return -1
    }
}

private func storeRuntimeStepThunk(_ engine: OpaquePointer?, _ address: UInt64, _ size: UInt32,
                                   _ context: UnsafeMutableRawPointer?) {
    guard let context else {
        return
    }

    Unmanaged<StoreRuntime>.fromOpaque(context).takeUnretainedValue().step(address, size)
}

// MARK: - 页分组

struct MemoryRegion {
    let address: UInt64
    let size: UInt64
}

/// 合并相邻页，减少 Unicorn 内存拓扑重建次数。
func groupPages(_ addresses: [UInt64]) throws -> [MemoryRegion] {
    let pageSize: UInt64 = 4096
    let maxRegionGap: UInt64 = 1 << 20
    let maxRegionSize: UInt64 = 32 << 20
    let maxProfileSpan: UInt64 = 1 << 30

    let sorted = addresses.sorted()
    for address in sorted where address % pageSize != 0 || address > UInt64.max - pageSize {
        throw StoreRuntimeError.failure("invalid Store profile page address")
    }

    var regions: [MemoryRegion] = []
    var total: UInt64 = 0
    var start = 0

    while start < sorted.count {
        var end = start + 1
        while end < sorted.count,
              sorted[end] - sorted[end - 1] <= maxRegionGap,
              sorted[end] - sorted[start] + pageSize <= maxRegionSize {
            end += 1
        }

        let size = sorted[end - 1] - sorted[start] + pageSize
        guard size <= maxProfileSpan - total else {
            throw StoreRuntimeError.failure("store profile mapping exceeds size limit")
        }

        total += size
        regions.append(MemoryRegion(address: sorted[start], size: size))
        start = end
    }

    return regions
}
