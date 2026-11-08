import Foundation
import Compression

// Store emulator 的运行时语义。
// 对应 Go 侧 internal/store/emulator/{hashing,callbacks,dictionary,async,
// notifications,accounts,session,bag,auth,purchase_adapter,compression,delegate,anisette}.go

// MARK: - SipHash

private func rotateLeft64(_ value: UInt64, _ amount: UInt64) -> UInt64 {
    (value << amount) | (value >> (64 - amount))
}

private func sipRound(_ v: inout [UInt64]) {
    v[0] &+= v[1]
    v[1] = rotateLeft64(v[1], 13) ^ v[0]
    v[0] = rotateLeft64(v[0], 32)
    v[2] &+= v[3]
    v[3] = rotateLeft64(v[3], 16) ^ v[2]
    v[0] &+= v[3]
    v[3] = rotateLeft64(v[3], 21) ^ v[0]
    v[2] &+= v[1]
    v[1] = rotateLeft64(v[1], 17) ^ v[2]
    v[2] = rotateLeft64(v[2], 32)
}

extension StoreRuntime {
    func initHasher(_ address: UInt64, _ seed: UInt64) throws {
        var a: UInt64 = 0
        var b: UInt64 = 0
        if let parameters = profile.Symbols["_swift_stdlib_Hashing_parameters"], parameters != 0 {
            a = try read64(parameters)
            b = try read64(parameters + 8)
        }

        a ^= seed

        let values: [UInt64] = [
            0,
            0x736f6d6570736575 ^ a,
            0x646f72616e646f6d ^ b,
            0x6c7967656e657261 ^ a,
            0x7465646279746573 ^ b,
            0, 0, 0, 0,
        ]

        for (index, value) in values.enumerated() {
            try write64(address + UInt64(index) * 8, value)
        }
    }

    func hashCompress(_ address: UInt64, _ word: UInt64, _ final: Bool) throws -> UInt64 {
        var v = [UInt64](repeating: 0, count: 4)
        for index in 0 ..< 4 {
            v[index] = try read64(address + 8 + UInt64(index) * 8)
        }

        v[3] ^= word
        sipRound(&v)

        v[0] ^= word
        if final {
            v[2] ^= 255
            for _ in 0 ..< 3 {
                sipRound(&v)
            }
        }

        for (index, value) in v.enumerated() {
            try write64(address + 8 + UInt64(index) * 8, value)
        }

        return v[0] ^ v[1] ^ v[2] ^ v[3]
    }

    func hashWord(_ address: UInt64, _ word: UInt64) throws {
        var tail = try read64(address)
        let count = tail >> 56
        let shift = (count & 7) * 8
        var chunk = word

        if shift != 0 {
            chunk = (tail & 0x00ff_ffff_ffff_ffff) | (word << shift)
            tail = ((count + 8) << 56) | (word >> (64 - shift))
        } else {
            tail &+= 8 << 56
        }

        try write64(address, tail)
        _ = try hashCompress(address, chunk, false)
    }

    func hashBytes(_ address: UInt64, _ data: [UInt8]) throws {
        for byte in data {
            var tail = try read64(address)
            let count = tail >> 56
            let shift = (count & 7) * 8
            let word = (tail & 0x00ff_ffff_ffff_ffff) | (UInt64(byte) << shift)

            if shift == 56 {
                _ = try hashCompress(address, word, false)
                try write64(address, (count + 1) << 56)
            } else {
                try write64(address, ((count + 1) << 56) | word)
            }
        }
    }
}

// MARK: - 回调与 block 复制

extension StoreRuntime {
    func callback(_ block: UInt64, _ args: [UInt64] = [], _ after: @escaping () throws -> Void) throws {
        try callbackFunction(try read64(block + 16), [block] + args, after)
    }

    func callbackFunction(_ function: UInt64, _ args: [UInt64],
                          _ after: @escaping () throws -> Void) throws {
        let link = try engine.regRead(ucRegLR)
        let resume = try alloc(16)
        try memWrite(resume, [0xc0, 0x03, 0x5f, 0xd6])

        callbacks[resume] = { [unowned self] in
            self.callbacks.removeValue(forKey: resume)
            try? self.engine.regWrite(ucRegLR, link)
            try? self.engine.regWrite(ucRegPC, link)
            try after()
        }

        for (index, value) in args.enumerated() {
            try engine.regWrite(ucRegX0 + Int32(index), value)
        }

        try engine.regWrite(ucRegLR, resume)
        try engine.regWrite(ucRegPC, function)
    }

    func copyBlock(_ block: UInt64, _ after: @escaping (UInt64) throws -> Void) throws {
        if block == 0 {
            try after(0)
            return
        }

        let flags = UInt32(try read64(block + 8))
        if flags & (1 << 28) != 0 {
            try after(block)
            return
        }

        let descriptor = try read64(block + 24)
        let size = try read64(descriptor + 8)
        guard size >= 32, size <= 1 << 20 else {
            throw StoreRuntimeError.failure("invalid guest block size")
        }

        let copied = try alloc(size)
        let data = try engine.memRead(block, size)
        try memWrite(copied, data)

        if flags & (1 << 25) != 0 {
            try callbackFunction(try read64(descriptor + 16), [copied, block]) {
                try after(copied)
            }
            return
        }

        try after(copied)
    }

    func copyValue(_ value: UInt64, _ after: @escaping (UInt64) throws -> Void) throws {
        if value == 0 {
            try after(0)
            return
        }

        if let object = objects[value] {
            if let entry = optionalLookup(object.cls, "copyWithZone:", false) {
                try callbackFunction(entry, [value, try selectorAddress(for: "copyWithZone:"), 0]) {
                    try after(self.arg(0))
                }
                return
            }

            try after(value)
            return
        }

        try copyBlock(value, after)
    }

    func copyByref(_ value: UInt64, _ after: @escaping (UInt64) throws -> Void) throws {
        let forwarded = try read64(value + 8)
        if forwarded != 0, forwarded != value {
            try after(forwarded)
            return
        }

        let header = try read64(value + 16)
        let size = header >> 32
        let flags = UInt32(truncatingIfNeeded: header)

        guard size >= 24, size <= 1 << 20 else {
            throw StoreRuntimeError.failure("invalid byref capture size")
        }

        let copied = try alloc(size)
        let data = try engine.memRead(value, size)
        try memWrite(copied, data)

        try write64(copied + 8, copied)
        try write64(value + 8, copied)

        if flags & (1 << 25) != 0 {
            try callbackFunction(try read64(value + 24), [copied, value]) {
                try after(copied)
            }
            return
        }

        try after(copied)
    }

    private func optionalLookup(_ className: String, _ selector: String, _ meta: Bool) -> UInt64? {
        let address = lookup(className, selector, meta)
        return address == 0 ? nil : address
    }
}

// MARK: - Swift 字典

extension StoreRuntime {
    func ensureUniqueDictionary(_ selfAddress: UInt64, _ unique: Bool, _ capacity: UInt64,
                                _ metadata: UInt64) throws {
        let old = try read64(selfAddress)
        let oldCapacity = try read64(old + 24)
        if unique, capacity <= oldCapacity {
            try set(0)
            return
        }

        let key = String(metadata)
        guard let layout = profile.SwiftDictionaries[key] else {
            throw StoreRuntimeError.failure("unprepared dictionary metadata \(String(metadata, radix: 16))")
        }

        guard (layout.KeyStride == 16 || layout.KeyStride == 32 || layout.KeyStride == 40),
              (layout.ValueStride == 8 || layout.ValueStride == 16 || layout.ValueStride == 32) else {
            throw StoreRuntimeError.failure("unsupported dictionary copy layout")
        }

        let buckets: UInt64 = 1024
        let storageCapacity = buckets * 3 / 4
        guard capacity <= storageCapacity else {
            throw StoreRuntimeError.failure("dictionary exceeds runtime capacity")
        }

        let count = try read64(old + 16)
        if count != 0, oldCapacity != storageCapacity {
            throw StoreRuntimeError.failure("dictionary resizing requires rehash")
        }

        let headerSize = 64 + buckets / 8
        let size = headerSize + buckets * (layout.KeyStride + layout.ValueStride)
        let storage = try alloc(size)
        try write64(storage, layout.Metadata)
        try write64(storage + 8, 3)
        try write64(storage + 16, count)
        try write64(storage + 24, storageCapacity)
        try write64(storage + 32, 10)
        try write64(storage + 40, try read64(old + 40))
        let keys = storage + headerSize
        let values = keys + buckets * layout.KeyStride
        try write64(storage + 48, keys)
        try write64(storage + 56, values)

        if count != 0 {
            let spans: [(UInt64, UInt64, UInt64)] = [
                (storage + 64, old + 64, buckets / 8),
                (keys, try read64(old + 48), buckets * layout.KeyStride),
                (values, try read64(old + 56), buckets * layout.ValueStride),
            ]

            for (destination, source, length) in spans {
                let data = try engine.memRead(source, length)
                try memWrite(destination, data)
            }
        }

        try write64(selfAddress, storage)
        try set(oldCapacity != storageCapacity ? 1 : 0)
    }

    func bridgeDictionaryToSwift(_ object: UInt64, _ keyType: UInt64, _ valueType: UInt64) throws -> UInt64 {
        let empty = profile.Symbols["_swiftEmptyDictionarySingleton"] ?? 0
        if object == 0 {
            return empty
        }

        guard let source = objects[object], case let .dictionary(values) = source.value else {
            throw StoreRuntimeError.failure("dictionary bridge input is not a dictionary")
        }

        if values.isEmpty {
            return empty
        }

        var typeRef: UInt64 = 0x1a2e1d5d6
        var keyStride: UInt64 = 16
        var valueStride: UInt64 = 32

        if valueType == profile.Symbols["$sSSN"] {
            guard keyType == valueType else {
                throw StoreRuntimeError.failure("unsupported typed dictionary bridge")
            }

            typeRef = 0x1a2e1d7c6
            valueStride = 16
        }

        if keyType == profile.Symbols["$ss11AnyHashableVN"] {
            typeRef = 0x1a2e1db1a
            keyStride = 40
        }

        guard let metadata = profile.SwiftTypes[String(typeRef)], metadata != 0 else {
            throw StoreRuntimeError.failure("String/Any dictionary metadata not prepared")
        }

        let slot = try alloc(8)
        try write64(slot, empty)
        try ensureUniqueDictionary(slot, false, UInt64(values.count), metadata)
        let storage = try read64(slot)
        let keys = try read64(storage + 48)
        let items = try read64(storage + 56)
        let seed = try read64(storage + 40)
        let buckets = UInt64(1) << UInt8(truncatingIfNeeded: try read64(storage + 32))

        for key in values.keys.sorted() {
            let hasher = try alloc(72)
            try initHasher(hasher, seed)
            var bytes = Array(key.precomposedStringWithCanonicalMapping.utf8)
            bytes.append(255)
            try hashBytes(hasher, bytes)
            let hash = try hashCompress(hasher, try read64(hasher), true)

            var index = hash & (buckets - 1)
            while try read64(storage + 64 + (index / 64) * 8) & (1 << (index % 64)) != 0 {
                index = (index + 1) & (buckets - 1)
            }

            let bitmap = storage + 64 + (index / 64) * 8
            try write64(bitmap, try read64(bitmap) | (1 << (index % 64)))
            try returnSwiftString(key)
            try write64(keys + index * keyStride, try arg(0))
            try write64(keys + index * keyStride + 8, try arg(1))

            if keyStride == 40 {
                try write64(keys + index * keyStride + 24, profile.Bridges["anyHashableStringMetadata"] ?? 0)
                try write64(keys + index * keyStride + 32, profile.Bridges["anyHashableStringWitness"] ?? 0)
            }

            if valueStride == 16 {
                guard let pointer = values[key],
                      let valueObject = objects[pointer],
                      case let .string(text) = valueObject.value else {
                    throw StoreRuntimeError.failure("non-string value in typed dictionary bridge")
                }

                try returnSwiftString(text)
                try write64(items + index * 16, try arg(0))
                try write64(items + index * 16 + 8, try arg(1))
            } else {
                try storeSwiftAny(items + index * 32, values[key] ?? 0)
            }
        }

        try write64(storage + 16, UInt64(values.count))

        return storage
    }

    func storeSwiftAny(_ destination: UInt64, _ object: UInt64) throws {
        guard let value = objects[object] else {
            throw StoreRuntimeError.failure("unknown object bridged to Swift Any")
        }

        var metadata: UInt64 = 0

        switch value.value {
        case let .string(text):
            try returnSwiftString(text)
            try write64(destination, try arg(0))
            try write64(destination + 8, try arg(1))
            metadata = profile.Symbols["$sSSN"] ?? 0
        case let .int(number):
            try write64(destination, UInt64(bitPattern: number))
            metadata = profile.Symbols["$sSiN"] ?? 0
        case let .bool(flag):
            try write64(destination, flag ? 1 : 0)
            metadata = profile.Symbols["$sSbN"] ?? 0
        case let .double(number):
            try write64(destination, number.bitPattern)
            metadata = profile.Symbols["$sSdN"] ?? 0
        default:
            var className = value.cls
            if className.contains("Dictionary") {
                className = "NSDictionary"
            } else if className.contains("Array") {
                className = "NSArray"
            } else if className.contains("Data") {
                className = "NSData"
            }

            metadata = profile.ObjCMetadata[className] ?? 0
            try write64(destination, object)
        }

        guard metadata != 0 else {
            throw StoreRuntimeError.failure("unprepared Swift Any metadata")
        }

        try write64(destination + 24, metadata)
    }

    func bridgeDictionaryToObjC(_ storage: UInt64, _ keyType: UInt64, _ valueType: UInt64) throws -> UInt64 {
        var result: [String: UInt64] = [:]
        let count = try read64(storage + 16)

        if count == 0 {
            return try newObject("NSDictionary", .dictionary(result))
        }

        guard keyType == profile.Symbols["$sSSN"], valueType == profile.Symbols["$sSSN"] else {
            throw StoreRuntimeError.failure("unsupported dictionary Objective-C bridge types")
        }

        guard count <= 768, (try read64(storage + 32) & 255) <= 10 else {
            throw StoreRuntimeError.failure("dictionary bridge exceeds budget")
        }

        let keys = try read64(storage + 48)
        let values = try read64(storage + 56)
        let buckets = UInt64(1) << UInt8(truncatingIfNeeded: try read64(storage + 32))

        for index in 0 ..< buckets {
            if try read64(storage + 64 + (index / 64) * 8) & (1 << (index % 64)) == 0 {
                continue
            }

            let key = try swiftString(try read64(keys + index * 16), try read64(keys + index * 16 + 8))
            let value = try swiftString(try read64(values + index * 16), try read64(values + index * 16 + 8))
            result[key] = try newObject("NSString", .string(value))
        }

        guard UInt64(result.count) == count else {
            throw StoreRuntimeError.failure("Swift dictionary count mismatch")
        }

        return try newObject("NSDictionary", .dictionary(result))
    }
}

// MARK: - Swift 并发

extension StoreRuntime {
    func asyncSymbol(_ name: String) throws -> Bool {
        switch name {
        case "swift_task_localValueGet":
            try set(taskLocalValue(try arg(0)))
        case "swift_task_localValuePush":
            let key = try arg(0)
            let source = try arg(1)
            let metadata = try arg(2)
            let size = try read64(try read64(metadata - 8) + 64)
            let value = try alloc(size)
            let data = try engine.memRead(source, size)
            try memWrite(value, data)

            let id = taskLocalOwner()
            taskLocalFrames[id, default: []].append(TaskLocalBinding(key: key, value: value))
            try set(0)
        case "swift_task_localValuePop":
            let id = taskLocalOwner()
            guard var values = taskLocalFrames[id], !values.isEmpty else {
                throw StoreRuntimeError.failure("empty TaskLocal binding stack")
            }

            values.removeLast()
            taskLocalFrames[id] = values
        case "swift_task_localsCopyTo":
            guard tasks[try arg(0)] != nil else {
                throw StoreRuntimeError.failure("unknown task for local bindings")
            }

            taskLocalFrames[try arg(0)] = taskLocalFrames[taskLocalOwner()] ?? []
        case "swift_continuation_init":
            guard let task = currentTask else {
                throw StoreRuntimeError.failure("continuation initialized outside task")
            }

            let context = try arg(0)
            let flags = try arg(1)
            guard flags & 4 == 0 else {
                throw StoreRuntimeError.failure("preawaited continuation unsupported")
            }

            task.continuation = context
            try write64(context + 16, (flags & 1) | ((flags & 8) >> 2))
            try write64(context + 24, 0)
            try write64(context + 32, 0)

            if flags & 2 == 0 {
                try write64(context + 48, 0)
                try write64(context + 56, 0)
            }

            try set(task.handle)
        case "swift_continuation_resume", "swift_continuation_throwingResume",
             "swift_continuation_throwingResumeWithError":
            guard let task = tasks[try arg(0)], task.continuation != 0 else {
                throw StoreRuntimeError.failure("unknown Swift continuation")
            }

            let context = task.continuation
            guard try read64(context + 24) != 2 else {
                throw StoreRuntimeError.failure("Swift continuation resumed twice")
            }

            if name == "swift_continuation_throwingResumeWithError" {
                try write64(context + 32, try arg(1))
            }

            try write64(context + 24, 2)
            try set(0)
        case "swift_continuation_await":
            let context = try arg(0)
            guard let task = currentTask, task.continuation == context else {
                throw StoreRuntimeError.failure("awaiting unknown Swift continuation")
            }

            try awaitContinuation(task: task, context: context)
        case "swift_task_create":
            let flags = try arg(0)
            let options = try arg(1)
            let resultType = try arg(2)
            let descriptor = try arg(3)
            let closure = try arg(4)

            guard options == 0, flags & ~UInt64(0x1cff) == 0 else {
                throw StoreRuntimeError.failure("unsupported Swift task options")
            }

            let bits = try read64(descriptor)
            let size = bits >> 32
            guard size >= 16, size <= 1 << 20 else {
                throw StoreRuntimeError.failure("invalid Swift async context size")
            }

            let entry = UInt64(bitPattern: Int64(bitPattern: descriptor) + Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: bits))))
            let task = AsyncTask()
            task.handle = try newObject("HostSwiftTask", .none)
            task.context = try alloc(size + 32) + 32
            task.entry = entry
            task.closure = closure

            var valueSize: UInt64 = 0
            if resultType != 0 {
                valueSize = try read64(try read64(resultType - 8) + 64)
            }

            task.result = try alloc(valueSize)
            tasks[task.handle] = task

            if flags & (1 << 10) != 0 {
                taskLocalFrames[task.handle] = taskLocalFrames[taskLocalOwner()] ?? []
            }

            pending.append(try hostBlock { [unowned self] in
                try self.startAsync(task)
            })
            try set(task.handle)
            try engine.regWrite(ucRegX0 + 1, task.context)
        case "swift_task_alloc":
            try set(try alloc(try arg(0)))
        case "swift_task_dealloc":
            break
        case "swift_task_getCurrent":
            try set(currentTask?.handle ?? 0)
        case "swift_task_isCancelled":
            try set(isCancelled() ? 1 : 0)
        case "swift_task_switch":
            guard let task = currentTask else {
                throw StoreRuntimeError.failure("executor switch outside a Swift task")
            }

            let function = try arg(0)
            task.executor = (try arg(1), try arg(2))
            try engine.regWrite(ucRegPC, function)
        case "swift_task_getCurrentExecutor":
            let executor = currentTask?.executor ?? (0, 0)
            try set(executor.0)
            try engine.regWrite(ucRegX0 + 1, executor.1)
        case "swift_task_isCurrentExecutor":
            let executor = currentTask?.executor ?? (0, 0)
            try set(executor == (try arg(0), try arg(1)) ? 1 : 0)
        default:
            return false
        }

        return true
    }

    private func awaitContinuation(task: AsyncTask, context: UInt64) throws {
        if try read64(context + 24) == 2 {
            task.continuation = 0
            currentTask = task
            try engine.regWrite(ucRegX0 + 22, context)
            try engine.regWrite(ucRegPC, try read64(context + 8))
            return
        }

        let block = nextPending()
        guard block != 0 else {
            throw StoreRuntimeError.failure("Swift continuation has no runnable completion")
        }

        currentTask = nil
        try pendingCallback(block) { [unowned self] in
            self.currentTask = task
            try self.awaitContinuation(task: task, context: context)
        }
    }

    func startAsync(_ task: AsyncTask) throws {
        guard !task.done else {
            throw StoreRuntimeError.failure("attempt to restart a completed Swift task")
        }

        var saved: [Int32: UInt64] = [:]
        for register in [ucRegSP, ucRegLR, ucRegX29] + (0 ..< 10).map({ ucRegX0 + 19 + Int32($0) }) {
            saved[register] = try engine.regRead(register)
        }

        let previous = currentTask
        currentTask = task
        let completion = try alloc(16)
        try memWrite(completion, [0xc0, 0x03, 0x5f, 0xd6])

        callbacks[completion] = { [unowned self] in
            guard !task.done else {
                throw StoreRuntimeError.failure("Swift task completed twice")
            }

            task.done = true
            self.currentTask = previous
            for (register, value) in saved {
                try self.engine.regWrite(register, value)
            }

            try self.set(0)
            try self.engine.regWrite(ucRegPC, saved[ucRegLR] ?? 0)
        }

        try write64(task.context, 0)
        try write64(task.context + 8, completion)
        try write64(task.context - 32, task.result)
        try write64(task.context - 24, task.entry)
        try write64(task.context - 16, task.closure)
        try engine.regWrite(ucRegX0, task.result)
        try engine.regWrite(ucRegX0 + 20, task.closure)
        try engine.regWrite(ucRegX0 + 21, 0)
        try engine.regWrite(ucRegX0 + 22, task.context)
        try engine.regWrite(ucRegPC, task.entry)
    }

    func taskLocalOwner() -> UInt64 {
        currentTask?.handle ?? 0
    }

    func taskLocalValue(_ key: UInt64) -> UInt64 {
        let frames = taskLocalFrames[taskLocalOwner()] ?? []
        for frame in frames.reversed() where frame.key == key {
            return frame.value
        }

        return 0
    }

    func pendingCallback(_ block: UInt64, _ after: @escaping () throws -> Void) throws {
        let previous = currentQueue
        currentQueue = selectedQueue
        try callback(block, []) { [unowned self] in
            self.currentQueue = previous
            try after()
        }
    }
}

// MARK: - 通知与 Accounts

extension StoreRuntime {
    func notificationMessage(_ receiver: UInt64, _ className: String, _ selector: String,
                             _ meta: Bool) throws -> Bool {
        if meta, className == "NSNotificationCenter", selector == "defaultCenter" {
            if notificationCenter == 0 {
                notificationCenter = try newObject(className, .none)
            }

            try set(notificationCenter)
            return true
        }

        if className == "NSNotification" {
            switch selector {
            case "name", "object", "userInfo":
                try set(objects[receiver]?.properties[selector] ?? 0)
                return true
            default:
                return false
            }
        }

        if meta || className != "NSNotificationCenter" {
            return false
        }

        switch selector {
        case "addObserver:selector:name:object:":
            let observer = try newObject("HostObserver", .none)
            guard let object = objects[observer] else {
                throw StoreRuntimeError.failure("unknown observer object")
            }

            object.properties = [
                "observer": try arg(2),
                "selector": try arg(3),
                "name": try arg(4),
                "object": try arg(5),
            ]
            observers[observer] = object
            try set(0)
        case "postNotificationName:object:userInfo:", "postNotificationName:object:":
            let name = try arg(2)
            let target = try arg(3)
            let info = selector == "postNotificationName:object:userInfo:" ? try arg(4) : 0

            let notification = try newObject("NSNotification", .none)
            objects[notification]?.properties = ["name": name, "object": target, "userInfo": info]

            for observer in observers.values {
                if let value = observer.properties["name"], value != 0,
                   try guestString(value) != guestString(name) {
                    continue
                }

                if let value = observer.properties["object"], value != 0, value != target {
                    continue
                }

                let observerTarget = observer.properties["observer"] ?? 0
                let observerSelector = try cstring(observer.properties["selector"] ?? 0)
                pending.append(try hostBlock { [unowned self] in
                    try self.delegateCall(observerTarget, observerSelector, [notification]) {
                        try self.set(0)
                    }
                })
            }

            try set(0)
        case "removeObserver:", "removeObserver:name:object:":
            let target = try arg(2)
            for (key, observer) in observers where key == target || observer.properties["observer"] == target {
                observers.removeValue(forKey: key)
            }

            try set(0)
        default:
            return false
        }

        return true
    }

    func accountMessage(_ receiver: UInt64, _ className: String, _ selector: String,
                        _ meta: Bool) throws -> Bool {
        if !meta, className == "ACAccountStore" || className == "ACDAccountStore" {
            switch selector {
            case "accountTypeWithAccountTypeIdentifier:", "accountTypeWithAccountTypeIdentifier:error:":
                let accountType = try newObject("ACAccountType", .none)
                objects[accountType]?.properties = ["identifier": try arg(2)]
                if selector == "accountTypeWithAccountTypeIdentifier:error:", try arg(3) != 0 {
                    try write64(try arg(3), 0)
                }

                try set(accountType)
                return true
            case "accountsWithAccountType:", "accountsWithAccountType:options:error:",
                 "accountsWithAccountType:options:classification:error:":
                if selector == "accountsWithAccountType:options:error:", try arg(4) != 0 {
                    try write64(try arg(4), 0)
                }

                if selector == "accountsWithAccountType:options:classification:error:", try arg(5) != 0 {
                    try write64(try arg(5), 0)
                }

                try set(try newObject("NSArray", .array([])))
                return true
            case "accounts":
                try set(try newObject("NSArray", .array([])))
                return true
            case "accountWithIdentifier:":
                try set(0)
                return true
            default:
                break
            }
        }

        if meta {
            return false
        }

        if !(try kindOf(className, "ACAccount")) && className != "ACAccountType"
            && className != "ACAccountCredential" {
            return false
        }

        guard let object = objects[receiver] else {
            throw StoreRuntimeError.failure("unknown account object")
        }

        switch selector {
        case "initWithIdentifier:description:":
            object.properties["identifier"] = try arg(2)
            object.properties["accountTypeDescription"] = try arg(3)
            try set(receiver)
        case "initWithAccountType:":
            object.properties["identifier"] = try newObject("NSString", .string(newUUIDString()))
            object.properties["accountType"] = try arg(2)
            object.properties["accountProperties"] = try newObject("NSMutableDictionary", .dictionary([:]))
            try set(receiver)
        case "initWithPassword:":
            object.properties["password"] = try arg(2)
            try set(receiver)
        case "accountPropertyForKey:":
            guard let properties = objects[object.properties["accountProperties"] ?? 0],
                  case let .dictionary(fields) = properties.value else {
                throw StoreRuntimeError.failure("account properties are not a dictionary")
            }

            try set(fields[try guestString(try arg(2))] ?? 0)
        case "setAccountProperty:forKey:":
            guard let properties = objects[object.properties["accountProperties"] ?? 0],
                  case var .dictionary(fields) = properties.value else {
                throw StoreRuntimeError.failure("account properties are not a dictionary")
            }

            let key = try guestString(try arg(3))
            if try arg(2) == 0 {
                fields.removeValue(forKey: key)
            } else {
                fields[key] = try arg(2)
            }

            properties.value = .dictionary(fields)
            try set(0)
        case "accountType", "identifier", "username", "credential", "accountProperties",
             "authenticated", "active", "owningBundleID", "accountDescription",
             "parentAccount", "isDirty":
            try set(object.properties[selector] ?? 0)
        default:
            guard selector.hasPrefix("set"), selector.hasSuffix(":"),
                  selector.filter({ $0 == ":" }).count == 1 else {
                return false
            }

            var key = String(selector.dropFirst(3).dropLast())
            if key.count >= 2 {
                let second = key[key.index(after: key.startIndex)]
                if !(second >= "A" && second <= "Z") {
                    key = key.prefix(1).lowercased() + String(key.dropFirst())
                }
            }

            object.properties[key] = try arg(2)
            try set(0)
            return true
        }

        return true
    }
}

// MARK: - AMS 会话 / bag / 凭据 / 购买

extension StoreRuntime {
    func resolveAddress(_ promise: UInt64) throws -> UInt64 {
        let failure = try alloc(8)
        let result = try invoke(promise, "resultWithError:", [failure])

        if try read64(failure) != 0 {
            let errorObject = try read64(failure)
            guard let domain = try? invoke(errorObject, "domain") else {
                throw StoreRuntimeError.failure("framework returned an error")
            }

            guard let code = try? invoke(errorObject, "code") else {
                throw StoreRuntimeError.failure("framework returned an error")
            }

            var failureError = FrameworkError(domain: try guestString(domain), code: Int64(bitPattern: code))
            if let message = try? invoke(errorObject, "localizedDescription"), message != 0 {
                failureError.message = try guestString(message)
            }

            throw failureError
        }

        guard result != 0 else {
            throw StoreRuntimeError.failure("framework returned no result")
        }

        return result
    }

    func ephemeralAccount(_ saved: [String: Any]?) throws -> UInt64 {
        let account = try invoke(classAddress("ACAccount"), "ams_createEphemeralAccount")
        guard let saved else {
            return account
        }

        guard let dsidText = saved["directoryServicesIdentifier"] as? String,
              let dsid = Int64(dsidText) else {
            throw StoreRuntimeError.failure("invalid saved account identifier")
        }

        let fields: [(String, UInt64)] = [
            ("setUsername:", try importValue(saved["email"] as Any)),
            ("ams_setDSID:", try newObject("NSNumber", .int(dsid))),
            ("ams_setPassword:", try importValue(saved["passwordToken"] as Any)),
            ("ams_setStorefront:", try importValue(saved["storeFront"] as Any)),
        ]

        for (selector, value) in fields {
            _ = try invoke(account, selector, [value])
        }

        return account
    }

    func configureRequest(_ request: UInt64, _ account: UInt64, _ bag: UInt64, _ raw: Bool) throws {
        let properties = try invoke(request, "properties")
        let fields: [(String, UInt64)] = [
            ("setAccount:", account),
            ("setBag:", bag),
            ("setKnownToBeTrusted:", 1),
            ("setShouldSetCookiesFromResponse:", 0),
            ("setShouldSetStorefrontFromResponse:", 0),
            ("setDisableLoadURLMetrics:", 1),
            ("setDisableBiometricsResponseHandling:", 1),
            ("setMaxRetryCount:", 0),
            ("setDisableResponseDecoding:", raw ? 1 : 0),
        ]

        for (selector, value) in fields {
            _ = try invoke(properties, selector, [value])
        }
    }

    func newSession() throws -> UInt64 {
        let session = try invoke(try newObject("AMSURLSession", .none),
                                 "initWithConfiguration:delegate:delegateQueue:", [0, 0, 0])
        _ = try invoke(session, "setUseFallbackBag:", [0])

        return session
    }

    func sendRequest(_ session: UInt64, _ request: UInt64) throws -> UInt64 {
        let promise = try invoke(session, "dataTaskPromiseWithRequest:", [request])
        return try resolveAddress(promise)
    }

    func frozenBagFromValues(_ values: [String: Any]) throws -> UInt64 {
        let builder = try newObject("AMSBagFrozenDataSourceBuilder", .none)
        let fields: [(String, UInt64)] = [
            ("setData:", try importValue(values)),
            ("setProfile:", try newObject("NSString", .string("AMSPurchase"))),
            ("setProfileVersion:", try newObject("NSString", .string("1"))),
            ("setExpirationDate:", try newObject("NSDate", .double(Date().addingTimeInterval(300).timeIntervalSince1970))),
        ]

        for (selector, value) in fields {
            _ = try invoke(builder, selector, [value])
        }

        return try invoke(builder, "createFrozenBag")
    }

    func newCredentialTask(_ account: UInt64, _ bag: UInt64, _ password: String, _ source: UInt64) throws -> UInt64 {
        guard classAddress("AMSVerifyCredentialsTask") != 0 else {
            throw StoreRuntimeError.failure("authentication plugin is missing from the profile")
        }

        let options = try invoke(try newObject("AMSAuthenticateOptions", .none), "init")
        let fields: [(String, UInt64)] = [
            ("setEphemeral:", 1),
            ("setCanMakeAccountActive:", 0),
            ("setAllowServerDialogs:", 0),
            ("setPassword:", try newObject("NSString", .string(password))),
            ("setCredentialSource:", source),
        ]

        for (selector, value) in fields {
            _ = try invoke(options, selector, [value])
        }

        let task = try invoke(try newObject("AMSVerifyCredentialsTask", .none), "init")
        for (name, value) in [("_account", account), ("_options", options), ("_bag", bag)] {
            try setIvar(task, name, value)
        }

        return task
    }

    func configuredPurchaseEncoder(_ info: UInt64, _ bag: UInt64) throws -> UInt64 {
        let className = "IPAToolPurchaseRequestEncoder"
        let selector = "requestByEncodingRequestAndReturnSigningErrors:parameters:"

        if classes[className] == nil {
            guard let base = classes["AMSPurchaseRequestEncoder"] else {
                throw StoreRuntimeError.failure("purchase request encoder is missing from the profile")
            }

            let address = try alloc(16)
            classes[className] = ProfileClass.stub(
                name: className,
                address: address,
                superName: base.Super,
                size: base.Size
            )
            classNames[address] = className
            let implementation = lookup("AMSURLRequestEncoder", selector, false)

            let block = try hostBlock { [unowned self] in
                let receiver = try self.arg(0)
                let request = try self.arg(2)
                let parameters = try self.arg(3)
                try self.delegateCall(receiver, "setAnisetteType:", [0]) {
                    try self.delegateCall(receiver, "setMescalType:", [0]) {
                        try self.delegateCall(request, "properties", []) {
                            let properties = try self.arg(0)
                            try self.delegateCall(properties, "setAnisetteType:", [0]) {
                                try self.delegateCall(properties, "setMescalType:", [0]) {
                                    try self.delegateCall(properties, "setDisableLoadURLMetrics:", [1]) {
                                        try self.delegateCall(receiver, "setDisableLoadURLMetrics:", [1]) {
                                            try self.callbackFunction(
                                                implementation,
                                                [receiver, try self.selectorAddress(for: selector), request, parameters]
                                            ) {}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            methods[profileMethodKey(className, selector, false)] = try read64(block + 16)
        }

        return try invoke(try newObject(className, .none), "initWithPurchaseInfo:bag:", [info, bag])
    }
}

// MARK: - 压缩

extension StoreRuntime {
    func compressionSymbol(_ name: String) throws -> Bool {
        switch name {
        case "inflateInit2_":
            guard try arg(3) == 112 else {
                throw StoreRuntimeError.failure("unsupported zlib stream ABI")
            }

            inflaters[try arg(0)] = InflateStream(bits: Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: try arg(1)))))
            try write64(try arg(0) + 16, 0)
            try write64(try arg(0) + 40, 0)
            try set(0)
        case "inflateEnd":
            inflaters.removeValue(forKey: try arg(0))
            try set(0)
        case "inflate":
            let address = try arg(0)
            guard let state = inflaters[address] else {
                throw StoreRuntimeError.failure("uninitialized inflate stream")
            }

            var size = UInt64(UInt32(truncatingIfNeeded: try read64(address + 8)))
            guard size <= 32 << 20 else {
                throw StoreRuntimeError.failure("inflate input exceeds budget")
            }

            if size != 0 {
                let pointer = try read64(address)
                let data = try engine.memRead(pointer, size)
                state.input.append(contentsOf: data)
                try write64(address, pointer + size)
                try write32(address + 8, 0)
                try write64(address + 16, try read64(address + 16) + size)
            }

            if !state.decoded {
                guard let output = StoreRuntime.inflate(state.input, bits: state.bits) else {
                    try set(~UInt64(2))
                    return true
                }

                guard output.count <= 32 << 20 else {
                    throw StoreRuntimeError.failure("decompressed response exceeds runtime limit")
                }

                state.output = output
                state.decoded = true
            }

            size = UInt64(UInt32(truncatingIfNeeded: try read64(address + 32)))
            let count = min(size, UInt64(state.output.count - state.position))
            let out = try read64(address + 24)

            if count != 0 {
                try memWrite(out, Array(state.output[state.position ..< state.position + Int(count)]))
            }

            state.position += Int(count)
            try write64(address + 24, out + count)
            try write32(address + 32, UInt32(size - count))
            try write64(address + 40, try read64(address + 40) + count)
            try set(state.position == state.output.count ? 1 : 0)
        default:
            return false
        }

        return true
    }

    /// zlib / gzip / raw deflate。返回 nil 表示当前输入尚不足以完成解码。
    static func inflate(_ input: [UInt8], bits: Int64) -> [UInt8]? {
        var payload: [UInt8]

        switch bits {
        case 31, 47:
            guard let stripped = stripGzip(input) else {
                return nil
            }
            payload = stripped
        case 15:
            guard let stripped = stripZlib(input) else {
                return nil
            }
            payload = stripped
        case -15:
            payload = input
        default:
            return nil
        }

        var capacity = max(64 * 1024, payload.count * 4)
        let limit = 32 << 20

        while capacity <= limit + 1 {
            var output = [UInt8](repeating: 0, count: capacity)
            let written = output.withUnsafeMutableBytes { destination -> Int in
                payload.withUnsafeBytes { source -> Int in
                    guard let sourceBase = source.bindMemory(to: UInt8.self).baseAddress,
                          let destinationBase = destination.bindMemory(to: UInt8.self).baseAddress else {
                        return 0
                    }

                    return compression_decode_buffer(
                        destinationBase,
                        capacity,
                        sourceBase,
                        payload.count,
                        nil,
                        COMPRESSION_ZLIB
                    )
                }
            }

            if written > 0 {
                return Array(output[0 ..< written])
            }

            capacity *= 2
        }

        return nil
    }

    private static func stripZlib(_ input: [UInt8]) -> [UInt8]? {
        guard input.count > 6 else {
            return nil
        }

        let cmf = UInt16(input[0])
        let flg = UInt16(input[1])
        guard (cmf * 256 + flg) % 31 == 0, cmf & 0x0f == 8 else {
            return nil
        }

        return Array(input[2 ..< input.count - 4])
    }

    private static func stripGzip(_ input: [UInt8]) -> [UInt8]? {
        guard input.count > 18, input[0] == 0x1f, input[1] == 0x8b, input[2] == 8 else {
            return nil
        }

        let flags = input[3]
        var offset = 10

        if flags & 0x04 != 0 {
            guard offset + 2 <= input.count else {
                return nil
            }

            let extra = Int(input[offset]) | (Int(input[offset + 1]) << 8)
            offset += 2 + extra
        }

        if flags & 0x08 != 0 {
            while offset < input.count, input[offset] != 0 {
                offset += 1
            }
            offset += 1
        }

        if flags & 0x10 != 0 {
            while offset < input.count, input[offset] != 0 {
                offset += 1
            }
            offset += 1
        }

        if flags & 0x02 != 0 {
            offset += 2
        }

        guard offset <= input.count, offset <= input.count - 8 else {
            return nil
        }

        return Array(input[offset ..< input.count - 8])
    }
}

// MARK: - Store AMD 适配器

extension StoreRuntime {
    func interactiveDelegate() throws -> UInt64 {
        let name = "IPAToolStoreDelegate"
        if classes[name] == nil {
            let address = try alloc(16)
            classes[name] = ProfileClass.stub(name: name, address: address, superName: "NSObject", size: 16)
            classNames[address] = name

            let selectors = [
                "AMSURLSession:task:handleAuthenticateRequest:completion:",
                "AMSURLSession:task:handleDialogRequest:completion:",
            ]

            for (index, selector) in selectors.enumerated() {
                let code = Int64(index + 1)
                let block = try hostBlock { [unowned self] in
                    let completion = try self.arg(5)
                    let failure = try self.newObject("NSError", .dictionary([
                        "domain": try self.newObject("NSString", .string("IPAToolStoreInteraction")),
                        "code": try self.newObject("NSNumber", .int(code)),
                        "userInfo": try self.newObject("NSDictionary", .dictionary([:])),
                    ]))
                    try self.callback(completion, [0, failure]) {
                        try self.set(0)
                    }
                }

                methods[profileMethodKey(name, selector, false)] = try read64(block + 16)
            }
        }

        return try newObject(name, .none)
    }

    func installStoreAMDAdapter() throws {
        func install(_ address: UInt64, _ callback: @escaping () throws -> Void) throws {
            let page = address & ~UInt64(4095)
            if pages[page] != true {
                try memMap(page, 4096)
            }

            try memWrite(address, [0xc0, 0x03, 0x5f, 0xd6])
            callbacks[address] = callback
        }

        try install(0x180574a18) { [unowned self] in
            try self.set(try self.newObject("HostXPCDictionary", .dictionary([:])))
        }

        try install(0x180553470) { [unowned self] in
            guard let object = self.objects[try self.arg(0)],
                  case var .dictionary(fields) = object.value else {
                throw StoreRuntimeError.failure("XPC dictionary receiver is not a dictionary")
            }

            let length = try self.arg(3)
            guard length <= 1 << 20 else {
                throw StoreRuntimeError.failure("XPC data exceeds runtime limit")
            }

            let data = try self.engine.memRead(try self.arg(2), length)
            fields[try self.cstring(try self.arg(1))] = try self.newObject("NSData", .data(data))
            object.value = .dictionary(fields)
            try self.set(0)
        }

        try install(0x180553a00) { [unowned self] in
            guard let object = self.objects[try self.arg(0)],
                  case let .dictionary(fields) = object.value else {
                throw StoreRuntimeError.failure("XPC dictionary receiver is not a dictionary")
            }

            guard let dataObject = self.objects[fields[try self.cstring(try self.arg(1))] ?? 0],
                  case let .data(data) = dataObject.value else {
                if try self.arg(2) != 0 {
                    try self.write64(try self.arg(2), 0)
                }

                try self.set(0)
                return
            }

            let pointer = try self.alloc(UInt64(max(data.count, 1)))
            if !data.isEmpty {
                try self.memWrite(pointer, data)
            }

            if try self.arg(2) != 0 {
                try self.write64(try self.arg(2), UInt64(data.count))
            }

            try self.set(pointer)
        }

        try install(0x18054c6b8) { [unowned self] in
            try self.set(0)
        }

        try install(0x180554c88) { [unowned self] in
            let connection = try self.newObject("HostXPCConnection", .string(try self.cstring(try self.arg(0))))
            self.objects[connection]?.properties["targetQueue"] = try self.arg(1)
            self.objects[connection]?.properties["flags"] = try self.arg(2)
            try self.set(connection)
        }

        try install(0x180554dac) { [unowned self] in
            self.objects[try self.arg(0)]?.properties["eventHandler"] = try self.arg(1)
            try self.set(0)
        }

        try install(0x1805550b4) { [unowned self] in
            try self.set(0)
        }

        try install(0x180556440) { [unowned self] in
            guard let connection = self.objects[try self.arg(0)],
                  let message = self.objects[try self.arg(1)],
                  case let .dictionary(fields) = message.value,
                  let dataObject = self.objects[fields["data"] ?? 0],
                  case let .data(data) = dataObject.value else {
                throw StoreRuntimeError.failure("Store AMD XPC handler is unavailable")
            }

            guard let handler = self.xpcSyncHandler else {
                throw StoreRuntimeError.failure("Store AMD XPC handler is unavailable")
            }

            let name: String
            if case let .string(value) = connection.value {
                name = value
            } else {
                name = ""
            }

            let reply = try handler(name, data)
            try self.set(try self.newObject("HostXPCDictionary", .dictionary([
                "data": try self.newObject("NSData", .data(reply)),
            ])))
        }

        try install(0x184e50b38) { [unowned self] in
            if try self.arg(1) != 0 {
                try self.write64(try self.arg(1), 1)
            }

            try self.set(0)
        }

        try install(0x184e51370) { [unowned self] in
            if try self.arg(1) != 0 {
                try self.write64(try self.arg(1), 0)
            }

            try self.set(0)
        }

        try install(0x18073bc1c) { [unowned self] in
            try self.set(0)
        }

        try install(0x18071bec4) { [unowned self] in
            let now = Date()
            if try self.arg(0) != 0 {
                try self.write64(try self.arg(0), UInt64(now.timeIntervalSince1970))
                try self.write64(try self.arg(0) + 8, UInt64(Int(now.timeIntervalSince1970 * 1_000_000) % 1_000_000))
            }

            try self.set(0)
        }
    }

    func storeAMDHeaders(endpoint: String, hardwareID: [UInt8],
                         xpcHandler: @escaping (String, [UInt8]) throws -> [UInt8]) throws -> [String: String] {
        guard let url = URL(string: endpoint), url.scheme == "https", let host = url.host, !host.isEmpty else {
            throw StoreRuntimeError.failure("invalid Store AMD endpoint")
        }

        guard hardwareID.count == 6 else {
            throw StoreRuntimeError.failure("invalid Store AMD hardware identity")
        }

        self.hardwareID = hardwareID
        xpcSyncHandler = xpcHandler
        try installStoreAMDAdapter()

        let request = try invoke(classAddress("NSURLRequest"), "requestWithURL:", [
            try newObject("NSURL", .string(url.absoluteString)),
        ])
        let value = try invoke(classAddress("AMSAnisette"), "_headersForRequest:account:type:", [request, 0, 2])
        let exported = try export(value)

        guard case let .dictionary(dictionary) = exported else {
            throw StoreRuntimeError.failure("AppleMediaServices returned no Store AMD proof")
        }

        var result: [String: String] = [:]
        for key in ["X-Apple-AMD", "X-Apple-AMD-M"] {
            guard case let .string(text)? = dictionary[key],
                  !text.isEmpty, text.utf8.count <= 8192,
                  !text.contains("\r"), !text.contains("\n") else {
                throw StoreRuntimeError.failure("AppleMediaServices returned an incomplete Store AMD proof")
            }

            result[key] = text
        }

        return result
    }
}

extension ProfileClass {
    static func stub(name: String, address: UInt64, superName: String, size: UInt64) -> ProfileClass {
        ProfileClass(
            MetaAddress: 0,
            Name: name,
            Address: address,
            Super: superName,
            Size: size,
            Ivars: [:],
            Methods: nil
        )
    }
}
