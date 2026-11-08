import Foundation
import CSAP
import CryptoKit

// Store emulator 的 Objective-C / C 符号桥。
// 对应 Go 侧 internal/store/emulator/bridge.go。

/// ARM64 的 D0（double 返回值）在 Unicorn 中的寄存器编号。
let ucRegD0 = Int32(40)

// MARK: - 共享辅助

func boolValue(_ value: Bool) -> UInt64 {
    value ? 1 : 0
}

func littleUInt32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
    var value: UInt32 = 0
    for index in 0 ..< 4 {
        value |= UInt32(bytes[offset + index]) << (index * 8)
    }
    return value
}

func littleUInt64(_ bytes: [UInt8], _ offset: Int) -> UInt64 {
    var value: UInt64 = 0
    for index in 0 ..< 8 {
        value |= UInt64(bytes[offset + index]) << (index * 8)
    }
    return value
}

func littleBytes64(_ value: UInt64) -> [UInt8] {
    (0 ..< 8).map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
}

/// 与 Go 的字符串比较一致：按 UTF-8 字节序比较。
func byteCompareStrings(_ left: String, _ right: String) -> Int64 {
    let a = Array(left.utf8)
    let b = Array(right.utf8)
    let count = min(a.count, b.count)
    for index in 0 ..< count where a[index] != b[index] {
        return a[index] < b[index] ? -1 : 1
    }
    if a.count == b.count {
        return 0
    }
    return a.count < b.count ? -1 : 1
}

/// Go 中 `fmt.Sprint(obj.Value)` 的近似实现。
func guestDescription(_ value: GuestValue) -> String {
    switch value {
    case .none:
        return "<nil>"
    case let .string(text):
        return text
    case let .int(number):
        return String(number)
    case let .bool(flag):
        return flag ? "true" : "false"
    case let .double(number):
        return String(number)
    case let .data(bytes):
        return "[" + bytes.map { String($0) }.joined(separator: " ") + "]"
    case let .array(items):
        return "[" + items.map { String($0) }.joined(separator: " ") + "]"
    case let .dictionary(fields):
        let body = fields.keys.sorted().map { "\($0):\(fields[$0] ?? 0)" }.joined(separator: " ")
        return "map[" + body + "]"
    }
}

/// Go 的 http.CanonicalHeaderKey。
func canonicalHeaderKey(_ name: String) -> String {
    if name.isEmpty {
        return name
    }

    var result = ""
    var upper = true
    for character in name {
        var value = character
        if upper, value >= "a", value <= "z" {
            value = Character(value.uppercased())
        } else if !upper, value >= "A", value <= "Z" {
            value = Character(value.lowercased())
        }
        result.append(value)
        upper = value == "-"
    }
    return result
}

func makeUTCDate(year: Int, month: Int, day: Int,
                 hour: Int, minute: Int, second: Int) -> Date {
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = TimeZone(identifier: "UTC") ?? TimeZone(secondsFromGMT: 0)!
    let components = DateComponents(year: year, month: month, day: day,
                                    hour: hour, minute: minute, second: second)
    return calendar.date(from: components) ?? Date(timeIntervalSince1970: 0)
}

func utcComponents(_ date: Date) -> DateComponents {
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = TimeZone(identifier: "UTC") ?? TimeZone(secondsFromGMT: 0)!
    return calendar.dateComponents([.second, .minute, .hour, .day, .month, .year, .weekday], from: date)
}

func utcDayOfYear(_ date: Date) -> Int {
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = TimeZone(identifier: "UTC") ?? TimeZone(secondsFromGMT: 0)!
    return calendar.ordinality(of: .day, in: .year, for: date) ?? 1
}

func formatHTTPDate(_ date: Date) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(identifier: "GMT")
    formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
    return formatter.string(from: date)
}

func parseHTTPDate(_ value: String) -> Date? {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(identifier: "GMT")

    formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
    if let date = formatter.date(from: value) {
        return date
    }

    formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
    return formatter.date(from: value)
}

/// Go 的 path.Join。
func storePathJoin(_ first: String, _ second: String) -> String {
    let combined = first + "/" + second
    var parts: [String] = []
    for part in combined.split(separator: "/", omittingEmptySubsequences: true) {
        if part == "." {
            continue
        }
        if part == ".." {
            if !parts.isEmpty {
                parts.removeLast()
            }
            continue
        }
        parts.append(String(part))
    }

    let prefix = first.hasPrefix("/") ? "/" : ""
    if parts.isEmpty {
        return prefix.isEmpty ? "." : "/"
    }
    return prefix + parts.joined(separator: "/")
}

/// Go 的 path.Ext。
func storePathExtension(_ value: String) -> String {
    let bytes = Array(value.utf8)
    var index = bytes.count - 1
    while index >= 0 {
        if bytes[index] == UInt8(ascii: "/") {
            return ""
        }
        if bytes[index] == UInt8(ascii: ".") {
            return String(decoding: bytes[index...], as: UTF8.self)
        }
        index -= 1
    }
    return ""
}

/// Go 的 path.Base。
func storePathBase(_ value: String) -> String {
    if value.isEmpty {
        return "."
    }

    var path = value
    while path.count > 1, path.hasSuffix("/") {
        path.removeLast()
    }

    if path == "/" {
        return "/"
    }

    if let index = path.lastIndex(of: "/") {
        return String(path[path.index(after: index)...])
    }
    return path
}

// MARK: - 符号分发

extension StoreRuntime {
    func symbol(_ name: String) throws {
        if try compressionSymbol(name) {
            return
        }

        switch name {
        case "xpc_get_type":
            if let object = objects[try arg(0)], object.cls == "HostXPCDictionary" {
                try set(profile.Symbols["__xpc_type_dictionary"] ?? 0)
            } else {
                try set(0)
            }
        case "CC_SHA512":
            let length = UInt64(UInt32(truncatingIfNeeded: try arg(1)))
            guard length <= StoreRuntimeConstants.heapSize else {
                throw StoreRuntimeError.failure("SHA-512 input exceeds runtime budget")
            }

            let data = try engine.memRead(try arg(0), length)
            let digest = Array(SHA512.hash(data: Data(data)))

            var output = try arg(2)
            if output == 0 {
                output = try alloc(64)
            }

            try memWrite(output, digest)
            try set(output)
        case "strftime":
            let out = try arg(0)
            let limit = try arg(1)
            let format = try cstring(try arg(2))
            let tm = try arg(3)
            guard format == "%a, %d %b %Y %H:%M:%S GMT" else {
                throw StoreRuntimeError.failure("unsupported date output format \(format)")
            }

            let data = try engine.memRead(tm, 36)
            func field(_ index: Int) -> Int {
                Int(Int32(bitPattern: littleUInt32(data, index * 4)))
            }

            let date = makeUTCDate(year: field(5) + 1900, month: field(4) + 1, day: field(3),
                                   hour: field(2), minute: field(1), second: field(0))
            let value = formatHTTPDate(date)
            if UInt64(value.utf8.count) + 1 > limit {
                try set(0)

                return
            }

            try memWrite(out, Array(value.utf8) + [0])
            try set(UInt64(value.utf8.count))
        case "strptime":
            let value = try cstring(try arg(0))
            let format = try cstring(try arg(1))
            let out = try arg(2)
            guard format == "%a, %d %b %Y %H:%M:%S GMT" || format == "%a, %d %b %Y %H:%M:%S %Z" else {
                throw StoreRuntimeError.failure("unsupported date format \(format)")
            }

            guard let date = parseHTTPDate(value) else {
                try set(0)

                return
            }

            let components = utcComponents(date)
            let fields = [
                components.second ?? 0,
                components.minute ?? 0,
                components.hour ?? 0,
                components.day ?? 1,
                (components.month ?? 1) - 1,
                (components.year ?? 1970) - 1900,
                (components.weekday ?? 1) - 1,
                utcDayOfYear(date) - 1,
                0,
            ]

            for (index, item) in fields.enumerated() {
                var word = UInt32(bitPattern: Int32(item)).littleEndian
                try memWrite(out + UInt64(index * 4),
                             withUnsafeBytes(of: &word) { Array($0) })
            }

            try set(try arg(0) + UInt64(value.utf8.count))
        case "timegm":
            let data = try engine.memRead(try arg(0), 36)
            func field(_ index: Int) -> Int {
                Int(Int32(bitPattern: littleUInt32(data, index * 4)))
            }

            let date = makeUTCDate(year: field(5) + 1900, month: field(4) + 1, day: field(3),
                                   hour: field(2), minute: field(1), second: field(0))
            try set(UInt64(bitPattern: Int64(date.timeIntervalSince1970.rounded(.down))))
        case "CFURLResponseCopyPeerAddress":
            // The portable response exposes no CFNetwork peer-address metadata.
            try set(0)
        case "res_9_ndestroy":
            // No native resolver state was created by the failed res_9_ninit.
            return
        case "res_9_ninit":
            // CFNetwork DNS diagnostics are unavailable; the host transport owns DNS.
            try set(UInt64(0xffff_ffff))
        case "CRIsAutoSubmitEnabled":
            // The isolated runtime does not opt into diagnostics submission.
            try set(0)
        case "NSUserName", "NSFullUserName":
            try set(try newObject("NSString", .string("ipatool")))
        case "NSTemporaryDirectory":
            try set(try newObject("NSString", .string("/ipatool/tmp/")))
        case "CPSharedResourcesDirectory", "NSHomeDirectory":
            try set(try newObject("NSString", .string("/ipatool")))
        case "getuid", "geteuid":
            try set(501)
        case "getgid", "getegid":
            try set(20)
        case "NSSearchPathForDirectoriesInDomains":
            guard try arg(0) == 5, try arg(1) == 8 else {
                throw StoreRuntimeError.failure("unsupported virtual filesystem directory")
            }

            try set(try newObject("NSArray", .array([
                try newObject("NSString", .string("/System/Library")),
            ])))
        case "MGCopyAnswerWithError", "MGCopyAnswer":
            let key = try guestString(try arg(0))
            let value: String
            switch key {
            case "BuildVersion":
                value = "26A434"
            case "ProductVersion":
                value = "27.0.1"
            case "DeviceClass":
                value = "Mac"
            case "ProductType":
                value = "Mac14,2"
            default:
                throw StoreRuntimeError.failure("unsupported device property \(key)")
            }

            if name == "MGCopyAnswerWithError", try arg(2) != 0 {
                try memWrite(try arg(2), [0, 0, 0, 0])
            }

            try set(try newObject("NSString", .string(value)))
        case "time":
            let now = UInt64(Date().timeIntervalSince1970)
            if try arg(0) != 0 {
                try write64(try arg(0), now)
            }

            try set(now)
        case "localtime", "localtime_r", "gmtime_r":
            let now = Date(timeIntervalSince1970: TimeInterval(Int64(bitPattern: try read64(try arg(0)))))

            var out = try arg(1)
            if name == "localtime" {
                out = try alloc(56)
            }

            let components = utcComponents(now)
            var data = [UInt8](repeating: 0, count: 56)
            let fields = [
                components.second ?? 0,
                components.minute ?? 0,
                components.hour ?? 0,
                components.day ?? 1,
                (components.month ?? 1) - 1,
                (components.year ?? 1970) - 1900,
                (components.weekday ?? 1) - 1,
                utcDayOfYear(now) - 1,
                0,
            ]

            for (index, item) in fields.enumerated() {
                var word = UInt32(bitPattern: Int32(item)).littleEndian
                let bytes: [UInt8] = withUnsafeBytes(of: &word) { Array($0) }
                data.replaceSubrange(index * 4 ..< index * 4 + 4, with: bytes)
            }

            try memWrite(out, data)
            try set(out)
        case "objc_getAssociatedObject":
            try set(associations[try arg(0)]?[try arg(1)] ?? 0)
        case "objc_setAssociatedObject":
            let object = try arg(0)
            let key = try arg(1)
            let value = try arg(2)
            let policy = try arg(3)

            func save(_ saved: UInt64) throws {
                associations[object, default: [:]][key] = saved
                try set(0)
            }

            if policy & 255 == 3 {
                try copyValue(value, save)
            } else {
                try save(value)
            }
        case "CFPreferencesGetAppIntegerValue":
            let preference = try guestString(try arg(1)) + "/" + (try guestString(try arg(0)))
            let pointer = preferences[preference] ?? 0

            var value: Int64 = 0
            var valid = false
            if let object = objects[pointer], case let .int(number) = object.value {
                value = number
                valid = true
            }

            let out = try arg(2)
            if out != 0 {
                try memWrite(out, [UInt8(truncatingIfNeeded: boolValue(valid))])
            }

            try set(UInt64(bitPattern: value))
        case "CFPreferencesGetAppBooleanValue":
            let preference = try guestString(try arg(1)) + "/" + (try guestString(try arg(0)))
            let pointer = preferences[preference] ?? 0

            var value = false
            var valid = false
            if let object = objects[pointer] {
                switch object.value {
                case let .bool(flag):
                    value = flag
                    valid = true
                case let .int(number):
                    value = number != 0
                    valid = true
                default:
                    break
                }
            }

            let out = try arg(2)
            if out != 0 {
                try memWrite(out, [UInt8(truncatingIfNeeded: boolValue(valid))])
            }

            try set(boolValue(value))
        case "CFPreferencesAppSynchronize", "CFPreferencesSynchronize":
            try set(1)
        case "CFPreferencesCopyAppValue", "CFPreferencesCopyValue":
            let preference = try guestString(try arg(1)) + "/" + (try guestString(try arg(0)))
            try set(preferences[preference] ?? 0)
        case "CFPreferencesSetAppValue", "CFPreferencesSetValue":
            let preference = try guestString(try arg(2)) + "/" + (try guestString(try arg(0)))
            preferences[preference] = try arg(1)
            try set(0)
        case "objc_opt_self", "objc_unsafeClaimAutoreleasedReturnValue", "objc_retain",
             "objc_retainAutoreleasedReturnValue", "objc_claimAutoreleasedReturnValue",
             "objc_autoreleaseReturnValue", "objc_autorelease",
             "objc_retainAutoreleaseReturnValue", "objc_retainAutorelease":
            return
        case "objc_release", "objc_autoreleasePoolPop":
            return
        case "objc_autoreleasePoolPush":
            try set(0)
        case "objc_getProperty":
            try set(try read64(try arg(0) + (try arg(2))))
        case "objc_setProperty_nonatomic", "objc_setProperty_atomic":
            try write64(try arg(0) + (try arg(3)), try arg(2))
        case "objc_setProperty_nonatomic_copy", "objc_setProperty_atomic_copy":
            let destination = try arg(0) + (try arg(3))
            let value = try arg(2)
            try copyValue(value) { [unowned self] copied in
                try self.write64(destination, copied)
                try self.set(0)
            }
        case "objc_storeStrong", "objc_storeWeak", "objc_initWeak":
            try write64(try arg(0), try arg(1))
            try set(try arg(1))
        case "objc_copyWeak":
            try write64(try arg(0), try read64(try arg(1)))
        case "objc_moveWeak":
            try write64(try arg(0), try read64(try arg(1)))
            try write64(try arg(1), 0)
        case "objc_loadWeakRetained", "objc_loadWeak":
            try set(try read64(try arg(0)))
        case "objc_destroyWeak":
            try write64(try arg(0), 0)
        case "objc_alloc", "objc_allocWithZone", "objc_alloc_init", "objc_opt_new":
            guard let className = classNames[try arg(0)], !className.isEmpty else {
                throw StoreRuntimeError.failure("unknown allocated class \(String(try arg(0), radix: 16))")
            }

            let object = try newObject(className, .none)
            try set(object)

            if name != "objc_alloc", name != "objc_allocWithZone" {
                try message(object, "init", false)
            }
        case "objc_opt_class":
            if classNames[try arg(0)] != nil {
                return
            }

            guard let object = objects[try arg(0)] else {
                throw StoreRuntimeError.failure("unknown object class \(String(try arg(0), radix: 16))")
            }

            try set(classAddress(object.cls))
        case "objc_opt_isKindOfClass":
            guard let object = objects[try arg(0)] else {
                try set(0)

                return
            }

            let target = classNames[try arg(1)] ?? ""
            try set(boolValue(try kindOf(object.cls, target)))
        case "objc_opt_respondsToSelector":
            try set(boolValue(try responds(try arg(0), try cstring(try arg(1)))))
        case "objc_msgSend":
            try message(try arg(0), try cstring(try arg(1)), false)
        case "objc_msgSendSuper2":
            let superAddress = try arg(0)
            let receiver = try read64(superAddress)
            let className = classNames[try read64(superAddress + 8)] ?? ""
            let selector = try cstring(try arg(1))
            let meta = classNames[receiver] != nil

            if let klass = classes[className] {
                let entry = lookup(klass.Super, selector, meta)
                if entry != 0 {
                    try jump(entry, receiver, selector)

                    return
                }
            }

            try message(receiver, selector, true)
        case "CFBundleGetMainBundle":
            try set(try bundle())
        case "CFBundleGetInfoDictionary":
            try set(try bundleInfo())
        case "CFBundleGetValueForInfoDictionaryKey":
            let infoAddress = try bundleInfo()
            guard let object = objects[infoAddress], case let .dictionary(info) = object.value else {
                throw StoreRuntimeError.failure("bundle info is not a dictionary")
            }

            try set(info[try guestString(try arg(1))] ?? 0)
        case "CFBundleCopyExecutableURL":
            try set(try newObject("NSURL", .string("file:///ipatool")))
        case "getprogname":
            let value = Array("ipatool".utf8) + [0]
            let pointer = try alloc(UInt64(value.count))
            try memWrite(pointer, value)
            try set(pointer)
        case "getpid", "_getpid":
            try set(123)
        case "CFGetTypeID":
            guard let object = objects[try arg(0)] else {
                throw StoreRuntimeError.failure("CFGetTypeID of unknown object")
            }

            switch object.value {
            case .bool:
                try set(4)
            case .data:
                try set(1)
            case .string:
                try set(2)
            default:
                try set(3)
            }
        case "CFBooleanGetTypeID":
            try set(4)
        case "CFBooleanGetValue":
            guard let object = objects[try arg(0)], case let .bool(flag) = object.value else {
                throw StoreRuntimeError.failure("CFBooleanGetValue of non-boolean object")
            }

            try set(boolValue(flag))
        case "CFDataGetTypeID":
            try set(1)
        case "CFStringGetTypeID":
            try set(2)
        case "IOMasterPort":
            try write32(try arg(1), 1)
            try set(0)
        case "IOServiceMatching":
            try set(try newObject("NSDictionary", .dictionary([
                "IOProviderClass": try newObject("NSString", .string(try cstring(try arg(0)))),
            ])))
        case "IOBSDNameMatching":
            try set(try newObject("NSDictionary", .dictionary([
                "IOBSDName": try newObject("NSString", .string(try cstring(try arg(2)))),
            ])))
        case "IOServiceGetMatchingService":
            // The virtual device exposes no platform expert/serial service.
            try set(0)
        case "IOServiceGetMatchingServices":
            try write32(try arg(2), 1)
            try set(0)
        case "IOIteratorNext":
            try set(1)
        case "IORegistryEntryGetParentEntry":
            try write32(try arg(2), 2)
            try set(0)
        case "IORegistryEntryCreateCFProperty", "IORegistryEntrySearchCFProperty":
            if try arg(0) == 0 {
                try set(0)

                return
            }

            let keyIndex = name == "IORegistryEntrySearchCFProperty" ? 2 : 1
            let key = try guestString(try arg(keyIndex))
            switch key {
            case "IOBuiltin", "IOPrimaryInterface":
                try set(try newObject("NSNumber", .bool(true)))
            case "IOMACAddress":
                try set(try newObject("NSData", .data(hardwareID)))
            default:
                throw StoreRuntimeError.failure("unsupported IOKit property \(key)")
            }
        case "IOObjectRelease", "CFRelease":
            try set(0)
        case "CFDataGetLength":
            guard let object = objects[try arg(0)], case let .data(data) = object.value else {
                throw StoreRuntimeError.failure("CFDataGetLength of non-data object")
            }

            try set(UInt64(data.count))
        case "CFDataGetBytePtr":
            guard let object = objects[try arg(0)], case let .data(data) = object.value else {
                throw StoreRuntimeError.failure("CFDataGetBytePtr of non-data object")
            }

            let pointer = try alloc(UInt64(data.count))
            try memWrite(pointer, data)
            try set(pointer)
        case "CFDataGetBytes":
            guard let object = objects[try arg(0)], case let .data(data) = object.value else {
                throw StoreRuntimeError.failure("CFDataGetBytes of non-data object")
            }

            let start = try arg(1)
            let length = try arg(2)
            let destination = try arg(3)
            guard start + length <= UInt64(data.count) else {
                throw StoreRuntimeError.failure("CFDataGetBytes range exceeds data")
            }

            try memWrite(destination, Array(data[Int(start) ..< Int(start + length)]))
            try set(0)
        case "CFUUIDCreate":
            var data = [UInt8](repeating: 0, count: 16)
            for index in 0 ..< 16 {
                data[index] = UInt8.random(in: 0 ... 255)
            }

            data[6] = (data[6] & 15) | 64
            data[8] = (data[8] & 63) | 128
            try set(try newObject("HostUUID", .data(data)))
        case "CFUUIDGetUUIDBytes":
            guard let object = objects[try arg(0)], case let .data(data) = object.value,
                  data.count >= 16 else {
                throw StoreRuntimeError.failure("CFUUIDGetUUIDBytes of invalid UUID")
            }

            try set(littleUInt64(data, 0))
            try engine.regWrite(ucRegX0 + 1, littleUInt64(data, 8))
        case "NSClassFromString":
            try set(classAddress(try guestString(try arg(0))))
        case "class_getMethodImplementation":
            try set(lookup(classNames[try arg(0)] ?? "", try cstring(try arg(1)), false))
        case "sel_getName":
            return
        case "objc_getClass":
            try set(classAddress(try cstring(try arg(0))))
        case "NSStringFromClass":
            if try arg(0) == 0 {
                try set(0)
            } else {
                try set(try newObject("NSString", .string(classNames[try arg(0)] ?? "")))
            }
        case "NSSelectorFromString":
            try set(try selectorAddress(for: try guestString(try arg(0))))
        case "NSStringFromSelector":
            try set(try newObject("NSString", .string(try cstring(try arg(0)))))
        case "SecTaskCreateFromSelf":
            try set(try newObject("HostSecurityTask", .none))
        case "SecTaskCopyValueForEntitlement":
            let out = try arg(2)
            if out != 0 {
                try write64(out, 0)
            }

            try set(0)
        case "dispatch_time":
            var base = try arg(0)
            if base == 0 {
                base = UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
            }

            try set(base + (try arg(1)))
        case "dispatch_after":
            let deadline = try arg(0)
            let block = try arg(2)
            try copyBlock(block) { [unowned self] copied in
                self.timers.append(TimerEntry(at: deadline, block: copied))
                try self.set(0)
            }
        case "dispatch_assert_queue":
            guard try queueIsWithin(currentQueue, try arg(0)) else {
                throw StoreRuntimeError.failure(
                    "dispatch queue mismatch: running \(String(currentQueue, radix: 16)) expected \(String(try arg(0), radix: 16))"
                )
            }
        case "dispatch_sync":
            let previous = currentQueue
            currentQueue = try arg(0)
            try callback(try arg(1), []) { [unowned self] in
                self.currentQueue = previous
                try self.set(0)
            }
        case "dispatch_sync_f":
            let previous = currentQueue
            currentQueue = try arg(0)
            try callbackFunction(try arg(2), [try arg(1)]) { [unowned self] in
                self.currentQueue = previous
                try self.set(0)
            }
        case "dispatch_block_create":
            try copyBlock(try arg(1)) { [unowned self] block in
                try self.set(block)
            }
        case "dispatch_async":
            let queue = try arg(0)
            try copyBlock(try arg(1)) { [unowned self] block in
                self.queuePending(block, queue)
                try self.set(0)
            }
        case "dispatch_suspend":
            guard let object = objects[try arg(0)] else {
                throw StoreRuntimeError.failure("dispatch_suspend of unknown queue")
            }

            object.properties["suspendCount", default: 0] += 1
        case "dispatch_resume":
            guard let object = objects[try arg(0)] else {
                throw StoreRuntimeError.failure("dispatch_resume of unknown queue")
            }

            guard object.properties["suspendCount"] != 0 else {
                throw StoreRuntimeError.failure("resuming active dispatch queue")
            }

            object.properties["suspendCount", default: 0] -= 1
        case "dispatch_retain", "dispatch_release":
            return
        case "dispatch_semaphore_create":
            try set(try newObject("HostSemaphore", .int(Int64(bitPattern: try arg(0)))))
        case "dispatch_semaphore_signal":
            guard let object = objects[try arg(0)], case let .int(value) = object.value else {
                throw StoreRuntimeError.failure("dispatch_semaphore_signal of non-semaphore")
            }

            object.value = .int(value + 1)
            try set(0)
        case "dispatch_semaphore_wait":
            guard let semaphore = objects[try arg(0)] else {
                throw StoreRuntimeError.failure("dispatch_semaphore_wait of unknown semaphore")
            }

            var value: Int64 = 0
            if case let .int(current) = semaphore.value {
                value = current
            }

            if value > 0 {
                semaphore.value = .int(value - 1)
                try set(0)
            } else if !pending.isEmpty {
                let block = nextPending()
                guard block != 0 else {
                    throw StoreRuntimeError.failure("all pending queues are suspended")
                }

                try pendingCallback(block) { [unowned self] in
                    guard case let .int(current) = semaphore.value, current != 0 else {
                        throw StoreRuntimeError.failure("guest semaphore remains unsignaled")
                    }

                    semaphore.value = .int(current - 1)
                    try self.set(0)
                }
            } else {
                throw StoreRuntimeError.failure("guest waits on an unavailable host service")
            }
        case "Block_copy", "objc_retainBlock":
            try copyBlock(try arg(0)) { [unowned self] value in
                try self.set(value)
            }
        case "Block_release", "Block_object_dispose":
            return
        case "Block_object_assign":
            let destination = try arg(0)
            let value = try arg(1)
            let flags = try arg(2)
            if flags & 0xf == 7 {
                try copyBlock(value) { [unowned self] copied in
                    try self.write64(destination, copied)
                }
            } else if flags & 8 != 0 {
                try copyByref(value) { [unowned self] copied in
                    try self.write64(destination, copied)
                }
            } else {
                try write64(destination, value)
            }
        case "dispatch_once":
            let predicate = try arg(0)
            let block = try arg(1)
            if try read64(predicate) != 0 {
                try set(0)

                return
            }

            try write64(predicate, UInt64.max)
            try pendingCallback(block) { [unowned self] in
                try self.set(0)
            }
        case "swift_once":
            let predicate = try arg(0)
            let function = try arg(1)
            let context = try arg(2)
            if try read64(predicate) != 0 {
                try set(0)

                return
            }

            try write64(predicate, UInt64.max)
            try callbackFunction(function, [context]) { [unowned self] in
                try self.set(0)
            }
        case "dispatch_once_f":
            let predicate = try arg(0)
            let context = try arg(1)
            let function = try arg(2)
            if try read64(predicate) != 0 {
                try set(0)

                return
            }

            try write64(predicate, UInt64.max)
            try callbackFunction(function, [context]) { [unowned self] in
                try self.set(0)
            }
        case "dispatch_queue_attr_make_with_autorelease_frequency",
             "dispatch_queue_attr_make_with_qos_class":
            return
        case "dispatch_queue_create_with_target":
            let target = try arg(2)
            let queue = try newObject("HostQueue", .none)
            objects[queue]?.properties["targetQueue"] = target
            try set(queue)
        case "dispatch_set_target_queue":
            guard let object = objects[try arg(0)] else {
                throw StoreRuntimeError.failure("dispatch_set_target_queue of unknown queue")
            }

            object.properties["targetQueue"] = try arg(1)
        case "dispatch_queue_create", "dispatch_get_global_queue", "dispatch_get_main_queue":
            try set(try newObject("HostQueue", .none))
        case "os_unfair_lock_assert_not_owner", "objc_sync_enter", "objc_sync_exit",
             "os_unfair_lock_lock_with_options", "os_unfair_lock_lock", "os_unfair_lock_unlock",
             "os_unfair_lock_assert_owner", "os_unfair_recursive_lock_lock_with_options",
             "os_unfair_recursive_lock_unlock":
            try set(0)
        case "os_feature_enabled_impl":
            let key = try cstring(try arg(0)) + "/" + (try cstring(try arg(1)))
            guard let value = profile.Features[key] else {
                throw StoreRuntimeError.failure("unresolved native feature flag \(key)")
            }

            try set(boolValue(value))
        case "os_log_create":
            try set(try newObject("HostOSLog", .none))
        case "os_signpost_enabled", "os_log_type_enabled", "os_variant_has_internal_content":
            try set(0)
        case "malloc_size":
            try set(allocations[try arg(0)] ?? 0)
        case "malloc", "calloc", "malloc_type_malloc", "malloc_type_calloc":
            var size = try arg(0)
            if name == "calloc" || name == "malloc_type_calloc" {
                let count = try arg(1)
                if size != 0, count > StoreRuntimeConstants.heapSize / size {
                    throw StoreRuntimeError.failure("guest calloc exceeds heap budget")
                }

                size = size &* count
            }

            try set(try alloc(size))
        case "chkstk_darwin", "free":
            return
        case "platform_memmove", "platform_memcpy", "memcpy", "memmove", "memcpy_chk", "memmove_chk":
            let size = try arg(2)
            if size == 0 {
                return
            }

            guard size <= StoreRuntimeConstants.heapSize else {
                throw StoreRuntimeError.failure("guest copy exceeds memory budget")
            }

            let data = try engine.memRead(try arg(1), size)
            try memWrite(try arg(0), data)
        case "memset", "memset_chk":
            let size = try arg(2)
            guard size <= StoreRuntimeConstants.heapSize else {
                throw StoreRuntimeError.failure("guest fill exceeds memory budget")
            }

            let byte = UInt8(truncatingIfNeeded: try arg(1))
            try memWrite(try arg(0), [UInt8](repeating: byte, count: Int(size)))
        case "strlen":
            try set(UInt64(try cstring(try arg(0)).utf8.count))
        default:
            if try swiftSymbol(name) {
                return
            }

            let linkRegister = (try? engine.regRead(ucRegLR)) ?? 0
            throw StoreRuntimeError.failure(
                "unsupported import \(name) lr=\(String(linkRegister, radix: 16))"
            )
        }
    }

    func kindOf(_ className: String, _ target: String) throws -> Bool {
        if className == target {
            return true
        }

        if target == "NSObject" {
            return true
        }

        var name = className
        while !name.isEmpty {
            guard let klass = classes[name] else {
                return false
            }

            if klass.Super == target {
                return true
            }

            name = klass.Super
        }

        return false
    }

    func message(_ receiver: UInt64, _ selector: String, _ isSuper: Bool) throws {
        _ = isSuper
        if receiver == 0 {
            try engine.regWrite(ucRegX0 + 1, 0)
            for register in 40 ..< 44 {
                try engine.regWrite(Int32(register), 0)
            }

            try set(0)

            return
        }

        var className = classNames[receiver] ?? ""
        let meta = classNames[receiver] != nil
        let object = objects[receiver]

        if !meta {
            guard let instance = object else {
                if selector == "copy", receiver >= StoreRuntimeConstants.heapBase,
                   receiver < StoreRuntimeConstants.stackBase + StoreRuntimeConstants.stackSize {
                    try copyBlock(receiver) { [unowned self] copied in
                        try self.set(copied)
                    }

                    return
                }

                throw StoreRuntimeError.failure(
                    "unknown receiver \(String(receiver, radix: 16)) for \(selector)"
                )
            }

            className = instance.cls
        }

        if className == "HostUnavailableProxy" {
            guard let instance = object else {
                throw StoreRuntimeError.failure("unknown HostUnavailableProxy receiver")
            }

            let domain = try newObject("NSString", .string("NSCocoaErrorDomain"))
            let failure = try newObject("NSError", .dictionary([
                "domain": domain,
                "code": try newObject("NSNumber", .int(4099)),
                "userInfo": try newObject("NSDictionary", .dictionary([:])),
            ]))
            try callback(instance.properties["errorBlock"] ?? 0, [failure]) { [unowned self] in
                try self.set(0)
            }

            return
        }

        // Logging is a host service; it must not pull platform logging infrastructure into the guest.
        if className == "AMSLogConfig"
            || (className == "AMSConcurrency" && selector == "logFaultFromSwiftConcurrencyOnInternalBuild") {
            try set(0)

            return
        }

        if !isSuper {
            let entry = lookup(className, selector, meta)
            if entry != 0 {
                try jump(entry, receiver, selector)

                return
            }
        }

        if try notificationMessage(receiver, className, selector, meta) {
            return
        }

        if try accountMessage(receiver, className, selector, meta) {
            return
        }

        if try networkMessage(receiver, className, selector, meta) {
            return
        }

        if !meta, className == "NSURLSessionConfiguration" || className == "NSOperationQueue"
            || className == "NSCache" {
            guard let instance = object else {
                throw StoreRuntimeError.failure("unknown configuration receiver")
            }

            if selector.hasPrefix("set"), selector.hasSuffix(":"),
               selector.filter({ $0 == ":" }).count == 1 {
                var key = String(selector.dropFirst(3).dropLast())
                guard let firstCharacter = key.first else {
                    throw StoreRuntimeError.failure("unsupported setter \(selector)")
                }

                if key.count < 2 {
                    key = String(firstCharacter).lowercased()
                } else if let secondCharacter = key.dropFirst().first,
                          !(secondCharacter >= "A" && secondCharacter <= "Z") {
                    key = String(firstCharacter).lowercased() + key.dropFirst()
                }

                instance.properties[key] = try arg(2)
                try set(0)

                return
            }

            if let value = instance.properties[selector], value != 0 {
                try set(value)

                return
            }
        }

        if selector == "initWithObjectsAndKeys:"
            || (meta && selector == "dictionaryWithObjectsAndKeys:") {
            var values: [String: UInt64] = [:]
            var value = try arg(2)
            let stackPointer = try engine.regRead(ucRegSP)

            var index: UInt64 = 0
            while value != 0 {
                guard index <= 1024 else {
                    throw StoreRuntimeError.failure("dictionary varargs exceeds budget")
                }

                let key = try read64(stackPointer + index * 16)
                values[collectionKey(key)] = value
                value = try read64(stackPointer + index * 16 + 8)
                index += 1
            }

            if meta {
                try set(try newObject(className, .dictionary(values)))
            } else {
                guard let instance = object else {
                    throw StoreRuntimeError.failure("unknown dictionary receiver")
                }

                instance.value = .dictionary(values)
                try set(receiver)
            }

            return
        }

        if meta {
            switch selector {
            case "instanceMethodForSelector:":
                try set(lookup(className, try cstring(try arg(2)), false))

                return
            case "alloc", "allocWithZone:":
                try set(try newObject(className, .none))

                return
            case "new":
                let instance = try newObject(className, .none)
                try set(instance)
                try message(instance, "init", false)

                return
            case "isSubclassOfClass:":
                try set(boolValue(try kindOf(className, classNames[try arg(2)] ?? "")))

                return
            case "class":
                try set(receiver)

                return
            case "setWithObjects:", "arrayWithObjects:":
                var items: [UInt64] = []
                let first = try arg(2)
                if first != 0 {
                    items.append(first)
                    let stackPointer = try engine.regRead(ucRegSP)
                    for index in UInt64(0) ..< 1024 {
                        let value = try read64(stackPointer + index * 8)
                        if value == 0 {
                            break
                        }

                        items.append(value)
                    }
                }

                try set(try newObject(className, .array(items)))

                return
            case "dictionaryWithDictionary:":
                guard let source = objects[try arg(2)], case let .dictionary(fields) = source.value else {
                    throw StoreRuntimeError.failure("dictionaryWithDictionary: source is not a dictionary")
                }

                try set(try newObject(className, .dictionary(fields)))

                return
            case "fileURLWithPath:", "fileURLWithPath:isDirectory:":
                let path = try guestString(try arg(2))
                var components = URLComponents()
                components.scheme = "file"
                components.path = path
                let value = components.string ?? ("file://" + path)
                try set(try newObject("NSURL", .string(value)))

                return
            case "URLWithString:":
                try set(try newObject("NSURL", .string(try guestString(try arg(2)))))

                return
            case "setWithObject:", "arrayWithObject:":
                try set(try newObject(className, .array([try arg(2)])))

                return
            case "setWithArray:":
                var items: [UInt64] = []
                if try arg(2) != 0 {
                    guard let source = objects[try arg(2)], case let .array(values) = source.value else {
                        throw StoreRuntimeError.failure("setWithArray: source is not an array")
                    }

                    items = values
                }

                try set(try newObject(className, .array(items)))

                return
            case "UUID":
                try set(try newObject("NSUUID", .string(newUUIDString())))

                return
            case "distantPast":
                try set(try newObject("NSDate", .double(-62_135_769_600)))

                return
            case "distantFuture":
                let date = makeUTCDate(year: 4001, month: 1, day: 1, hour: 0, minute: 0, second: 0)
                try set(try newObject("NSDate", .double(date.timeIntervalSince1970)))

                return
            case "dateWithTimeIntervalSinceNow:", "dateWithTimeIntervalSince1970:":
                let bits = try engine.regRead(ucRegD0)
                var seconds = Double(bitPattern: bits)
                guard seconds.isFinite else {
                    throw StoreRuntimeError.failure("unsupported date interval")
                }

                if selector == "dateWithTimeIntervalSinceNow:" {
                    seconds += Date().timeIntervalSince1970
                }

                guard seconds > Double(Int64.min), seconds < Double(Int64.max) else {
                    throw StoreRuntimeError.failure("date interval exceeds supported range")
                }

                try set(try newObject("NSDate", .double(seconds)))

                return
            case "date", "now":
                try set(try newObject("NSDate", .double(Date().timeIntervalSince1970)))

                return
            case "defaultSessionConfiguration", "ephemeralSessionConfiguration":
                let configuration = try newObject("NSURLSessionConfiguration", .none)
                objects[configuration]?.properties = [
                    "usesClassicLoadingMode": 1,
                    "protocolClasses": try newObject("NSArray", .array([])),
                    "HTTPShouldSetCookies": 1,
                    "HTTPMaximumConnectionsPerHost": 6,
                ]
                try set(configuration)

                return
            case "interfaceWithProtocol:":
                try set(try newObject("NSXPCInterface", .none))

                return
            case "currentThread":
                try set(try newObject("NSThread", .none))

                return
            case "isMainThread":
                try set(1)

                return
            case "null":
                if nullObject == 0 {
                    nullObject = try newObject("NSNull", .none)
                }

                try set(nullObject)

                return
            case "standardUserDefaults":
                try set(try newObject("NSUserDefaults", .dictionary([:])))

                return
            case "preferredLanguages":
                try set(try newObject("NSArray", .array([
                    try newObject("NSString", .string("en-US")),
                ])))

                return
            case "decimalDigitCharacterSet":
                try set(try newObject("NSCharacterSet", .string("0123456789")))

                return
            case "characterSetWithCharactersInString:":
                try set(try newObject("NSCharacterSet", .string(try guestString(try arg(2)))))

                return
            case "currentLocale", "systemLocale":
                try set(try newObject("NSLocale", .string("en_US")))

                return
            case "defaultManager":
                try set(try newObject("NSFileManager", .none))

                return
            case "bundleWithPath:":
                guard try guestString(try arg(2)) == "/System/Library/Frameworks/WebKit.framework" else {
                    try set(0)

                    return
                }

                let bundle = try newObject("NSBundle", .none)
                objects[bundle]?.properties = [
                    "bundlePath": try arg(2),
                    "infoDictionary": try newObject("NSDictionary", .dictionary([
                        "CFBundleVersion": try newObject("NSString", .string("22625.1.29.11.28")),
                    ])),
                ]
                try set(bundle)

                return
            case "bundleForClass:":
                let bundle = try bundle()
                if (classNames[try arg(2)] ?? "").contains("AMS") {
                    objects[bundle]?.properties["bundleIdentifier"] = try newObject(
                        "NSString", .string("com.apple.AppleMediaServices")
                    )
                }

                try set(bundle)

                return
            case "mainBundle":
                try set(try bundle())

                return
            case "processInfo":
                let processInfo = try newObject("NSProcessInfo", .none)
                objects[processInfo]?.properties = [
                    "processName": try newObject("NSString", .string("ipatool")),
                    "environment": try newObject("NSDictionary", .dictionary([:])),
                ]
                try set(processInfo)

                return
            case "dictionary", "dictionaryWithCapacity:":
                try set(try newObject(className, .dictionary([:])))

                return
            case "weakToStrongObjectsMapTable", "weakToWeakObjectsMapTable",
                 "strongToWeakObjectsMapTable", "strongToStrongObjectsMapTable":
                try set(try newObject("NSMapTable", .dictionary([:])))

                return
            case "set", "setWithCapacity:", "array", "arrayWithCapacity:":
                try set(try newObject(className, .array([])))

                return
            case "numberWithDouble:", "numberWithFloat:":
                let bits = try engine.regRead(ucRegD0)
                var value = Double(bitPattern: bits)
                if selector == "numberWithFloat:" {
                    value = Double(Float(bitPattern: UInt32(truncatingIfNeeded: bits)))
                }

                try set(try newObject("NSNumber", .double(value)))

                return
            case "numberWithBool:":
                try set(try newObject("NSNumber", .bool(try arg(2) != 0)))

                return
            case "numberWithInteger:", "numberWithInt:", "numberWithUnsignedInteger:",
                 "numberWithLongLong:", "numberWithUnsignedLongLong:":
                try set(try newObject("NSNumber", .int(Int64(bitPattern: try arg(2)))))

                return
            case "dictionaryWithObjects:forKeys:count:":
                let values = try arg(2)
                let keys = try arg(3)
                let count = try arg(4)
                guard count <= 65536 else {
                    throw StoreRuntimeError.failure("guest dictionary exceeds runtime limit")
                }

                var fields: [String: UInt64] = [:]
                for index in UInt64(0) ..< count {
                    fields[try guestString(try read64(keys + index * 8))] = try read64(values + index * 8)
                }

                try set(try newObject("NSDictionary", .dictionary(fields)))

                return
            case "setWithObjects:count:", "arrayWithObjects:count:":
                let values = try arg(2)
                let count = try arg(3)
                guard count <= 65536 else {
                    throw StoreRuntimeError.failure("guest array exceeds runtime limit")
                }

                var items: [UInt64] = []
                items.reserveCapacity(Int(count))
                for index in UInt64(0) ..< count {
                    items.append(try read64(values + index * 8))
                }

                try set(try newObject(className, .array(items)))

                return
            case "stringWithFormat:":
                try set(try newObject("NSString", .string(try format(try guestString(try arg(2))))))

                return
            case "stringWithUTF8String:":
                try set(try newObject("NSString", .string(try cstring(try arg(2)))))

                return
            case "errorWithDomain:code:userInfo:":
                try set(try newObject("NSError", .dictionary([
                    "domain": try arg(2),
                    "code": try newObject("NSNumber", .int(Int64(bitPattern: try arg(3)))),
                    "userInfo": try arg(4),
                ])))

                return
            default:
                throw StoreRuntimeError.failure(
                    "unsupported class message \(profileMethodKey(className, selector, true))"
                )
            }
        }

        guard let instance = object else {
            throw StoreRuntimeError.failure("unknown receiver \(String(receiver, radix: 16)) for \(selector)")
        }

        switch selector {
        case "initWithMachServiceName:options:":
            instance.properties["serviceName"] = try arg(2)
            try set(receiver)
        case "_setQueue:":
            instance.properties["queue"] = try arg(2)
            try set(0)
        case "setRemoteObjectInterface:":
            instance.properties["interface"] = try arg(2)
            try set(0)
        case "setInterruptionHandler:", "setInvalidationHandler:":
            let target = instance
            try copyBlock(try arg(2)) { [unowned self] block in
                target.properties[selector] = block
                try self.set(0)
            }
        case "remoteObjectProxyWithErrorHandler:":
            try copyBlock(try arg(2)) { [unowned self] block in
                let proxy = try self.newObject("HostUnavailableProxy", .none)
                self.objects[proxy]?.properties["errorBlock"] = block
                try self.set(proxy)
            }
        case "resume", "invalidate", "setClass:forSelector:argumentIndex:ofReply:",
             "setClasses:forSelector:argumentIndex:ofReply:",
             "setInterface:forSelector:argumentIndex:ofReply:":
            guard className == "NSXPCConnection" || className == "NSXPCInterface" else {
                throw StoreRuntimeError.failure("unsupported message \(className) \(selector)")
            }

            try set(0)
        case "addOperationWithBlock:":
            try copyBlock(try arg(2)) { [unowned self] block in
                self.queuePending(block, receiver)
                try self.set(0)
            }
        case "lock", "unlock", "signal", "broadcast":
            guard className == "NSCondition" || className == "NSLock" || className == "NSRecursiveLock" else {
                throw StoreRuntimeError.failure("unsupported lock receiver \(className)")
            }

            try set(0)
        case "wait", "waitUntilDate:":
            guard className == "NSCondition", !pending.isEmpty else {
                throw StoreRuntimeError.failure("guest condition has no runnable callback")
            }

            let block = nextPending()
            guard block != 0 else {
                throw StoreRuntimeError.failure("all pending queues are suspended")
            }

            try pendingCallback(block) { [unowned self] in
                try self.set(1)
            }
        case "createDirectoryAtURL:withIntermediateDirectories:attributes:error:",
             "createDirectoryAtPath:withIntermediateDirectories:attributes:error:":
            let out = try arg(5)
            if out != 0 {
                try write64(out, try newObject("NSError", .dictionary([
                    "domain": try newObject("NSString", .string("NSCocoaErrorDomain")),
                    "code": try newObject("NSNumber", .int(513)),
                    "userInfo": try newObject("NSDictionary", .dictionary([:])),
                ])))
            }

            try set(0)
        case "isWritableFileAtPath:", "fileExistsAtPath:", "fileExistsAtPath:isDirectory:":
            if selector == "fileExistsAtPath:isDirectory:", try arg(3) != 0 {
                try memWrite(try arg(3), [0])
            }

            try set(0)
        case "URLsForDirectory:inDomains:":
            guard className == "NSFileManager" else {
                throw StoreRuntimeError.failure("invalid file-manager receiver")
            }

            try set(try newObject("NSArray", .array([
                try newObject("NSURL", .string("file:///ipatool/cache/")),
            ])))
        case "URLForDirectory:inDomain:appropriateForURL:create:error:":
            try set(try newObject("NSURL", .string("file:///ipatool/cache/")))
        case "threadDictionary":
            if instance.properties[selector] == nil || instance.properties[selector] == 0 {
                instance.properties[selector] = try newObject("NSMutableDictionary", .dictionary([:]))
            }

            try set(instance.properties[selector] ?? 0)
        case "boolForKey:":
            var value: UInt64 = 0
            if case let .dictionary(fields) = instance.value {
                value = fields[try guestString(try arg(2))] ?? 0
            }

            if value == 0 {
                try set(0)
            } else {
                try message(value, "boolValue", false)
            }
        case "operatingSystemVersion":
            let out = try engine.regRead(ucRegX0 + 8)
            try write64(out, 27)
            try write64(out + 8, 0)
            try write64(out + 16, 1)
        case "operatingSystemVersionString":
            try set(try newObject("NSString", .string("Version 27.0.1 (Build 26A434)")))
        case "initWithTimeIntervalSince1970:":
            guard className == "NSDate" else {
                throw StoreRuntimeError.failure("unsupported date initializer")
            }

            let bits = try engine.regRead(ucRegD0)
            instance.value = .double(Double(bitPattern: bits))
            try set(receiver)
        case "initWithBytesNoCopy:length:encoding:freeWhenDone:":
            guard try kindOf(className, "NSString"),
                  try arg(4) == 4 || arg(4) == 1,
                  try arg(3) <= 1 << 20 else {
                throw StoreRuntimeError.failure("unsupported string buffer initialization")
            }

            let data = try engine.memRead(try arg(2), try arg(3))
            instance.value = .string(String(decoding: data, as: UTF8.self))
            try set(receiver)
        case "initWithBytesNoCopy:length:freeWhenDone:":
            guard try kindOf(className, "NSData"), try arg(3) <= 1 << 20 else {
                throw StoreRuntimeError.failure("unsupported data buffer initialization")
            }

            let data = try engine.memRead(try arg(2), try arg(3))
            instance.value = .data(data)
            try set(receiver)
        case "timeIntervalSinceDate:":
            guard case let .double(date) = instance.value,
                  let otherObject = objects[try arg(2)],
                  case let .double(other) = otherObject.value else {
                throw StoreRuntimeError.failure("timeIntervalSinceDate: on non-date")
            }

            try engine.regWrite(ucRegD0, (date - other).bitPattern)
        case "timeIntervalSinceNow", "timeIntervalSince1970", "timeIntervalSinceReferenceDate":
            guard case let .double(date) = instance.value else {
                throw StoreRuntimeError.failure("time interval on non-date")
            }

            var seconds = date
            switch selector {
            case "timeIntervalSinceNow":
                seconds = date - Date().timeIntervalSince1970
            case "timeIntervalSinceReferenceDate":
                seconds -= 978_307_200
            default:
                break
            }

            try engine.regWrite(ucRegD0, seconds.bitPattern)
        case "localizedStringForKey:value:table:":
            guard className == "NSBundle" else {
                throw StoreRuntimeError.failure("unsupported localization receiver")
            }

            // No bundle resource files are mounted in this runtime. Foundation's
            // documented fallback is the supplied value, then the key itself.
            let value = try arg(3)
            if value != 0, try guestString(value) != "" {
                try set(value)
            } else {
                try set(try arg(2))
            }
        case "localeIdentifier":
            try set(try newObject("NSString", .string("en_US")))
        case "languageCode":
            try set(try newObject("NSString", .string("en")))
        case "infoDictionary":
            if let value = instance.properties["infoDictionary"], value != 0 {
                try set(value)
            } else {
                try set(try bundleInfo())
            }
        case "executableURL", "bundleURL":
            try set(try newObject("NSURL", .string("file:///ipatool")))
        case "bundleIdentifier", "bundlePath", "processName", "environment":
            try set(instance.properties[selector] ?? 0)
        case "objectForInfoDictionaryKey:":
            var pointer = instance.properties["infoDictionary"] ?? 0
            if pointer == 0 {
                pointer = try bundleInfo()
            }

            guard let infoObject = objects[pointer], case let .dictionary(info) = infoObject.value else {
                throw StoreRuntimeError.failure("info dictionary is not a dictionary")
            }

            try set(info[try guestString(try arg(2))] ?? 0)
        case "initWithCapacity:":
            if className == "NSMutableString" {
                instance.value = .string("")
            } else if className.contains("Array") {
                instance.value = .array([])
            } else {
                instance.value = .dictionary([:])
            }

            try set(receiver)
        case "appendFormat:":
            instance.value = .string(try guestString(receiver) + (try format(try guestString(try arg(2)))))
            try set(0)
        case "init":
            if case .none = instance.value {
                switch className {
                case "NSString", "NSMutableString":
                    instance.value = .string("")
                case "NSCache", "NSDictionary", "NSMutableDictionary":
                    instance.value = .dictionary([:])
                case "NSArray", "NSMutableArray", "NSSet", "NSMutableSet",
                     "NSOrderedSet", "NSMutableOrderedSet":
                    instance.value = .array([])
                default:
                    break
                }
            }

            try set(receiver)
        case "containsObject:":
            guard case let .array(items) = instance.value else {
                throw StoreRuntimeError.failure("containsObject: on non-array")
            }

            let target = try arg(2)
            var match = false
            for item in items {
                if item == target {
                    match = true
                    continue
                }

                if let left = objects[item], let right = objects[target],
                   guestDescription(left.value) == guestDescription(right.value) {
                    match = true
                }
            }

            try set(boolValue(match))
        case "UUIDString":
            try set(try newObject("NSString", instance.value))
        case "initWithFormat:":
            instance.value = .string(try format(try guestString(try arg(2))))
            try set(receiver)
        case "initWithFormat:locale:arguments:":
            instance.value = .string(try formatAt(try guestString(try arg(2)), try arg(4)))
            try set(receiver)
        case "initWithString:":
            instance.value = .string(try guestString(try arg(2)))
            try set(receiver)
        case "stringByAppendingPathComponent:":
            try set(try newObject("NSString", .string(
                storePathJoin(try guestString(receiver), try guestString(try arg(2)))
            )))
        case "stringByDeletingPathExtension":
            let value = try guestString(receiver)
            let suffix = storePathExtension(value)
            let trimmed = value.hasSuffix(suffix) ? String(value.dropLast(suffix.count)) : value
            try set(try newObject("NSString", .string(trimmed)))
        case "componentsJoinedByString:":
            guard case let .array(items) = instance.value else {
                throw StoreRuntimeError.failure("componentsJoinedByString: on non-array")
            }

            var parts: [String] = []
            parts.reserveCapacity(items.count)
            for item in items {
                parts.append(try guestString(item))
            }

            try set(try newObject("NSString", .string(
                parts.joined(separator: try guestString(try arg(2)))
            )))
        case "componentsSeparatedByString:":
            let parts = try guestString(receiver).components(separatedBy: try guestString(try arg(2)))
            var items: [UInt64] = []
            items.reserveCapacity(parts.count)
            for part in parts {
                items.append(try newObject("NSString", .string(part)))
            }

            try set(try newObject("NSArray", .array(items)))
        case "sortedArrayUsingComparator:":
            guard case let .array(original) = instance.value else {
                throw StoreRuntimeError.failure("sortedArrayUsingComparator: on non-array")
            }

            var items = original
            guard items.count <= 4096 else {
                throw StoreRuntimeError.failure("sort exceeds runtime budget")
            }

            let block = try arg(2)
            var i = 1
            var j = 1

            func next() throws {
                if i >= items.count {
                    try set(try newObject("NSArray", .array(items)))

                    return
                }

                if j == 0 {
                    i += 1
                    j = i
                    try next()

                    return
                }

                try callback(block, [items[j - 1], items[j]]) { [unowned self] in
                    if Int64(bitPattern: try self.arg(0)) > 0 {
                        items.swapAt(j - 1, j)
                        j -= 1
                    } else {
                        i += 1
                        j = i
                    }

                    try next()
                }
            }

            try next()
        case "compare:":
            if try kindOf(className, "NSDate") {
                guard case let .double(date) = instance.value,
                      let otherObject = objects[try arg(2)],
                      case let .double(other) = otherObject.value else {
                    throw StoreRuntimeError.failure("compare: on non-date")
                }

                let result: Int64 = date < other ? -1 : (date > other ? 1 : 0)
                try set(UInt64(bitPattern: result))

                return
            }

            let result = byteCompareStrings(try guestString(receiver), try guestString(try arg(2)))
            try set(UInt64(bitPattern: result))
        case "allObjects":
            guard case let .array(items) = instance.value else {
                throw StoreRuntimeError.failure("allObjects on non-array")
            }

            try set(try newObject("NSArray", .array(items)))
        case "firstObject", "lastObject":
            guard case let .array(items) = instance.value else {
                throw StoreRuntimeError.failure("firstObject on non-array")
            }

            if items.isEmpty {
                try set(0)
            } else if selector == "firstObject" {
                try set(items[0])
            } else {
                try set(items[items.count - 1])
            }
        case "objectAtIndex:", "objectAtIndexedSubscript:":
            guard case let .array(items) = instance.value else {
                throw StoreRuntimeError.failure("objectAtIndex: on non-array")
            }

            let index = Int(try arg(2))
            guard index < items.count else {
                throw StoreRuntimeError.failure("array index out of bounds")
            }

            try set(items[index])
        case "removeObjectsInArray:", "removeObject:":
            if try arg(2) == 0 {
                try set(0)

                return
            }

            guard case let .array(current) = instance.value else {
                throw StoreRuntimeError.failure("removeObject: on non-array")
            }

            var remove = [try arg(2)]
            if selector == "removeObjectsInArray:" {
                guard let source = objects[try arg(2)], case let .array(values) = source.value else {
                    throw StoreRuntimeError.failure("removeObjectsInArray: on non-array")
                }

                remove = values
            }

            var items: [UInt64] = []
            for item in current {
                var found = false
                for candidate in remove {
                    if foundationEqual(item, candidate) {
                        found = true
                    }
                }

                if !found {
                    items.append(item)
                }
            }

            instance.value = .array(items)
            try set(0)
        case "addObjectsFromArray:":
            guard case let .array(current) = instance.value,
                  let source = objects[try arg(2)],
                  case let .array(values) = source.value else {
                throw StoreRuntimeError.failure("addObjectsFromArray: on non-array")
            }

            instance.value = .array(current + values)
            try set(0)
        case "removeObjectAtIndex:":
            guard case let .array(items) = instance.value else {
                throw StoreRuntimeError.failure("removeObjectAtIndex: on non-array")
            }

            let index = Int(try arg(2))
            guard index < items.count else {
                throw StoreRuntimeError.failure("array removal index out of bounds")
            }

            var result = items
            result.remove(at: index)
            instance.value = .array(result)
            try set(0)
        case "addObject:":
            guard case let .array(items) = instance.value else {
                throw StoreRuntimeError.failure("addObject: on non-array")
            }

            instance.value = .array(items + [try arg(2)])
            try set(0)
        case "path", "lastPathComponent":
            guard case let .string(text) = instance.value else {
                throw StoreRuntimeError.failure("path on non-string")
            }

            var value = text
            if className == "NSURL" {
                guard let parsed = URL(string: text) else {
                    throw StoreRuntimeError.failure("invalid URL \(text)")
                }

                value = parsed.path
            }

            if selector == "lastPathComponent" {
                value = storePathBase(value)
            }

            try set(try newObject("NSString", .string(value)))
        case "absoluteString":
            guard case let .string(text) = instance.value else {
                throw StoreRuntimeError.failure("absoluteString on non-string")
            }

            try set(try newObject("NSString", .string(text)))
        case "stringValue":
            try set(try newObject("NSString", .string(guestDescription(instance.value))))
        case "description":
            guard try kindOf(className, "NSString") else {
                throw StoreRuntimeError.failure(
                    "unsupported instance message \(profileMethodKey(className, selector, false))"
                )
            }

            try set(receiver)
        case "lowercaseString":
            try set(try newObject("NSString", .string(try guestString(receiver).lowercased())))
        case "uppercaseString":
            try set(try newObject("NSString", .string(try guestString(receiver).uppercased())))
        case "appendString:":
            instance.value = .string(try guestString(receiver) + (try guestString(try arg(2))))
            try set(0)
        case "stringByAppendingString:":
            try set(try newObject("NSString", .string(
                try guestString(receiver) + (try guestString(try arg(2)))
            )))
        case "initWithDomain:code:userInfo:":
            instance.value = .dictionary([
                "domain": try arg(2),
                "code": try newObject("NSNumber", .int(Int64(bitPattern: try arg(3)))),
                "userInfo": try arg(4),
            ])
            try set(receiver)
        case "copy":
            let entry = lookup(className, "copyWithZone:", false)
            if entry != 0 {
                try engine.regWrite(ucRegX0 + 2, 0)
                try jump(entry, receiver, "copyWithZone:")
            } else {
                try set(try foundationCopy(receiver, false))
            }
        case "retain", "autorelease", "copyWithZone:":
            try set(receiver)
        case "mutableCopy", "mutableCopyWithZone:":
            if case let .dictionary(fields) = instance.value {
                try set(try newObject("NSMutableDictionary", .dictionary(fields)))
            } else {
                try set(try newObject(className, instance.value))
            }
        case "release":
            try set(0)
        case "class":
            guard let klass = classes[className] else {
                throw StoreRuntimeError.failure("unknown class \(className)")
            }

            try set(klass.Address)
        case "isKindOfClass:":
            try set(boolValue(try kindOf(className, classNames[try arg(2)] ?? "")))
        case "isEqualToDate:", "isEqual:", "isEqualToString:", "isEqualToDictionary:", "isEqualToArray:":
            try set(boolValue(foundationEqual(receiver, try arg(2))))
        case "length", "count":
            switch instance.value {
            case let .string(text):
                try set(UInt64(text.utf8.count))
            case let .data(data):
                try set(UInt64(data.count))
            case let .array(items):
                try set(UInt64(items.count))
            case let .dictionary(fields):
                try set(UInt64(fields.count))
            default:
                throw StoreRuntimeError.failure("count of \(className)")
            }
        case "valueForKey:", "__swift_objectForKeyedSubscript:", "objectForKey:",
             "objectForKeyedSubscript:":
            guard case let .dictionary(fields) = instance.value else {
                throw StoreRuntimeError.failure("dictionary access on \(className)")
            }

            try set(fields[collectionKey(try arg(2))] ?? 0)
        case "setObject:forKey:cost:", "setValue:forKey:", "setObject:forKey:",
             "setObject:forKeyedSubscript:":
            guard case let .dictionary(current) = instance.value else {
                throw StoreRuntimeError.failure("dictionary mutation on \(className)")
            }

            var fields = current
            let key = collectionKey(try arg(3))
            if try arg(2) == 0 {
                fields.removeValue(forKey: key)
            } else {
                fields[key] = try arg(2)
            }

            instance.value = .dictionary(fields)
            try set(0)
        case "countByEnumeratingWithState:objects:count:":
            let state = try arg(2)
            let buffer = try arg(3)
            let limit = try arg(4)
            guard limit <= 100_000 else {
                throw StoreRuntimeError.failure("enumeration limit too large")
            }

            var items: [UInt64] = []
            switch instance.value {
            case let .array(values):
                items = values
            case let .dictionary(fields):
                for key in fields.keys.sorted() {
                    items.append(try newObject("NSString", .string(key)))
                }
            default:
                throw StoreRuntimeError.failure("invalid collection")
            }

            let index = try read64(state)
            if index >= UInt64(items.count) {
                try set(0)

                return
            }

            let count = min(limit, UInt64(items.count) - index)
            for offset in UInt64(0) ..< count {
                try write64(buffer + offset * 8, items[Int(index + offset)])
            }

            if instance.properties["mutationCounter"] == nil || instance.properties["mutationCounter"] == 0 {
                instance.properties["mutationCounter"] = try alloc(8)
            }

            try write64(state, index + count)
            try write64(state + 8, buffer)
            try write64(state + 16, instance.properties["mutationCounter"] ?? 0)
            try set(count)
        case "enumerateKeysAndObjectsUsingBlock:":
            guard case let .dictionary(fields) = instance.value else {
                throw StoreRuntimeError.failure("enumerateKeysAndObjectsUsingBlock: on non-dictionary")
            }

            let keys = fields.keys.sorted()
            let block = try arg(2)
            let stop = try alloc(8)
            var index = 0

            func next() throws {
                let stopped = try read64(stop) != 0
                if index == keys.count || stopped {
                    try set(0)

                    return
                }

                let key = keys[index]
                index += 1

                try callback(block, [
                    try newObject("NSString", .string(key)),
                    fields[key] ?? 0,
                    stop,
                ], next)
            }

            try next()
        case "allValues":
            guard case let .dictionary(fields) = instance.value else {
                throw StoreRuntimeError.failure("allValues on non-dictionary")
            }

            var items: [UInt64] = []
            for key in fields.keys.sorted() {
                items.append(fields[key] ?? 0)
            }

            try set(try newObject("NSArray", .array(items)))
        case "allKeys":
            guard case let .dictionary(fields) = instance.value else {
                throw StoreRuntimeError.failure("allKeys on non-dictionary")
            }

            var items: [UInt64] = []
            for key in fields.keys.sorted() {
                items.append(try newObject("NSString", .string(key)))
            }

            try set(try newObject("NSArray", .array(items)))
        case "doubleValue", "floatValue":
            var value: Double
            switch instance.value {
            case let .double(number):
                value = number
            case let .int(number):
                value = Double(number)
            case let .bool(flag):
                value = Double(boolValue(flag))
            case let .string(text):
                value = Double(text) ?? 0
            default:
                throw StoreRuntimeError.failure("unsupported numeric conversion")
            }

            var bits = value.bitPattern
            if selector == "floatValue" {
                bits = UInt64(Float(value).bitPattern)
            }

            try engine.regWrite(ucRegD0, bits)
        case "integerValue", "intValue", "longLongValue", "unsignedIntegerValue",
             "unsignedLongLongValue", "boolValue":
            var value: Int64 = 0
            switch instance.value {
            case let .double(number):
                value = Int64(number)
                if selector == "boolValue" {
                    value = Int64(boolValue(number != 0))
                }
            case let .int(number):
                value = number
            case let .string(text):
                value = Int64(text) ?? 0
            case let .bool(flag):
                if flag {
                    value = 1
                }
            default:
                break
            }

            try set(UInt64(bitPattern: value))
        case "localizedDescription", "localizedFailureReason", "localizedRecoverySuggestion":
            guard try kindOf(className, "NSError") else {
                throw StoreRuntimeError.failure("unsupported localized error receiver")
            }

            guard case let .dictionary(fields) = instance.value else {
                throw StoreRuntimeError.failure("error is not a dictionary")
            }

            let key: String
            switch selector {
            case "localizedDescription":
                key = "NSLocalizedDescription"
            case "localizedFailureReason":
                key = "NSLocalizedFailureReason"
            default:
                key = "NSLocalizedRecoverySuggestion"
            }

            var value: UInt64 = 0
            if let info = objects[fields["userInfo"] ?? 0], case let .dictionary(infoFields) = info.value {
                value = infoFields[key] ?? 0
            }

            if value == 0, selector == "localizedDescription" {
                let domain = try guestString(fields["domain"] ?? 0)
                guard let codeObject = objects[fields["code"] ?? 0], case let .int(code) = codeObject.value else {
                    throw StoreRuntimeError.failure("error code is not an integer")
                }

                value = try newObject("NSString", .string("\(domain) error \(code)"))
            }

            try set(value)
        case "domain", "userInfo", "code":
            guard case let .dictionary(fields) = instance.value else {
                throw StoreRuntimeError.failure("error field access on non-dictionary")
            }

            var value = fields[selector] ?? 0
            if selector == "code" {
                guard let codeObject = objects[value], case let .int(number) = codeObject.value else {
                    throw StoreRuntimeError.failure("error code is not an integer")
                }

                value = UInt64(bitPattern: number)
            }

            try set(value)
        case "cStringUsingEncoding:", "UTF8String":
            let value = try guestString(receiver)
            let address = try alloc(UInt64(value.utf8.count + 1))
            try memWrite(address, Array(value.utf8) + [0])
            try set(address)
        case "dataUsingEncoding:":
            var data: [UInt8] = []
            switch try arg(2) {
            case 4: // NSUTF8StringEncoding.
                data = Array(try guestString(receiver).utf8)
            case 10: // NSUnicodeStringEncoding, native ARM64 byte order with BOM.
                let words = Array(try guestString(receiver).utf16)
                data = [0xff, 0xfe]
                for word in words {
                    data.append(UInt8(truncatingIfNeeded: word))
                    data.append(UInt8(truncatingIfNeeded: word >> 8))
                }
            default:
                throw StoreRuntimeError.failure("unsupported string encoding \(try arg(2))")
            }

            try set(try newObject("NSData", .data(data)))
        case "base64EncodedStringWithOptions:":
            guard try kindOf(className, "NSData") else {
                throw StoreRuntimeError.failure("base64 encoding on \(className)")
            }

            guard case let .data(data) = instance.value else {
                throw StoreRuntimeError.failure("base64 encoding on non-data object")
            }

            try set(try newObject("NSString", .string(Data(data).base64EncodedString())))
        case "removeAllObjects":
            switch instance.value {
            case .array:
                instance.value = .array([])
            case .dictionary:
                instance.value = .dictionary([:])
            default:
                throw StoreRuntimeError.failure("removeAllObjects on \(className)")
            }

            try set(0)
        case "removeObjectForKey:":
            guard case let .dictionary(current) = instance.value else {
                throw StoreRuntimeError.failure("removeObjectForKey: on non-dictionary")
            }

            var fields = current
            fields.removeValue(forKey: collectionKey(try arg(2)))
            instance.value = .dictionary(fields)
            try set(0)
        case "addEntriesFromDictionary:":
            guard case let .dictionary(current) = instance.value,
                  let source = objects[try arg(2)],
                  case let .dictionary(values) = source.value else {
                throw StoreRuntimeError.failure("addEntriesFromDictionary: on non-dictionary")
            }

            var fields = current
            for (key, value) in values {
                fields[key] = value
            }

            instance.value = .dictionary(fields)
            try set(0)
        case "initWithArray:":
            guard let source = objects[try arg(2)], case let .array(values) = source.value else {
                throw StoreRuntimeError.failure("initWithArray: source is not an array")
            }

            instance.value = .array(values)
            try set(receiver)
        case "initWithDictionary:":
            guard let source = objects[try arg(2)], case let .dictionary(values) = source.value else {
                throw StoreRuntimeError.failure("initWithDictionary: source is not a dictionary")
            }

            instance.value = .dictionary(values)
            try set(receiver)
        case "initWithDictionary:copyItems:":
            try initializeDictionary(receiver, try arg(2), try arg(3) != 0)
        case "rangeOfString:options:", "rangeOfString:":
            var value = try guestString(receiver)
            var needle = try guestString(try arg(2))
            var options: UInt64 = 0
            if selector == "rangeOfString:options:" {
                options = try arg(3)
            }

            if options & 1 != 0 {
                value = value.lowercased()
                needle = needle.lowercased()
            }

            var found: Range<String.Index>?
            if options & 4 != 0 {
                found = value.range(of: needle, options: .backwards)
            } else {
                found = value.range(of: needle)
            }

            var start = UInt64(0x7fff_ffff_ffff_ffff)
            var length: UInt64 = 0
            if let found {
                start = UInt64(value[..<found.lowerBound].utf16.count)
                length = UInt64(value[found].utf16.count)
            }

            try set(start)
            try engine.regWrite(ucRegX0 + 1, length)
        case "invertedSet":
            let characterSet = try newObject("NSCharacterSet", instance.value)
            objects[characterSet]?.properties["inverted"] = 1 - (instance.properties["inverted"] ?? 0)
            try set(characterSet)
        case "stringByTrimmingCharactersInSet:":
            let characterSet = objects[try arg(2)]
            let characters = Array(try guestString(receiver))
            var start = 0
            var end = characters.count
            while start < end, try characterSetContains(characterSet, characters[start]) {
                start += 1
            }

            while end > start, try characterSetContains(characterSet, characters[end - 1]) {
                end -= 1
            }

            try set(try newObject("NSString", .string(String(characters[start ..< end]))))
        case "rangeOfCharacterFromSet:", "rangeOfCharacterFromSet:options:":
            let characterSet = objects[try arg(2)]
            var options: UInt64 = 0
            if selector == "rangeOfCharacterFromSet:options:" {
                options = try arg(3)
            }

            var start = UInt64(0x7fff_ffff_ffff_ffff)
            var length: UInt64 = 0
            var offset: UInt64 = 0

            for character in try guestString(receiver) {
                let count = UInt64(String(character).utf16.count)
                if try characterSetContains(characterSet, character) {
                    start = offset
                    length = count

                    if options & 4 == 0 {
                        break
                    }
                }

                offset += count
            }

            try set(start)
            try engine.regWrite(ucRegX0 + 1, length)
        case "substringFromIndex:", "substringToIndex:", "substringWithRange:":
            let value = Array(try guestString(receiver).utf16)
            var start = 0
            var end = value.count

            switch selector {
            case "substringFromIndex:":
                start = Int(try arg(2))
            case "substringToIndex:":
                end = Int(try arg(2))
            default:
                start = Int(try arg(2))
                end = start + Int(try arg(3))
            }

            guard end <= value.count, start <= end, start >= 0 else {
                throw StoreRuntimeError.failure("substring range exceeds string")
            }

            try set(try newObject("NSString", .string(String(decoding: value[start ..< end], as: UTF16.self))))
        case "hasSuffix:":
            try set(boolValue(try guestString(receiver).hasSuffix(try guestString(try arg(2)))))
        case "containsString:":
            try set(boolValue(try guestString(receiver).range(of: try guestString(try arg(2))) != nil))
        case "caseInsensitiveCompare:":
            let result = byteCompareStrings(
                try guestString(receiver).lowercased(),
                try guestString(try arg(2)).lowercased()
            )
            try set(UInt64(bitPattern: result))
        case "hasPrefix:":
            try set(boolValue(try guestString(receiver).hasPrefix(try guestString(try arg(2)))))
        default:
            throw StoreRuntimeError.failure(
                "unsupported instance message \(profileMethodKey(className, selector, false))"
            )
        }
    }

    func responds(_ receiver: UInt64, _ selector: String) throws -> Bool {
        if receiver == 0 {
            return false
        }

        var className = classNames[receiver] ?? ""
        let meta = classNames[receiver] != nil
        let object = objects[receiver]

        if !meta {
            guard let instance = object else {
                return false
            }

            className = instance.cls
        }

        if lookup(className, selector, meta) != 0 {
            return true
        }

        if meta {
            return selector == "class" || selector == "alloc" || selector == "new"
        }

        switch selector {
        case "class", "retain", "release", "autorelease", "copy", "mutableCopy",
             "isKindOfClass:", "isEqual:", "respondsToSelector:":
            return true
        default:
            break
        }

        guard let value = object?.value else {
            return false
        }

        switch value {
        case .string:
            switch selector {
            case "length", "isEqualToString:", "hasPrefix:", "UTF8String", "integerValue",
                 "intValue", "longLongValue", "unsignedIntegerValue",
                 "unsignedLongLongValue", "boolValue":
                return true
            default:
                return false
            }
        case .int:
            switch selector {
            case "integerValue", "intValue", "longLongValue", "unsignedIntegerValue",
                 "unsignedLongLongValue", "boolValue":
                return true
            default:
                return false
            }
        case .dictionary:
            switch selector {
            case "count", "objectForKey:", "objectForKeyedSubscript:", "allKeys",
                 "setObject:forKey:", "setObject:forKeyedSubscript:":
                return true
            default:
                return false
            }
        case .array, .data:
            return selector == "count" || selector == "length"
        default:
            return false
        }
    }

    func format(_ format: String) throws -> String {
        let stackPointer = try engine.regRead(ucRegSP)
        return try formatAt(format, stackPointer)
    }

    func formatAt(_ format: String, _ stackPointer: UInt64) throws -> String {
        let bytes = Array(format.utf8)
        var offset: UInt64 = 0
        var result: [UInt8] = []
        var index = 0

        while index < bytes.count {
            if bytes[index] != UInt8(ascii: "%") {
                result.append(bytes[index])
                index += 1
                continue
            }

            index += 1
            guard index < bytes.count else {
                throw StoreRuntimeError.failure("incomplete format")
            }

            if bytes[index] == UInt8(ascii: "%") {
                result.append(UInt8(ascii: "%"))
                index += 1
                continue
            }

            let widthStart = index
            while index < bytes.count, bytes[index] >= UInt8(ascii: "0"), bytes[index] <= UInt8(ascii: "9") {
                index += 1
            }

            let width = String(decoding: bytes[widthStart ..< index], as: UTF8.self)

            while index < bytes.count,
                  bytes[index] == UInt8(ascii: "l") || bytes[index] == UInt8(ascii: "z") {
                index += 1
            }

            guard index < bytes.count else {
                throw StoreRuntimeError.failure("invalid format")
            }

            let value = try read64(stackPointer + offset)
            offset += 8

            switch bytes[index] {
            case UInt8(ascii: "@"):
                if value == 0 {
                    result.append(contentsOf: Array("(null)".utf8))
                } else {
                    guard let object = objects[value] else {
                        throw StoreRuntimeError.failure(
                            "unknown format object \(String(value, radix: 16))"
                        )
                    }

                    result.append(contentsOf: Array(guestDescription(object.value).utf8))
                }
            case UInt8(ascii: "d"), UInt8(ascii: "i"):
                result.append(contentsOf: Array(String(Int64(bitPattern: value)).utf8))
            case UInt8(ascii: "u"):
                result.append(contentsOf: Array(String(value).utf8))
            case UInt8(ascii: "x"), UInt8(ascii: "X"), UInt8(ascii: "p"):
                let uppercase = bytes[index] == UInt8(ascii: "X")
                let prefix = bytes[index] == UInt8(ascii: "p")
                result.append(contentsOf: Array(
                    paddedHex(value, width: width, uppercase: uppercase, prefix: prefix).utf8
                ))
            case UInt8(ascii: "s"):
                result.append(contentsOf: Array(try cstring(value).utf8))
            default:
                throw StoreRuntimeError.failure("unsupported format \(format)")
            }

            index += 1
        }

        return String(decoding: result, as: UTF8.self)
    }

    func bundle() throws -> UInt64 {
        let object = try newObject("NSBundle", .none)
        objects[object]?.properties = [
            "bundleIdentifier": try newObject("NSString", .string("me.majd.ipatool")),
            "bundlePath": try newObject("NSString", .string("/ipatool")),
        ]
        return object
    }

    func bundleInfo() throws -> UInt64 {
        try newObject("NSDictionary", .dictionary([
            "CFBundleIdentifier": try newObject("NSString", .string("me.majd.ipatool")),
            "CFBundleVersion": try newObject("NSString", .string("1.0")),
            "CFBundleExecutable": try newObject("NSString", .string("ipatool")),
            "CFBundleName": try newObject("NSString", .string("ipatool")),
        ]))
    }

    func foundationCopy(_ receiver: UInt64, _ mutable: Bool) throws -> UInt64 {
        guard let object = objects[receiver] else {
            throw StoreRuntimeError.failure("copy of unknown object")
        }

        switch object.cls {
        case "NSArray", "NSMutableArray", "NSSet", "NSMutableSet":
            var className = object.cls.contains("Set") ? "NSSet" : "NSArray"
            if mutable {
                className = "NSMutable" + String(className.dropFirst(2))
            }

            guard case let .array(items) = object.value else {
                throw StoreRuntimeError.failure("copy of non-array collection")
            }

            return try newObject(className, .array(items))
        case "NSDictionary", "NSMutableDictionary":
            let className = mutable ? "NSMutableDictionary" : "NSDictionary"
            guard case let .dictionary(fields) = object.value else {
                throw StoreRuntimeError.failure("copy of non-dictionary collection")
            }

            return try newObject(className, .dictionary(fields))
        case "NSMutableString":
            return try newObject("NSString", object.value)
        default:
            return receiver
        }
    }

    /// copyItems copies each immediate value, using its native copyWithZone: when
    /// available. Nested collection contents remain shared, as in Foundation.
    func initializeDictionary(_ receiver: UInt64, _ source: UInt64, _ copyItems: Bool) throws {
        guard let sourceObject = objects[source], case let .dictionary(sourceValues) = sourceObject.value else {
            throw StoreRuntimeError.failure("initWithDictionary: source is not a dictionary")
        }

        guard let target = objects[receiver] else {
            throw StoreRuntimeError.failure("unknown dictionary receiver")
        }

        var values = sourceValues
        target.value = .dictionary(values)
        if !copyItems {
            try set(receiver)

            return
        }

        let keys = values.keys.sorted()
        var index = 0

        func next() throws {
            while index < keys.count {
                let key = keys[index]
                let value = values[key] ?? 0
                index += 1

                guard let valueObject = objects[value] else {
                    throw StoreRuntimeError.failure("unknown copied dictionary value")
                }

                let entry = lookup(valueObject.cls, "copyWithZone:", false)
                if entry != 0 {
                    try callbackFunction(entry, [value, try selectorAddress(for: "copyWithZone:"), 0]) {
                        [unowned self] in
                        values[key] = try self.arg(0)
                        try next()
                    }

                    return
                }

                values[key] = try foundationCopy(value, false)
            }

            target.value = .dictionary(values)
            try set(receiver)
        }

        try next()
    }

    func collectionKey(_ address: UInt64) -> String {
        if let object = objects[address] {
            switch object.value {
            case let .string(value):
                return value
            case let .int(number):
                return "#number:\(number)"
            default:
                break
            }
        }

        return "#object:" + String(address, radix: 16)
    }

    func foundationEqual(_ left: UInt64, _ right: UInt64) -> Bool {
        if left == right {
            return true
        }

        guard let x = objects[left], let y = objects[right] else {
            return false
        }

        switch x.value {
        case let .double(value):
            if case let .double(other) = y.value {
                return value == other
            }
        case let .string(value):
            if case let .string(other) = y.value {
                return value == other
            }
        case let .int(value):
            switch y.value {
            case let .int(other):
                return value == other
            case let .bool(other):
                return value == Int64(boolValue(other))
            default:
                break
            }
        case let .bool(value):
            switch y.value {
            case let .int(other):
                return Int64(boolValue(value)) == other
            case let .bool(other):
                return value == other
            default:
                break
            }
        case let .data(value):
            if case let .data(other) = y.value {
                return value == other
            }
        case let .array(value):
            guard case let .array(other) = y.value, value.count == other.count else {
                return false
            }

            for index in 0 ..< value.count where !foundationEqual(value[index], other[index]) {
                return false
            }

            return true
        case let .dictionary(value):
            guard case let .dictionary(other) = y.value, value.count == other.count else {
                return false
            }

            for (key, pointer) in value {
                guard let candidate = other[key], foundationEqual(pointer, candidate) else {
                    return false
                }
            }

            return true
        case .none:
            break
        }

        return false
    }

    func characterSetContains(_ set: GuestObject?, _ character: Character) throws -> Bool {
        guard let set, case let .string(chars) = set.value else {
            throw StoreRuntimeError.failure("character set is not a string")
        }

        var match = chars.contains(character)
        if chars == "0123456789" {
            match = character.isWholeNumber
        }

        if let inverted = set.properties["inverted"], inverted != 0 {
            match = !match
        }

        return match
    }

    func newUUIDString() -> String {
        UUID().uuidString
    }
}

/// 按 Go 的 `%<width><verb>` 语义输出十六进制。
private func paddedHex(_ value: UInt64, width: String, uppercase: Bool, prefix: Bool) -> String {
    let digits = String(value, radix: 16, uppercase: uppercase)
    let body = (prefix ? "0x" : "") + digits
    let target = Int(width) ?? 0
    if body.count >= target {
        return body
    }

    return String(repeating: " ", count: target - body.count) + body
}
