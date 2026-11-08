import Foundation
import CSAP

// Swift 运行时符号桥。
// 对应 Go 侧 internal/store/emulator/swift.go。

func isASCII(_ value: String) -> Bool {
    value.utf8.allSatisfy { $0 < 0x80 }
}

/// profileformat.WitnessKey 的对应物。
func profileWitnessKey(_ descriptor: UInt64, _ metadata: UInt64) -> String {
    "\(descriptor):\(metadata)"
}

extension StoreRuntime {
    func swiftSymbol(_ name: String) throws -> Bool {
        if try asyncSymbol(name) {
            return true
        }

        switch name {
        case "$ss27_stringCompareWithSmolCheck__9expectingSbs11_StringGutsV_ADs01_G16ComparisonResultOtF":
            let left = try swiftString(try arg(0), try arg(1)).precomposedStringWithCanonicalMapping
            let right = try swiftString(try arg(2), try arg(3)).precomposedStringWithCanonicalMapping

            switch try arg(4) {
            case 0:
                try set(boolValue(left == right))
            case 1:
                try set(boolValue(byteCompareStrings(left, right) < 0))
            default:
                throw StoreRuntimeError.failure("unsupported Swift string comparison")
            }
        case "$ss18_DictionaryStorageC6resize8original8capacity4moveAByxq_Gs05__RawaB0C_SiSbtFZ":
            let storageType = try arg(3)
            let capacity = try arg(1)

            var metadata: UInt64 = 0
            for (key, layout) in profile.SwiftDictionaries where layout.Metadata == storageType {
                metadata = UInt64(key) ?? 0
                break
            }

            guard metadata != 0 else {
                throw StoreRuntimeError.failure(
                    "unprepared dictionary storage \(String(storageType, radix: 16))"
                )
            }

            let slot = try alloc(8)
            try write64(slot, profile.Symbols["_swiftEmptyDictionarySingleton"] ?? 0)
            try ensureUniqueDictionary(slot, false, capacity, metadata)
            try set(try read64(slot))
        case "swift_dynamicCast":
            let destination = try arg(0)
            let source = try arg(1)
            var sourceType = try arg(2)
            let targetType = try arg(3)
            let stringMetadata = profile.Symbols["$sSSN"] ?? 0

            if sourceType == profile.Symbols["$ss11AnyHashableVN"], targetType == stringMetadata {
                guard try read64(source + 24) == (profile.Bridges["anyHashableStringMetadata"] ?? 0) else {
                    throw StoreRuntimeError.failure("unsupported AnyHashable cast box")
                }

                sourceType = targetType
            } else if sourceType == (profile.Symbols["$sypN"] ?? 0) + 8 {
                sourceType = try read64(source + 24)
            }

            if sourceType == targetType {
                let size = try read64(try read64(sourceType &- 8) + 64)
                guard size <= 24 else {
                    throw StoreRuntimeError.failure("unsupported Swift cast value size")
                }

                let data = try engine.memRead(source, size)
                try memWrite(destination, data)
                try set(1)
            } else if targetType == stringMetadata,
                      sourceType == profile.Symbols["$sSiN"]
                          || sourceType == profile.Symbols["$sSbN"]
                          || sourceType == profile.Symbols["$sSdN"],
                      try arg(4) & 1 == 0 {
                try set(0)
            } else {
                throw StoreRuntimeError.failure(
                    "unsupported Swift cast metadata \(String(sourceType, radix: 16)) -> \(String(targetType, radix: 16)) flags=\(try arg(4))"
                )
            }
        case "$ss17CodingUserInfoKeyVwCP", "$sSSwCP", "$sSSwcp", "$sSSwca":
            // The pinned runtime shares this witness with String: two words,
            // followed by a retain that our scoped allocation lifetime subsumes.
            let data = try engine.memRead(try arg(1), 16)
            try memWrite(try arg(0), data)
        case "$ss11AnyHashableVwxx", "$sSSwxx":
            // References remain alive until this runtime closes.
            break
        case "$ss11AnyHashableVwcp", "$ss11AnyHashableVwca":
            // This bridge currently constructs only inline String-backed boxes.
            guard try read64(try arg(1) + 24) == (profile.Bridges["anyHashableStringMetadata"] ?? 0) else {
                throw StoreRuntimeError.failure("unsupported AnyHashable copy layout")
            }

            let data = try engine.memRead(try arg(1), 40)
            try memWrite(try arg(0), data)
        case "$sSD10FoundationE36_unconditionallyBridgeFromObjectiveCySDyxq_GSo12NSDictionaryCSgFZ":
            let keyType = try arg(1)
            let valueType = try arg(2)
            guard keyType == profile.Symbols["$sSSN"] || keyType == profile.Symbols["$ss11AnyHashableVN"],
                  valueType == (profile.Symbols["$sypN"] ?? 0) + 8 || valueType == profile.Symbols["$sSSN"] else {
                throw StoreRuntimeError.failure(
                    "unsupported dictionary bridge metadata \(String(keyType, radix: 16))/\(String(valueType, radix: 16))"
                )
            }

            try set(try bridgeDictionaryToSwift(try arg(0), keyType, valueType))
        case "$sSo13os_log_type_ta0A0E5errorABvgZ":
            try set(16)
        case "$sSo13os_log_type_ta0A0E5faultABvgZ":
            try set(17)
        case "$sSo13os_log_type_ta0A0E4infoABvgZ":
            try set(1)
        case "$sSo13os_log_type_ta0A0E5debugABvgZ":
            try set(2)
        case "$sSo13os_log_type_ta0A0E7defaultABvgZ":
            try set(0)
        case "$sSS6appendyySSF":
            let selfAddress = try engine.regRead(ucRegX0 + 20)
            let value = try swiftString(try read64(selfAddress), try read64(selfAddress + 8))
                + (try swiftString(try arg(0), try arg(1)))
            try returnSwiftString(value)
            try write64(selfAddress, try arg(0))
            try write64(selfAddress + 8, try arg(1))
        case "$ss9_typeName_9qualifiedSSypXp_SbtF":
            var name = classNames[try arg(0)] ?? ""
            if name.isEmpty, try read64(try arg(0)) == 0x305 {
                name = classNames[try read64(try arg(0) + 8)] ?? ""
            }

            guard !name.isEmpty else {
                throw StoreRuntimeError.failure(
                    "unprepared Swift type name \(String(try arg(0), radix: 16))"
                )
            }

            try returnSwiftString(name)
        case "$ss9TaskLocalC12wrappedValueAByxGx_tcfc":
            let selfAddress = try engine.regRead(ucRegX0 + 20)
            let metadata = try read64(selfAddress)
            let valueType = try read64(metadata + 80)
            let size = try read64(try read64(valueType &- 8) + 64)

            let allocation = allocations[selfAddress] ?? 0
            guard allocation < 16 || size <= allocation - 16 else {
                throw StoreRuntimeError.failure("TaskLocal value exceeds allocation")
            }

            let data = try engine.memRead(try arg(0), size)
            try memWrite(selfAddress + 16, data)
            objects[selfAddress] = GuestObject(
                cls: "HostSwiftTaskLocal",
                value: .none,
                properties: ["valueSize": size, "defaultValue": selfAddress + 16]
            )
            try set(selfAddress)
        case "$ss9TaskLocalC3getxyF", "$ss9TaskLocalC12wrappedValuexvg":
            let selfAddress = try engine.regRead(ucRegX0 + 20)
            guard let object = objects[selfAddress] else {
                throw StoreRuntimeError.failure("unknown TaskLocal")
            }

            let out = try engine.regRead(ucRegX0 + 8)
            var source = taskLocalValue(selfAddress)
            if source == 0 {
                source = object.properties["defaultValue"] ?? 0
            }

            let data = try engine.memRead(source, object.properties["valueSize"] ?? 0)
            try memWrite(out, data)
        case "$sSo9OS_os_logC0B0E9subsystem8categoryABSS_SStcfC":
            try set(try newObject("HostOSLog", .none))
        case "$s10Foundation10URLRequestV8setValue_18forHTTPHeaderFieldySSSg_SStF":
            let copied = try mutableSwiftRequest()
            guard let object = objects[copied] else {
                throw StoreRuntimeError.failure("invalid Swift request storage")
            }

            if object.properties["allHTTPHeaderFields"] == nil
                || object.properties["allHTTPHeaderFields"] == 0 {
                object.properties["allHTTPHeaderFields"] = try newObject("NSMutableDictionary", .dictionary([:]))
            }

            let fieldsAddress = object.properties["allHTTPHeaderFields"] ?? 0
            guard let fieldsObject = objects[fieldsAddress],
                  case var .dictionary(fields) = fieldsObject.value else {
                throw StoreRuntimeError.failure("Swift request headers are not a dictionary")
            }

            let key = canonicalHeaderKey(try swiftString(try arg(2), try arg(3)))
            if try arg(1) == 0 {
                fields.removeValue(forKey: key)
            } else {
                fields[key] = try newObject(
                    "NSString",
                    .string(try swiftString(try arg(0), try arg(1)))
                )
            }

            fieldsObject.value = .dictionary(fields)
        case "swift_initWithCopy_strong", "swift_initWithTake_strong",
             "swift_assignWithCopy_strong", "swift_assignWithTake_strong":
            try write64(try arg(0), try read64(try arg(1)))
        case "$s10Foundation3URLV14absoluteStringSSvg":
            let selfAddress = try engine.regRead(ucRegX0 + 20)
            try returnSwiftString(try guestString(try read64(selfAddress)))
        case "$s10Foundation10URLRequestV3urlAA3URLVSgvg":
            let selfAddress = try engine.regRead(ucRegX0 + 20)
            guard let object = objects[try read64(selfAddress)] else {
                throw StoreRuntimeError.failure("invalid Swift URLRequest value")
            }

            let out = try engine.regRead(ucRegX0 + 8)
            try write64(out, object.properties["URL"] ?? 0)
            try write64(out + 8, 0)
        case "swift_getSingletonMetadata":
            guard let value = profile.SwiftSingletons[String(try arg(1))], value != 0 else {
                throw StoreRuntimeError.failure(
                    "unprepared singleton metadata \(String(try arg(1), radix: 16))"
                )
            }

            try set(value)
            try engine.regWrite(ucRegX0 + 1, 0)
        case "$s10Foundation22_convertErrorToNSErrorySo0E0Cs0C0_pF":
            var value = try arg(0)
            for _ in 0 ..< 16 {
                guard let object = objects[value] else {
                    throw StoreRuntimeError.failure("unknown Swift error value")
                }

                if try kindOf(object.cls, "NSError") {
                    try set(value)

                    return true
                }

                guard object.cls == "HostSwiftError",
                      object.properties["metadata"] == profile.SwiftTypes[String(0x1a2e1c7fa)] else {
                    throw StoreRuntimeError.failure(
                        "unsupported Swift error bridge \(object.cls) metadata \(String(object.properties["metadata"] ?? 0, radix: 16))"
                    )
                }

                value = try read64(object.properties["value"] ?? 0)
            }

            throw StoreRuntimeError.failure("recursive Swift error box")
        case "$ss38_bridgeAnythingNonVerbatimToObjectiveCyyXlxnlF":
            let source = try arg(0)
            let metadata = try arg(1)
            switch metadata {
            case profile.Symbols["$sSSN"]:
                try set(try newObject("NSString", .string(
                    try swiftString(try read64(source), try read64(source + 8))
                )))
            case profile.Symbols["$sSiN"]:
                try set(try newObject("NSNumber", .int(Int64(bitPattern: try read64(source)))))
            default:
                throw StoreRuntimeError.failure(
                    "unsupported nonverbatim bridge metadata \(String(metadata, radix: 16))"
                )
            }
        case "$sSD10FoundationE19_bridgeToObjectiveCSo12NSDictionaryCyF":
            try set(try bridgeDictionaryToObjC(try arg(0), try arg(1), try arg(2)))
        case "$sSS4hash4intoys6HasherVz_tF":
            let value = try swiftString(try arg(1), try arg(2)).precomposedStringWithCanonicalMapping
            try hashBytes(try arg(0), Array(value.utf8) + [255])
        case "swift_allocError":
            let metadata = try arg(0)
            let witness = try arg(1)
            let source = try arg(2)

            let size = try read64(try read64(metadata &- 8) + 64)
            guard size <= 1 << 20 else {
                throw StoreRuntimeError.failure("Swift error exceeds budget")
            }

            let value = try alloc(size)
            let box = try newObject("HostSwiftError", .none)

            objects[box]?.properties = ["metadata": metadata, "witness": witness, "value": value]
            if source != 0 {
                let data = try engine.memRead(source, size)
                try memWrite(value, data)
            }

            try set(box)
            try engine.regWrite(ucRegX0 + 1, value)
        case "swift_getErrorValue":
            guard let box = objects[try arg(0)], box.cls == "HostSwiftError" else {
                throw StoreRuntimeError.failure("unsupported unboxed Swift error")
            }

            let out = try arg(2)
            try write64(out, box.properties["value"] ?? 0)
            try write64(out + 8, box.properties["metadata"] ?? 0)
            try write64(out + 16, box.properties["witness"] ?? 0)
        case "swift_errorRetain", "swift_errorRelease", "swift_willThrow":
            break
        case "$s10Foundation10URLRequestV36_unconditionallyBridgeFromObjectiveCyACSo12NSURLRequestCSgFZ":
            let value = try arg(0)
            guard let object = objects[value], try kindOf(object.cls, "NSURLRequest") else {
                throw StoreRuntimeError.failure("invalid Swift request bridge input")
            }

            let out = try engine.regRead(ucRegX0 + 8)
            try write64(out, value)
        case "$s10Foundation10URLRequestV19_bridgeToObjectiveCSo12NSURLRequestCyF":
            let selfAddress = try engine.regRead(ucRegX0 + 20)
            try set(try read64(selfAddress))
        case "$sScPwst":
            guard try arg(2) == 1, try arg(1) <= 1 else {
                throw StoreRuntimeError.failure("unsupported task priority optional tag")
            }

            let size = try read64(try read64(try arg(3) &- 8) + 64)
            guard size == 1 else {
                throw StoreRuntimeError.failure("unexpected priority size")
            }

            try memWrite(try arg(0) + size, [UInt8(truncatingIfNeeded: try arg(1))])
        case "$sScPwet":
            let size = try read64(try read64(try arg(2) &- 8) + 64)
            let data = try engine.memRead(try arg(0) + size, 1)
            try set(UInt64(data[0]))
        case "$s10Foundation3URLV06isFileB0Sbvg":
            let selfAddress = try engine.regRead(ucRegX0 + 20)
            let raw = try guestString(try read64(selfAddress))
            guard let url = URL(string: raw) else {
                throw StoreRuntimeError.failure("invalid URL \(raw)")
            }

            try set(boolValue(url.scheme == "file"))
        case "$s10Foundation3URLV19_bridgeToObjectiveCSo5NSURLCyF":
            let selfAddress = try engine.regRead(ucRegX0 + 20)
            try set(try read64(selfAddress))
        case "$sSqwta", "$sSqwca", "$sSqwcp", "$sSqwtk", "swift_cvw_initWithCopy",
             "swift_cvw_assignWithCopy", "swift_cvw_initWithTake", "swift_cvw_assignWithTake":
            let size = try read64(try read64(try arg(2) &- 8) + 64)
            guard size <= 1024 else {
                throw StoreRuntimeError.failure("Swift value copy exceeds budget")
            }

            let data = try engine.memRead(try arg(1), size)
            try memWrite(try arg(0), data)
        case "$s10Foundation3URLVwst":
            guard try arg(2) == 1, try arg(1) <= 1 else {
                throw StoreRuntimeError.failure("unsupported URL optional tag")
            }

            if try arg(1) == 1 {
                try write64(try arg(0), 0)
                try write64(try arg(0) + 8, 0)
            }
        case "$s10Foundation3URLVwet":
            guard try arg(1) == 1 else {
                throw StoreRuntimeError.failure("unsupported URL optional tag")
            }

            try set(boolValue(try read64(try arg(0)) == 0))
        case "$s10Foundation3URLV9appending10components13directoryHintACxd_AC09DirectoryF0OtSyRzlF",
             "$s10Foundation3URLV6append10components13directoryHintyxd_AC09DirectoryF0OtSyRzlF":
            var selfAddress = try engine.regRead(ucRegX0 + 20)
            let array = try arg(0)
            let count = try read64(array + 16)
            guard count <= 32 else {
                throw StoreRuntimeError.failure("URL component count exceeds budget")
            }

            var value = try guestString(try read64(selfAddress))
            for index in UInt64(0) ..< count {
                let pointer = array + 32 + index * 16
                let component = try swiftString(try read64(pointer), try read64(pointer + 8))
                value = try urlJoinPath(value, component)
            }

            if name.contains("9appending") {
                selfAddress = try engine.regRead(ucRegX0 + 8)
            }

            try write64(selfAddress, try newObject("NSURL", .string(value)))
            try write64(selfAddress + 8, 0)
        case "$s10Foundation3URLV36_unconditionallyBridgeFromObjectiveCyACSo5NSURLCSgFZ":
            guard let object = objects[try arg(0)], object.cls == "NSURL" else {
                throw StoreRuntimeError.failure("invalid Swift URL bridge input")
            }

            let out = try engine.regRead(ucRegX0 + 8)
            try write64(out, try arg(0))
            try write64(out + 8, 0)
        case "$s10ObjectiveC8SelectorV2eeoiySbAC_ACtFZ":
            try set(boolValue(try arg(0) == arg(1)))
        case "$ss17_NativeDictionaryV12ensureUnique02isD08capacityS2b_SitF":
            let selfAddress = try engine.regRead(ucRegX0 + 20)
            try ensureUniqueDictionary(selfAddress, try arg(0) != 0, try arg(1), try arg(2))
        case "$ss6HasherV5_seedABSi_tcfC":
            let out = try engine.regRead(ucRegX0 + 8)
            try initHasher(out, try arg(0))
        case "$ss6HasherV8_combineyySuF":
            let selfAddress = try engine.regRead(ucRegX0 + 20)
            try hashWord(selfAddress, try arg(0))
        case "$ss6HasherV9_finalizeSiyF":
            let selfAddress = try engine.regRead(ucRegX0 + 20)
            try set(try hashCompress(selfAddress, try read64(selfAddress), true))
        case "$s10ObjectiveC8SelectorV4hash4intoys6HasherVz_tF":
            try hashWord(try arg(0), try arg(1))
        case "$sSo17OS_dispatch_queueC8DispatchE5async5group3qos5flags7executeySo0a1_b1_F0CSg_AC0D3QoSVAC0D13WorkItemFlagsVyyXBtF":
            guard try arg(0) == 0 else {
                throw StoreRuntimeError.failure("Swift dispatch group unsupported")
            }

            let queue = try engine.regRead(ucRegX0 + 20)
            try copyBlock(try arg(3)) { [unowned self] block in
                self.queuePending(block, queue)
                try self.set(0)
            }
        case "$sSo17OS_dispatch_queueC8DispatchE5label3qos10attributes20autoreleaseFrequency6targetABSS_AC0D3QoSVAbCE10AttributesVAbCE011AutoreleaseI0OABSgtcfC",
             "$sSo24OS_dispatch_queue_serialC8DispatchE5label3qos10attributes20autoreleaseFrequency6targetABSS_AC0E3QoSVAbCE10AttributesVSo0a1_b1_C0CACE011AutoreleaseJ0OANSgtcfC":
            let target = try arg(5)
            let queue = try newObject("HostQueue", .string(try swiftString(try arg(0), try arg(1))))
            objects[queue]?.properties["targetQueue"] = target
            try set(queue)
        case "$ss10SetAlgebraPyxqd__ncSTRd__7ElementQyd__ACRtzlufCTj":
            let accessors = profile.SwiftAccessors
            let attributeType = try arg(3)
            guard attributeType == accessors["$sSo24OS_dispatch_queue_serialC8DispatchE10AttributesVMa"]
                || attributeType == accessors["$sSo17OS_dispatch_queueC8DispatchE10AttributesVMa"]
                || attributeType == accessors["$s8Dispatch0A13WorkItemFlagsVMa"],
                try read64(try read64(try arg(0)) + 16) == 0 else {
                throw StoreRuntimeError.failure("unsupported SetAlgebra initializer")
            }

            let out = try engine.regRead(ucRegX0 + 8)
            try write64(out, 0)
        case "$s8Dispatch0A3QoSV11unspecifiedACvgZ":
            let out = try engine.regRead(ucRegX0 + 8)
            try write64(out, 5)
            try write64(out + 8, 0)
        case "swift_isUniquelyReferenced_nonNull_native", "swift_isUniquelyReferenced_nonNull_bridgeObject":
            // Conservatively copy; host handles can retain aliases for VM lifetime.
            try set(0)
        case "swift_retain_n", "swift_bridgeObjectRetain_n", "swift_retain",
             "swift_bridgeObjectRetain", "swift_unknownObjectRetain":
            break
        case "swift_destroy_strong", "$ss15CollectionOfOneV8IteratorVwxx", "swift_pod_destroy",
             "swift_arrayDestroy", "swift_deallocPartialClassInstance", "swift_cvw_destroy",
             "swift_noop_void_return", "swift_release_n", "swift_bridgeObjectRelease_n",
             "swift_release", "swift_bridgeObjectRelease", "swift_unknownObjectRelease",
             "swift_deallocObject":
            break
        case "swift_arrayInitWithCopy", "swift_arrayInitWithTakeFrontToBack",
             "swift_arrayInitWithTakeBackToFront":
            let destination = try arg(0)
            let source = try arg(1)
            let count = try arg(2)
            let metadata = try arg(3)
            if count == 0 {
                try set(destination)

                return true
            }

            let witnesses = try read64(metadata &- 8)
            let stride = try read64(witnesses + 72)
            guard count <= 65536, stride <= 1 << 20 else {
                throw StoreRuntimeError.failure("Swift array copy exceeds budget")
            }

            var index: UInt64 = 0
            let offset: UInt64 = name == "swift_arrayInitWithCopy" ? 16 : 32

            func next() throws {
                if index == count {
                    try set(destination)

                    return
                }

                var item = index
                if name == "swift_arrayInitWithTakeBackToFront" {
                    item = count - index - 1
                }

                index += 1

                try callbackFunction(try read64(witnesses + offset), [
                    destination + item * stride,
                    source + item * stride,
                    metadata,
                ], next)
            }

            try next()
        case "swift_allocObject":
            let metadata = try arg(0)
            let size = try arg(1)
            guard size >= 16 else {
                throw StoreRuntimeError.failure("invalid Swift object size")
            }

            let object = try alloc(size)
            try write64(object, metadata)
            try write64(object + 8, 3) // inline refcount: one strong reference, live object
            try set(object)
        case "swift_getForeignTypeMetadata":
            let candidate = try arg(1)
            if let value = profile.SwiftForeign[String(candidate)], value != 0 {
                try set(value)
                try engine.regWrite(ucRegX0 + 1, 0)

                return true
            }

            // AMSErrorCode: the pinned native runtime returns this complete, static enum
            // metadata unchanged. Do not generalize to foreign classes with initializers.
            guard candidate == 0x1eaa52f08, try read64(candidate) == 0x201 else {
                throw StoreRuntimeError.failure(
                    "unsupported foreign metadata \(String(candidate, radix: 16))"
                )
            }

            try set(candidate)
            try engine.regWrite(ucRegX0 + 1, 0)
        case "swift_getWitnessTable":
            guard let value = profile.SwiftWitnesses[
                profileWitnessKey(try arg(0), try arg(1))
            ], value != 0 else {
                throw StoreRuntimeError.failure(
                    "unprepared witness descriptor \(String(try arg(0), radix: 16)) for metadata \(String(try arg(1), radix: 16))"
                )
            }

            try set(value)
        case "$sSD17dictionaryLiteralSDyxq_Gx_q_td_tcfC":
            guard try read64(try arg(0) + 16) == 0 else {
                throw StoreRuntimeError.failure("nonempty Swift dictionary literal unsupported")
            }

            try set(profile.Symbols["_swiftEmptyDictionarySingleton"] ?? 0)
        case "swift_defaultActor_initialize":
            // Serial host scheduler: freshly allocated actor has an empty mailbox.
            // Enqueue/async entry points remain explicit unsupported services.
            objects[try arg(0)] = GuestObject(cls: "HostSwiftActor", value: .none)
        case "swift_getObjectType":
            try set(try read64(try arg(0)))
        case "swift_getObjCClassFromMetadata":
            if let name = classNames[try arg(0)], !name.isEmpty {
                return true
            }

            if try read64(try arg(0)) == 0x305 {
                try set(try read64(try arg(0) + 8))

                return true
            }

            throw StoreRuntimeError.failure("unknown Objective-C class metadata")
        case "swift_getObjCClassMetadata":
            // Objective-C compatible class metadata uses the class address itself.
            break
        case "swift_getTypeByMangledNameInContext2":
            guard let value = profile.SwiftTypes[String(try arg(0))], value != 0,
                  try arg(2) == 0, try arg(3) == 0 else {
                throw StoreRuntimeError.failure(
                    "unprepared Swift type \(String(try arg(0), radix: 16))/\(try arg(1))"
                )
            }

            try set(value)
        case "$sSS10FoundationE36_unconditionallyBridgeFromObjectiveCySSSo8NSStringCSgFZ":
            try returnSwiftString(try guestString(try arg(0)))
        case "$sSS10FoundationE19_bridgeToObjectiveCSo8NSStringCyF":
            try set(try newObject("NSString", .string(try swiftString(try arg(0), try arg(1)))))
        default:
            if name.contains("NativeBoxIyLm8ELm8ELm8E"), name.contains("initializeBufferWithCopyOfBuffer") {
                try write64(try arg(0), try read64(try arg(1)))

                return true
            }

            if name.contains("BridgeObjectBox"),
               name.contains("initializeWithCopy") || name.contains("assignWithCopy") {
                try write64(try arg(0), try read64(try arg(1)))

                return true
            }

            if name.contains("BridgeObjectBox"), name.contains("destroy") {
                return true
            }

            if name.contains("tuple_initializeWithCopy") || name.contains("tuple_assignWithCopy") {
                let size = try read64(try read64(try arg(2) &- 8) + 64)
                guard size <= 1024 else {
                    throw StoreRuntimeError.failure("tuple copy exceeds budget")
                }

                let data = try engine.memRead(try arg(1), size)
                try memWrite(try arg(0), data)

                return true
            }

            if name.hasPrefix("swift_memcpy") {
                let suffix = name.dropFirst("swift_memcpy".count)
                let pieces = suffix.split(separator: "_")
                guard pieces.count == 2, let size = UInt64(pieces[0]), size <= 1024 else {
                    throw StoreRuntimeError.failure("unsupported Swift copy size")
                }

                let data = try engine.memRead(try arg(1), size)
                try memWrite(try arg(0), data)

                return true
            }

            if name.contains("SwiftRetainableBox"), name.contains("7destroy") {
                return true
            }

            if name.contains("SwiftRetainableBox"), name.contains("initializeBufferWithCopyOfBuffer") {
                try write64(try arg(0), try read64(try arg(1)))

                return true
            }

            if let value = profile.SwiftGlobals[name], value != 0 {
                try set(value)

                return true
            }

            if (name.hasPrefix("$sSo17OS_dispatch_queueC8DispatchE")
                || name.hasPrefix("$s10Foundation3URLV13DirectoryHintO")),
               name.hasSuffix("Owui") {
                let metadata = try arg(2)
                guard try read64(try read64(metadata &- 8) + 64) == 1 else {
                    throw StoreRuntimeError.failure("unexpected dispatch enum size")
                }

                try memWrite(try arg(0), [UInt8(truncatingIfNeeded: try arg(1))])

                return true
            }

            if let value = profile.SwiftAccessors[name], value != 0 {
                try set(value)
                try engine.regWrite(ucRegX0 + 1, 0)

                return true
            }

            return false
        }

        return true
    }

    func returnSwiftString(_ value: String) throws {
        var words = [UInt8](repeating: 0, count: 16)
        let bytes = Array(value.utf8)

        if bytes.count <= 15 {
            words.replaceSubrange(0 ..< bytes.count, with: bytes)
            words[15] = 0xa0 | UInt8(bytes.count)
            if isASCII(value) {
                words[15] |= 0x40
            }

            try set(littleUInt64(words, 0))
            try engine.regWrite(ucRegX0 + 1, littleUInt64(words, 8))

            return
        }

        // Immortal native UTF-8 uses an address biased by the 32-byte storage header.
        let pointer = try alloc(UInt64(bytes.count + 33))
        try memWrite(pointer + 32, bytes + [0])

        var flags = UInt64(bytes.count) | 0x3000_0000_0000_0000
        if isASCII(value) {
            flags |= 0xc000_0000_0000_0000
        }

        try set(flags)
        try engine.regWrite(ucRegX0 + 1, pointer | 0x8000_0000_0000_0000)
    }

    func swiftString(_ first: UInt64, _ second: UInt64) throws -> String {
        if second & (1 << 61) != 0 {
            var buffer = [UInt8](repeating: 0, count: 16)
            buffer.replaceSubrange(0 ..< 8, with: littleBytes64(first))
            buffer.replaceSubrange(8 ..< 16, with: littleBytes64(second))
            let count = Int((second >> 56) & 15)
            return String(decoding: buffer[0 ..< count], as: UTF8.self)
        }

        let pointer = second & 0x0fff_ffff_ffff_ffff
        if second & (1 << 60) != 0 {
            return try guestString(pointer)
        }

        guard second & (1 << 63) != 0 else {
            throw StoreRuntimeError.failure("unsupported mortal Swift string")
        }

        let length = first & 0x0000_ffff_ffff_ffff
        guard length <= 1 << 20 else {
            throw StoreRuntimeError.failure("Swift string exceeds runtime limit")
        }

        let data = try engine.memRead(pointer + 32, length)
        return String(decoding: data, as: UTF8.self)
    }

    func mutableSwiftRequest() throws -> UInt64 {
        let selfAddress = try engine.regRead(ucRegX0 + 20)
        let source = try read64(selfAddress)

        guard let object = objects[source] else {
            throw StoreRuntimeError.failure("invalid Swift request storage")
        }

        let copied = try newObject(object.cls, object.value)

        if let klass = classes[object.cls] {
            let data = try engine.memRead(source, klass.Size)
            try memWrite(copied, data)
        }

        guard let copy = objects[copied] else {
            throw StoreRuntimeError.failure("invalid Swift request copy")
        }

        for (key, value) in object.properties {
            copy.properties[key] = value
        }

        if let header = object.properties["allHTTPHeaderFields"], header != 0 {
            copy.properties["allHTTPHeaderFields"] = try foundationCopy(header, true)
        }

        try write64(selfAddress, copied)

        return copied
    }
}
