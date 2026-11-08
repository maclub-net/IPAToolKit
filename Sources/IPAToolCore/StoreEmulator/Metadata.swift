import Foundation

/// 解析并索引 Store profile。对应 Go 侧 internal/store/emulator/metadata.go。
enum StoreProfileMetadata {
    static func prepare(metadata raw: [UInt8]) throws -> ProfileTables {
        let profile: StoreProfile
        do {
            profile = try JSONDecoder().decode(StoreProfile.self, from: Data(raw))
        } catch {
            throw StoreRuntimeError.failure("decode Store metadata: \(error)")
        }

        guard profile.UUID == "5DFC37A5-4689-3F9D-9655-D4774E1D8D08" else {
            throw StoreRuntimeError.failure("unsupported Store profile UUID")
        }

        var calls = profile.Calls
        // 固定的 dyld lazy-import thunk（已用解析后的 import slot 0x1eaaee178 核对）。
        calls.append(ProfileCall(
            Address: 0x1a2d0fb94,
            Symbol: "CRIsAutoSubmitEnabled",
            Selector: "",
            SelectorAddress: 0
        ))

        let tables = ProfileTables(profile: profile)
        tables.callsList = calls
        tables.calls = [:]

        for call in calls {
            tables.calls[call.Address] = call
            if !call.Selector.isEmpty {
                tables.selectors[call.SelectorAddress] = call.Selector
                tables.selectorAddresses[call.Selector] = call.SelectorAddress
            }
        }

        for klass in profile.Classes {
            tables.classes[klass.Name] = klass
            tables.classNames[klass.Address] = klass.Name

            if klass.MetaAddress != 0 {
                tables.classNames[klass.MetaAddress] = klass.Name
            }

            for method in klass.Methods ?? [] {
                let key = profileMethodKey(klass.Name, method.Selector, method.ClassMethod)
                tables.methods[key] = method.Address
                tables.entries[method.Address] = key
            }
        }

        for (key, value) in profile.Strings {
            guard let address = UInt64(key) else {
                throw StoreRuntimeError.failure("decode Store string address")
            }

            tables.objects[address] = GuestTemplate(cls: "NSString", value: .string(value))
        }

        for (key, value) in profile.Constants {
            guard let address = UInt64(key) else {
                throw StoreRuntimeError.failure("decode Store constant address")
            }

            let guest: GuestValue
            switch value.Kind {
            case "NSString":
                guest = .string(value.Text ?? "")
            case "NSNumber":
                if value.IsBoolean == true {
                    guest = .bool(value.Boolean ?? false)
                } else {
                    guest = .int(value.Number ?? 0)
                }
            case "NSDictionary":
                guest = .dictionary(value.Entries ?? [:])
            case "NSArray", "NSSet":
                guest = .array(value.Items ?? [])
            default:
                guest = .none
            }

            tables.objects[address] = GuestTemplate(cls: value.Kind, value: guest)
        }

        return tables
    }
}
