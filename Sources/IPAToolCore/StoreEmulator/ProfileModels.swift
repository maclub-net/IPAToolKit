import Foundation

// Store runtime profile 的 JSON 结构与 internal/store/profile/format/types.go 一致。
// 键名保持 Go 字段原名，避免额外的 CodingKeys 映射。

struct ProfileMethod: Decodable {
    let Selector: String
    let Address: UInt64
    let ClassMethod: Bool
    let Types: String?

    private enum CodingKeys: String, CodingKey {
        case Selector, Address, ClassMethod, Types
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        Selector = try c.decodeIfPresent(String.self, forKey: .Selector) ?? ""
        Address = try c.decodeIfPresent(UInt64.self, forKey: .Address) ?? 0
        ClassMethod = try c.decodeIfPresent(Bool.self, forKey: .ClassMethod) ?? false
        Types = try c.decodeIfPresent(String.self, forKey: .Types)
    }
}

struct ProfileClass: Decodable {
    let MetaAddress: UInt64
    let Name: String
    let Address: UInt64
    let Super: String
    let Size: UInt64
    let Ivars: [String: UInt64]
    let Methods: [ProfileMethod]?

    private enum CodingKeys: String, CodingKey {
        case MetaAddress, Name, Address, Super, Size, Ivars, Methods
    }

    init(MetaAddress: UInt64, Name: String, Address: UInt64, Super: String,
         Size: UInt64, Ivars: [String: UInt64], Methods: [ProfileMethod]?) {
        self.MetaAddress = MetaAddress
        self.Name = Name
        self.Address = Address
        self.Super = Super
        self.Size = Size
        self.Ivars = Ivars
        self.Methods = Methods
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        MetaAddress = try c.decodeIfPresent(UInt64.self, forKey: .MetaAddress) ?? 0
        Name = try c.decodeIfPresent(String.self, forKey: .Name) ?? ""
        Address = try c.decodeIfPresent(UInt64.self, forKey: .Address) ?? 0
        Super = try c.decodeIfPresent(String.self, forKey: .Super) ?? ""
        Size = try c.decodeIfPresent(UInt64.self, forKey: .Size) ?? 0
        Ivars = try c.decodeIfPresent([String: UInt64].self, forKey: .Ivars) ?? [:]
        Methods = try c.decodeIfPresent([ProfileMethod].self, forKey: .Methods)
    }
}

struct ProfileCall: Decodable {
    let Address: UInt64
    let Symbol: String
    let Selector: String
    let SelectorAddress: UInt64

    private enum CodingKeys: String, CodingKey {
        case Address, Symbol, Selector, SelectorAddress
    }

    init(Address: UInt64, Symbol: String, Selector: String, SelectorAddress: UInt64) {
        self.Address = Address
        self.Symbol = Symbol
        self.Selector = Selector
        self.SelectorAddress = SelectorAddress
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        Address = try c.decodeIfPresent(UInt64.self, forKey: .Address) ?? 0
        Symbol = try c.decodeIfPresent(String.self, forKey: .Symbol) ?? ""
        Selector = try c.decodeIfPresent(String.self, forKey: .Selector) ?? ""
        SelectorAddress = try c.decodeIfPresent(UInt64.self, forKey: .SelectorAddress) ?? 0
    }
}

struct ProfilePage: Decodable {
    let Address: UInt64
    let Offset: UInt64

    private enum CodingKeys: String, CodingKey {
        case Address, Offset
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        Address = try c.decodeIfPresent(UInt64.self, forKey: .Address) ?? 0
        Offset = try c.decodeIfPresent(UInt64.self, forKey: .Offset) ?? 0
    }
}

struct ProfileConstant: Decodable {
    let IsBoolean: Bool?
    let Boolean: Bool?
    let Kind: String
    let Text: String?
    let Number: Int64?
    let Entries: [String: UInt64]?
    let Items: [UInt64]?

    private enum CodingKeys: String, CodingKey {
        case IsBoolean, Boolean, Kind, Text, Number, Entries, Items
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        IsBoolean = try c.decodeIfPresent(Bool.self, forKey: .IsBoolean)
        Boolean = try c.decodeIfPresent(Bool.self, forKey: .Boolean)
        Kind = try c.decodeIfPresent(String.self, forKey: .Kind) ?? ""
        Text = try c.decodeIfPresent(String.self, forKey: .Text)
        Number = try c.decodeIfPresent(Int64.self, forKey: .Number)
        Entries = try c.decodeIfPresent([String: UInt64].self, forKey: .Entries)
        Items = try c.decodeIfPresent([UInt64].self, forKey: .Items)
    }
}

struct DictionaryLayout: Decodable {
    let Metadata: UInt64
    let KeyStride: UInt64
    let ValueStride: UInt64
}

struct ProfileMetadataPatch: Decodable {
    let Address: UInt64
    let Data: Data
}

struct StoreProfile: Decodable {
    let Bridges: [String: UInt64]
    let ObjCMetadata: [String: UInt64]
    let SwiftSingletons: [String: UInt64]
    let MetadataPatches: [ProfileMetadataPatch]
    let SwiftForeign: [String: UInt64]
    let PluginUUID: String
    let SwiftDictionaries: [String: DictionaryLayout]
    let SwiftGlobals: [String: UInt64]
    let SwiftTypes: [String: UInt64]
    let SwiftWitnesses: [String: UInt64]
    let SwiftAccessors: [String: UInt64]
    let Symbols: [String: UInt64]
    let Features: [String: Bool]
    let Constants: [String: ProfileConstant]
    let UUID: String
    let Classes: [ProfileClass]
    let Calls: [ProfileCall]
    let Strings: [String: String]
    let Pages: [ProfilePage]

    private enum CodingKeys: String, CodingKey {
        case Bridges, ObjCMetadata, SwiftSingletons, MetadataPatches, SwiftForeign, PluginUUID
        case SwiftDictionaries, SwiftGlobals, SwiftTypes, SwiftWitnesses, SwiftAccessors
        case Symbols, Features, Constants, UUID, Classes, Calls, Strings, Pages
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        Bridges = try c.decodeIfPresent([String: UInt64].self, forKey: .Bridges) ?? [:]
        ObjCMetadata = try c.decodeIfPresent([String: UInt64].self, forKey: .ObjCMetadata) ?? [:]
        SwiftSingletons = try c.decodeIfPresent([String: UInt64].self, forKey: .SwiftSingletons) ?? [:]
        MetadataPatches = try c.decodeIfPresent([ProfileMetadataPatch].self, forKey: .MetadataPatches) ?? []
        SwiftForeign = try c.decodeIfPresent([String: UInt64].self, forKey: .SwiftForeign) ?? [:]
        PluginUUID = try c.decodeIfPresent(String.self, forKey: .PluginUUID) ?? ""
        SwiftDictionaries = try c.decodeIfPresent([String: DictionaryLayout].self, forKey: .SwiftDictionaries) ?? [:]
        SwiftGlobals = try c.decodeIfPresent([String: UInt64].self, forKey: .SwiftGlobals) ?? [:]
        SwiftTypes = try c.decodeIfPresent([String: UInt64].self, forKey: .SwiftTypes) ?? [:]
        SwiftWitnesses = try c.decodeIfPresent([String: UInt64].self, forKey: .SwiftWitnesses) ?? [:]
        SwiftAccessors = try c.decodeIfPresent([String: UInt64].self, forKey: .SwiftAccessors) ?? [:]
        Symbols = try c.decodeIfPresent([String: UInt64].self, forKey: .Symbols) ?? [:]
        Features = try c.decodeIfPresent([String: Bool].self, forKey: .Features) ?? [:]
        Constants = try c.decodeIfPresent([String: ProfileConstant].self, forKey: .Constants) ?? [:]
        UUID = try c.decodeIfPresent(String.self, forKey: .UUID) ?? ""
        Classes = try c.decodeIfPresent([ProfileClass].self, forKey: .Classes) ?? []
        Calls = try c.decodeIfPresent([ProfileCall].self, forKey: .Calls) ?? []
        Strings = try c.decodeIfPresent([String: String].self, forKey: .Strings) ?? [:]
        Pages = try c.decodeIfPresent([ProfilePage].self, forKey: .Pages) ?? []
    }
}

func profileMethodKey(_ className: String, _ selector: String, _ meta: Bool) -> String {
    (meta ? "+[" : "-[") + className + " " + selector + "]"
}

/// 表达式 `m[...]` 的对应物：Swift 里直接使用字符串键。
final class ProfileTables {
    var profile: StoreProfile
    var callsList: [ProfileCall]
    var classes: [String: ProfileClass]
    var classNames: [UInt64: String]
    var methods: [String: UInt64]
    var calls: [UInt64: ProfileCall]
    var selectors: [UInt64: String]
    var selectorAddresses: [String: UInt64]
    var objects: [UInt64: GuestTemplate]
    var entries: [UInt64: String]

    init(profile: StoreProfile) {
        self.profile = profile
        callsList = []
        classes = [:]
        classNames = [:]
        methods = [:]
        calls = [:]
        selectors = [:]
        selectorAddresses = [:]
        objects = [:]
        entries = [:]
    }
}

/// Profile 中预置的 guest 对象模板（NSString / NSNumber / NSDictionary / NSArray ...）。
struct GuestTemplate {
    let cls: String
    let value: GuestValue
}
