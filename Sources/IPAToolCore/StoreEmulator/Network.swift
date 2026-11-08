import Foundation
import CSAP

// Store 传输层与 NSURLSession / NSHTTPURLResponse 桥。
// 对应 Go 侧 internal/store/emulator/network.go（含 client.go 的 allowedURL）。

// MARK: - URL 辅助

func storeAllowedURL(_ value: URL?, authenticated: Bool) -> Bool {
    guard let value else {
        return false
    }

    if value.user != nil || value.fragment != nil {
        return false
    }

    let host = (value.host ?? "").lowercased()
    if !authenticated {
        // Package/artwork URLs are supplied by the Store response. Retain the
        // downloader's support for signed CDN URLs without binding it to one CDN.
        return !host.isEmpty && (value.scheme == "https" || value.scheme == "http")
    }

    let apple = host == "apple.com" || host.hasSuffix(".apple.com")
        || host.hasSuffix(".mzstatic.com") || host.hasSuffix(".cdn-apple.com")

    return apple && value.scheme == "https"
}

/// Go 的 url.JoinPath：把组件按 "/" 拼入并清理路径。
func urlJoinPath(_ base: String, _ component: String) throws -> String {
    guard var value = URL(string: base) else {
        throw StoreRuntimeError.failure("invalid URL \(base)")
    }

    for element in component.split(separator: "/", omittingEmptySubsequences: true) {
        value.appendPathComponent(String(element))
    }

    return value.absoluteString
}

/// Go 的 url.QueryEscape。
func storeQueryEscape(_ value: String) -> String {
    var result = ""
    let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~".utf8)

    for byte in value.utf8 {
        if allowed.contains(byte) {
            result.append(Character(UnicodeScalar(byte)))
        } else if byte == 0x20 {
            result.append("+")
        } else {
            result += String(format: "%%%02X", byte)
        }
    }

    return result
}

/// Go 的 url.QueryUnescape / url.PathUnescape。
func storeUnescape(_ value: String, plusAsSpace: Bool) -> String? {
    let input = Array(value.utf8)
    var output: [UInt8] = []
    var index = 0

    func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0") ... UInt8(ascii: "9"):
            return byte - UInt8(ascii: "0")
        case UInt8(ascii: "a") ... UInt8(ascii: "f"):
            return byte - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A") ... UInt8(ascii: "F"):
            return byte - UInt8(ascii: "A") + 10
        default:
            return nil
        }
    }

    while index < input.count {
        let byte = input[index]
        if byte == UInt8(ascii: "%") {
            guard index + 2 < input.count,
                  let high = hexValue(input[index + 1]),
                  let low = hexValue(input[index + 2]) else {
                return nil
            }

            output.append(high << 4 | low)
            index += 3
        } else if plusAsSpace, byte == UInt8(ascii: "+") {
            output.append(UInt8(ascii: " "))
            index += 1
        } else {
            output.append(byte)
            index += 1
        }
    }

    return String(decoding: output, as: UTF8.self)
}

/// Go 的 encodeComponentQuery。
func encodeComponentQuery(_ query: String) -> String {
    let allowed = Set("-._~!$&'()*+,;=:@/?".utf8)
    var result = ""

    for byte in query.utf8 {
        if (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
            || (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
            || (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
            || allowed.contains(byte) {
            result.append(Character(UnicodeScalar(byte)))
        } else {
            result += String(format: "%%%02X", byte)
        }
    }

    return result
}

/// Go 的 http.Header.Get：大小写不敏感地取第一个值。
func headerValue(_ headers: [String: [String]], _ name: String) -> String {
    let canonical = canonicalHeaderKey(name)
    if let values = headers[canonical], let first = values.first {
        return first
    }

    for (key, values) in headers where key.caseInsensitiveCompare(canonical) == .orderedSame {
        return values.first ?? ""
    }

    return ""
}

// MARK: - Cookie

struct StoreCookie {
    var name: String
    var value: String
    var domain: String
    var path: String
    var secure: Bool
    var httpOnly: Bool
    var expires: Date?
}

func parseSetCookie(_ line: String) -> StoreCookie? {
    let parts = line.components(separatedBy: ";")
    guard let first = parts.first else {
        return nil
    }

    guard let separator = first.firstIndex(of: "=") else {
        return nil
    }

    let name = String(first[..<separator]).trimmingCharacters(in: .whitespaces)
    let value = String(first[first.index(after: separator)...]).trimmingCharacters(in: .whitespaces)
    guard !name.isEmpty else {
        return nil
    }

    var cookie = StoreCookie(name: name, value: value, domain: "", path: "",
                             secure: false, httpOnly: false, expires: nil)

    for attribute in parts.dropFirst() {
        let pieces = attribute.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        let key = pieces[0].trimmingCharacters(in: .whitespaces).lowercased()
        let value = pieces.count > 1 ? pieces[1].trimmingCharacters(in: .whitespaces) : ""

        switch key {
        case "domain":
            cookie.domain = value
        case "path":
            cookie.path = value
        case "secure":
            cookie.secure = true
        case "httponly":
            cookie.httpOnly = true
        case "expires":
            cookie.expires = parseHTTPDate(value)
        case "max-age":
            if let seconds = Int(value) {
                cookie.expires = Date(timeIntervalSinceNow: Double(seconds))
            }
        default:
            break
        }
    }

    return cookie
}

func parseSetCookies(_ values: [String]) -> [StoreCookie] {
    values.compactMap(parseSetCookie)
}

func validCookiePair(_ cookie: StoreCookie) -> Bool {
    func isValid(_ text: String) -> Bool {
        guard !text.isEmpty else {
            return false
        }

        for scalar in text.unicodeScalars {
            if scalar.value < 0x20 || scalar.value == 0x7f {
                return false
            }

            if " \",;\\".unicodeScalars.contains(scalar) {
                return false
            }
        }

        return true
    }

    return isValid(cookie.name) && isValid(cookie.value)
}

func cookieHeaderValue(_ cookies: [StoreCookie]) -> String {
    cookies
        .filter(validCookiePair)
        .map { "\($0.name)=\($0.value)" }
        .joined(separator: "; ")
}

// MARK: - Property list 桥

func foundationValue(_ value: ExportValue) -> Any {
    switch value {
    case .null:
        return NSNull()
    case let .string(text):
        return text
    case let .int(number):
        return number
    case let .bool(flag):
        return flag
    case let .double(number):
        return number
    case let .data(data):
        return Data(data)
    case let .dictionary(fields):
        return fields.mapValues(foundationValue)
    case let .array(items):
        return items.map(foundationValue)
    }
}

// MARK: - 传输层桥

extension StoreRuntime {
    func hostBlock(_ fn: @escaping () throws -> Void) throws -> UInt64 {
        let function = try alloc(16)
        try memWrite(function, [0xc0, 0x03, 0x5f, 0xd6])

        callbacks[function] = fn
        let descriptor = try alloc(16)
        try write64(descriptor + 8, 32)

        let block = try alloc(32)
        try write64(block + 8, 1 << 28)
        try write64(block + 16, function)
        try write64(block + 24, descriptor)

        return block
    }

    func importValue(_ value: Any) throws -> UInt64 {
        if value is NSNull {
            return 0
        }

        // JSONSerialization / PropertyListSerialization 都返回 NSNumber。
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                return try newObject("NSNumber", .bool(number.boolValue))
            }

            let double = number.doubleValue
            if double.truncatingRemainder(dividingBy: 1) == 0,
               double >= Double(Int64.min), double < Double(Int64.max) {
                return try newObject("NSNumber", .int(Int64(double)))
            }

            return try newObject("NSNumber", .double(double))
        }

        switch value {
        case let text as String:
            return try newObject("NSString", .string(text))
        case let data as Data:
            return try newObject("NSData", .data([UInt8](data)))
        case let date as Date:
            return try newObject("NSDate", .double(date.timeIntervalSince1970))
        case let items as [Any]:
            var result: [UInt64] = []
            result.reserveCapacity(items.count)
            for item in items {
                result.append(try importValue(item))
            }

            return try newObject("NSArray", .array(result))
        case let fields as [String: Any]:
            var result: [String: UInt64] = [:]
            for (key, item) in fields {
                result[key] = try importValue(item)
            }

            return try newObject("NSDictionary", .dictionary(result))
        default:
            throw StoreRuntimeError.failure("unsupported Foundation import \(type(of: value))")
        }
    }

    func networkMessage(_ receiver: UInt64, _ className: String, _ selector: String,
                        _ meta: Bool) throws -> Bool {
        let object = objects[receiver]

        if !meta, className == "NSURLSessionConfiguration",
           selector == "_allowsTCPFastOpen" || selector == "_allowsTLSSessionTickets" || selector == "URLCache" {
            // These optional CFNetwork facilities are absent from the transport.
            try set(0)

            return true
        }

        if !meta, className == "NSHTTPURLResponse", selector == "_CFURLResponse" {
            try set(receiver)

            return true
        }

        if !meta, className == "NSURLSessionDataTask", selector == "_timingData" {
            // The portable transport has no CFNetwork timing-data object.
            try set(0)

            return true
        }

        if !meta, className == "AKAppleIDSession", selector == "handleResponse:forRequest:shouldRetry:" {
            // Pinned AuthKit _canHandleAnisetteURLResponse: accepts exactly these
            // challenge status codes. All other responses leave shouldRetry false.
            guard let response = objects[try arg(2)] else {
                throw StoreRuntimeError.failure("unsupported AuthKit anisette response")
            }

            let status = response.properties["statusCode"] ?? 0
            switch status {
            case 431, 433, 434, 441, 442, 443, 444:
                throw StoreRuntimeError.failure("AuthKit anisette challenge is not supported")
            default:
                break
            }

            let out = try arg(4)
            if out != 0 {
                try memWrite(out, [0])
            }

            try set(0)

            return true
        }

        if meta {
            switch selector {
            case "componentsWithURL:resolvingAgainstBaseURL:" where className == "NSURLComponents":
                guard let value = URL(string: try guestString(try arg(2))) else {
                    try set(0)

                    return true
                }

                try set(try newObject("NSURLComponents", .string(value.absoluteString)))
            case "sharedURLCache" where className == "NSURLCache":
                try set(0)
            case "isValidJSONObject:" where className == "NSJSONSerialization":
                try set(boolValue(validJSONObject(try arg(2), true, 0)))
            case "queryItemWithName:value:" where className == "NSURLQueryItem":
                let item = try newObject(className, .none)
                objects[item]?.properties = ["name": try arg(2), "value": try arg(3)]
                try set(item)
            case "cookieWithProperties:" where className == "NSHTTPCookie":
                guard let fieldsObject = objects[try arg(2)],
                      case let .dictionary(fields) = fieldsObject.value else {
                    throw StoreRuntimeError.failure("cookie properties are not a dictionary")
                }

                let cookie = try cookieFromFields(fields)
                try set(try newCookieObject(cookie))
            case "requestHeaderFieldsWithCookies:" where className == "NSHTTPCookie":
                guard let source = objects[try arg(2)], case let .array(items) = source.value else {
                    throw StoreRuntimeError.failure("cookies are not an array")
                }

                var cookies: [StoreCookie] = []
                for item in items {
                    guard let cookie = objects[item] else {
                        throw StoreRuntimeError.failure("unknown cookie object")
                    }

                    cookies.append(try cookieFromObject(cookie))
                }

                var fields: [String: UInt64] = [:]
                let value = cookieHeaderValue(cookies)
                if !value.isEmpty {
                    fields["Cookie"] = try newObject("NSString", .string(value))
                }

                try set(try newObject("NSDictionary", .dictionary(fields)))
            case "cookiesWithResponseHeaderFields:forURL:" where className == "NSHTTPCookie":
                var headers: [String: [String]] = [:]
                if let source = objects[try arg(2)], case let .dictionary(fields) = source.value {
                    for (key, value) in fields {
                        headers[key] = [try guestString(value)]
                    }
                }

                if let raw = responseHeaders[try arg(2)] {
                    headers = raw
                }

                var cookies: [StoreCookie] = []
                for (key, values) in headers where key.caseInsensitiveCompare("Set-Cookie") == .orderedSame {
                    cookies.append(contentsOf: parseSetCookies(values))
                }

                let origin = URL(string: try guestString(try arg(3)))
                var items: [UInt64] = []
                for var cookie in cookies {
                    if cookie.domain.isEmpty {
                        cookie.domain = origin?.host ?? ""
                    } else if !cookie.domain.hasPrefix(".") {
                        cookie.domain = "." + cookie.domain
                    }

                    if cookie.path.isEmpty {
                        cookie.path = "/"
                    }

                    items.append(try newCookieObject(cookie))
                }

                try set(try newObject("NSArray", .array(items)))
            case "sessionWithConfiguration:delegate:delegateQueue:" where className == "NSURLSession":
                let session = try newObject("NSURLSession", .none)
                objects[session]?.properties = [
                    "configuration": try arg(2),
                    "delegate": try arg(3),
                    "delegateQueue": try arg(4),
                ]
                try set(session)
            case "requestWithURL:" where className == "NSURLRequest" || className == "NSMutableURLRequest":
                let request = try newObject(className, .none)
                objects[request]?.properties = [
                    "URL": try arg(2),
                    "HTTPMethod": try newObject("NSString", .string("GET")),
                    "allHTTPHeaderFields": try newObject("NSMutableDictionary", .dictionary([:])),
                ]
                try set(request)
            case "JSONObjectWithData:options:error:" where className == "NSJSONSerialization":
                guard let dataObject = objects[try arg(2)], case let .data(data) = dataObject.value else {
                    throw StoreRuntimeError.failure("JSON input is not data")
                }

                let decoded: Any
                do {
                    decoded = try JSONSerialization.jsonObject(with: Data(data), options: [])
                } catch {
                    try parserError(try arg(4))
                    try set(0)

                    return true
                }

                try set(try importValue(decoded))
            case "propertyList:isValidForFormat:" where className == "NSPropertyListSerialization":
                var valid = false
                if let value = try? export(try arg(2)) {
                    valid = (try? PropertyListSerialization.data(
                        fromPropertyList: foundationValue(value), format: .xml, options: 0
                    )) != nil
                }

                try set(boolValue(valid))
            case "propertyListWithData:options:format:error:" where className == "NSPropertyListSerialization":
                guard let dataObject = objects[try arg(2)], case let .data(data) = dataObject.value else {
                    throw StoreRuntimeError.failure("property list input is not data")
                }

                let decoded: Any
                do {
                    decoded = try PropertyListSerialization.propertyList(
                        from: Data(data), options: [], format: nil
                    )
                } catch {
                    try parserError(try arg(5))
                    try set(0)

                    return true
                }

                try set(try importValue(decoded))
            case "dataWithPropertyList:format:options:error:" where className == "NSPropertyListSerialization":
                let value = try export(try arg(2))
                let binary = try arg(3) == 200
                let data = try PropertyListSerialization.data(
                    fromPropertyList: foundationValue(value),
                    format: binary ? .binary : .xml,
                    options: 0
                )
                try set(try newObject("NSData", .data([UInt8](data))))
            default:
                return false
            }

            return true
        }

        if selector == "initWithIndexesInRange:", className == "NSIndexSet" {
            guard let object else {
                throw StoreRuntimeError.failure("unknown index set")
            }

            object.value = .array([try arg(2), try arg(3)])
            try set(receiver)

            return true
        }

        if selector == "containsIndex:", className == "NSIndexSet" {
            guard let object, case let .array(range) = object.value, range.count >= 2 else {
                throw StoreRuntimeError.failure("invalid index set")
            }

            let index = try arg(2)
            try set(boolValue(index >= range[0] && index - range[0] < range[1]))

            return true
        }

        if selector == "initWithURL:", try kindOf(className, "NSURLRequest") {
            try engine.regWrite(ucRegX0 + 3, 0)
            try engine.regWrite(ucRegD0, Double(60).bitPattern)
            try message(receiver, "initWithURL:cachePolicy:timeoutInterval:", false)

            return true
        }

        if selector == "initWithURL:cachePolicy:timeoutInterval:", try kindOf(className, "NSURLRequest") {
            guard let object else {
                throw StoreRuntimeError.failure("unknown URL request")
            }

            object.properties = [
                "URL": try arg(2),
                "cachePolicy": try arg(3),
                "HTTPMethod": try newObject("NSString", .string("GET")),
                "allHTTPHeaderFields": try newObject("NSMutableDictionary", .dictionary([:])),
            ]
            try set(receiver)

            return true
        }

        if className == "NSHTTPURLResponse", selector == "valueForHTTPHeaderField:" {
            guard let object else {
                throw StoreRuntimeError.failure("unknown URL response")
            }

            var fields: [String: UInt64] = [:]
            if let pointer = object.properties["allHeaderFields"], pointer != 0,
               let headerObject = objects[pointer], case let .dictionary(values) = headerObject.value {
                fields = values
            }

            let target = try guestString(try arg(2))
            for (key, value) in fields where key.caseInsensitiveCompare(target) == .orderedSame {
                try set(value)

                return true
            }

            try set(0)

            return true
        }

        if try kindOf(className, "NSURLRequest") {
            guard let object else {
                throw StoreRuntimeError.failure("unknown URL request")
            }

            switch selector {
            case "HTTPBody", "HTTPBodyStream":
                // Bodyless requests have nil bodies. The framework inspects these
                // optional properties when handling redirects, even if no setter ran.
                try set(object.properties[selector] ?? 0)

                return true
            case "copy", "copyWithZone:", "mutableCopy", "mutableCopyWithZone:":
                if selector == "copy" || selector == "mutableCopy" {
                    let zone = selector + "WithZone:"
                    let entry = lookup(className, zone, false)
                    if entry != 0 {
                        try engine.regWrite(ucRegX0 + 2, 0)
                        try jump(entry, receiver, zone)

                        return true
                    }
                }

                let copied = try newObject(className, object.value)
                guard let destination = objects[copied] else {
                    throw StoreRuntimeError.failure("invalid request copy")
                }

                for (key, value) in object.properties {
                    destination.properties[key] = value
                }

                if let header = object.properties["allHTTPHeaderFields"], header != 0 {
                    destination.properties["allHTTPHeaderFields"] = try foundationCopy(header, true)
                }

                try set(copied)

                return true
            case "_CFURLRequest":
                try set(receiver)

                return true
            case "_initWithCFURLRequest:":
                guard let source = objects[try arg(2)] else {
                    throw StoreRuntimeError.failure("unknown CFURLRequest source")
                }

                object.properties = [:]
                for (key, value) in source.properties {
                    object.properties[key] = value
                }

                if let header = object.properties["allHTTPHeaderFields"], header != 0 {
                    object.properties["allHTTPHeaderFields"] = try foundationCopy(header, true)
                }

                try set(receiver)

                return true
            case "setValue:forHTTPHeaderField:", "addValue:forHTTPHeaderField:":
                if object.properties["allHTTPHeaderFields"] == nil
                    || object.properties["allHTTPHeaderFields"] == 0 {
                    object.properties["allHTTPHeaderFields"] = try newObject(
                        "NSMutableDictionary", .dictionary([:])
                    )
                }

                let pointer = object.properties["allHTTPHeaderFields"] ?? 0
                guard let headerObject = objects[pointer],
                      case var .dictionary(fields) = headerObject.value else {
                    throw StoreRuntimeError.failure("request headers are not a dictionary")
                }

                let key = canonicalHeaderKey(try guestString(try arg(3)))
                if try arg(2) == 0 {
                    fields.removeValue(forKey: key)
                } else {
                    fields[key] = try arg(2)
                }

                headerObject.value = .dictionary(fields)
                try set(0)

                return true
            case "valueForHTTPHeaderField:":
                var fields: [String: UInt64] = [:]
                if let pointer = object.properties["allHTTPHeaderFields"], pointer != 0,
                   let headerObject = objects[pointer], case let .dictionary(values) = headerObject.value {
                    fields = values
                }

                try set(fields[canonicalHeaderKey(try guestString(try arg(2)))] ?? 0)

                return true
            default:
                break
            }
        }

        if className == "NSURLSession", selector == "dataTaskWithRequest:" {
            let task = try newObject("NSURLSessionDataTask", .none)
            objects[task]?.properties = [
                "currentRequest": try arg(2),
                "originalRequest": try arg(2),
                "session": receiver,
                "taskIdentifier": task,
                "state": 1,
            ]
            try set(task)

            return true
        }

        if className == "NSURLSessionDataTask", selector == "resume" {
            guard let object else {
                throw StoreRuntimeError.failure("unknown data task")
            }

            guard object.properties["state"] == 1 else {
                throw StoreRuntimeError.failure("task resumed twice")
            }

            object.properties["state"] = 0
            pending.append(try hostBlock { [unowned self] in
                try self.performHTTP(receiver)
            })
            try set(0)

            return true
        }

        if (className == "NSURLSession"
            && (selector == "invalidateAndCancel" || selector == "finishTasksAndInvalidate"))
            || (className == "NSURLSessionDataTask" && selector == "cancel") {
            try set(0)

            return true
        }

        let requestClass: Bool
        if className == "NSURLSession" || className == "NSURLSessionDataTask"
            || className == "NSHTTPURLResponse" || className == "NSURLResponse" {
            requestClass = true
        } else {
            requestClass = try kindOf(className, "NSURLRequest")
        }

        if requestClass {
            guard let object else {
                throw StoreRuntimeError.failure("unknown session object")
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

                object.properties[key] = try arg(2)
                try set(0)

                return true
            }

            if let value = object.properties[selector] {
                try set(value)

                return true
            }
        }

        if className == "NSHTTPCookie" {
            if selector == "initWithProperties:" {
                guard let object else {
                    throw StoreRuntimeError.failure("unknown cookie")
                }

                guard let fieldsObject = objects[try arg(2)],
                      case let .dictionary(fields) = fieldsObject.value else {
                    throw StoreRuntimeError.failure("cookie properties are not a dictionary")
                }

                let cookie = try cookieFromFields(fields)
                object.value = try cookieValue(cookie)
                try set(receiver)

                return true
            }

            guard let object else {
                throw StoreRuntimeError.failure("unknown cookie")
            }

            let cookie = try cookieFromObject(object)

            switch selector {
            case "properties":
                var fields: [String: Any] = [
                    "Name": cookie.name,
                    "Value": cookie.value,
                    "Domain": cookie.domain,
                    "Path": cookie.path,
                    "Created": Int64(Date().timeIntervalSince1970) - 978_307_200,
                ]
                if cookie.secure {
                    fields["Secure"] = "TRUE"
                }

                if cookie.httpOnly {
                    fields["HttpOnly"] = "TRUE"
                }

                if let expires = cookie.expires {
                    fields["Expires"] = expires
                } else {
                    fields["Discard"] = "TRUE"
                }

                try set(try importValue(fields))

                return true
            case "name":
                try set(try newObject("NSString", .string(cookie.name)))

                return true
            case "domain":
                try set(try newObject("NSString", .string(cookie.domain)))

                return true
            case "path":
                try set(try newObject("NSString", .string(cookie.path)))

                return true
            case "value":
                try set(try newObject("NSString", .string(cookie.value)))

                return true
            case "expiresDate":
                if let expires = cookie.expires {
                    try set(try newObject("NSDate", .double(expires.timeIntervalSince1970)))
                } else {
                    try set(0)
                }

                return true
            case "isSessionOnly":
                try set(boolValue(cookie.expires == nil))

                return true
            case "version":
                try set(0)

                return true
            case "isSecure":
                try set(boolValue(cookie.secure))

                return true
            case "isHTTPOnly":
                try set(boolValue(cookie.httpOnly))

                return true
            default:
                break
            }
        }

        if className == "NSURLQueryItem", selector == "name" || selector == "value" {
            guard let object else {
                throw StoreRuntimeError.failure("unknown query item")
            }

            try set(object.properties[selector] ?? 0)

            return true
        }

        if className == "NSURLComponents" {
            if selector == "initWithURL:resolvingAgainstBaseURL:" {
                guard let object else {
                    throw StoreRuntimeError.failure("unknown URL components")
                }

                guard let value = URL(string: try guestString(try arg(2))) else {
                    throw StoreRuntimeError.failure("invalid URL components source")
                }

                object.value = .string(value.absoluteString)
                try set(receiver)

                return true
            }

            guard let object else {
                throw StoreRuntimeError.failure("unknown URL components")
            }

            guard case let .string(raw) = object.value,
                  var components = URLComponents(string: raw) else {
                throw StoreRuntimeError.failure("invalid URL components")
            }

            switch selector {
            case "setQuery:":
                let value = try arg(2)
                if value != 0 {
                    components.percentEncodedQuery = encodeComponentQuery(try guestString(value))
                } else {
                    components.percentEncodedQuery = ""
                }

                object.value = .string(components.string ?? "")
                try set(0)

                return true
            case "query", "percentEncodedQuery":
                if let rawQuery = components.percentEncodedQuery, !rawQuery.isEmpty {
                    var value = rawQuery
                    if selector == "query" {
                        guard let decoded = storeUnescape(rawQuery, plusAsSpace: false) else {
                            throw StoreRuntimeError.failure("invalid URL query encoding")
                        }

                        value = decoded
                    }

                    try set(try newObject("NSString", .string(value)))
                } else if components.percentEncodedQuery == nil {
                    try set(0)
                } else {
                    try set(try newObject("NSString", .string("")))
                }

                return true
            case "setFragment:":
                components.fragment = try guestString(try arg(2))
                object.value = .string(components.string ?? "")
                try set(0)

                return true
            case "URL":
                guard let value = components.url else {
                    throw StoreRuntimeError.failure("invalid URL components output")
                }

                try set(try newObject("NSURL", .string(value.absoluteString)))

                return true
            case "queryItems", "percentEncodedQueryItems":
                var items: [UInt64] = []

                if let rawQuery = components.percentEncodedQuery, !rawQuery.isEmpty {
                    for part in rawQuery.split(separator: "&", omittingEmptySubsequences: false) {
                        let pieces = part.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                        var key = String(pieces[0])
                        var value = pieces.count > 1 ? String(pieces[1]) : ""
                        let hasValue = pieces.count > 1

                        if selector == "queryItems" {
                            key = storeUnescape(
                                key.replacingOccurrences(of: "+", with: "%2B"),
                                plusAsSpace: false
                            ) ?? ""
                            value = storeUnescape(
                                value.replacingOccurrences(of: "+", with: "%2B"),
                                plusAsSpace: false
                            ) ?? ""
                        }

                        let item = try newObject("NSURLQueryItem", .none)
                        objects[item]?.properties["name"] = try newObject("NSString", .string(key))
                        if hasValue {
                            objects[item]?.properties["value"] = try newObject("NSString", .string(value))
                        }

                        items.append(item)
                    }
                }

                try set(try newObject("NSArray", .array(items)))

                return true
            case "setQueryItems:", "setPercentEncodedQueryItems:":
                var parts: [String] = []

                if try arg(2) != 0 {
                    guard let source = objects[try arg(2)], case let .array(items) = source.value else {
                        throw StoreRuntimeError.failure("query items are not an array")
                    }

                    for item in items {
                        guard let queryItem = objects[item] else {
                            throw StoreRuntimeError.failure("unknown query item")
                        }

                        let properties = queryItem.properties
                        var part: String
                        if selector == "setPercentEncodedQueryItems:" {
                            part = try guestString(properties["name"] ?? 0)
                            if let pointer = properties["value"], pointer != 0 {
                                part += "=" + (try guestString(pointer))
                            }
                        } else {
                            part = storeQueryEscape(try guestString(properties["name"] ?? 0))
                                .replacingOccurrences(of: "+", with: "%20")
                            if let pointer = properties["value"], pointer != 0 {
                                let value = storeQueryEscape(try guestString(pointer))
                                    .replacingOccurrences(of: "+", with: "%20")
                                part += "=" + value
                            }
                        }

                        parts.append(part)
                    }
                }

                components.percentEncodedQuery = parts.joined(separator: "&")
                object.value = .string(components.string ?? "")
                try set(0)

                return true
            default:
                break
            }
        }

        if className == "NSURL" {
            guard let object else {
                throw StoreRuntimeError.failure("unknown URL")
            }

            guard case let .string(raw) = object.value, let value = URL(string: raw) else {
                throw StoreRuntimeError.failure("invalid URL value")
            }

            switch selector {
            case "URLByAppendingPathComponent:", "URLByAppendingPathComponent:isDirectory:":
                let joined = try urlJoinPath(value.absoluteString, try guestString(try arg(2)))
                try set(try newObject("NSURL", .string(joined)))

                return true
            case "fileSystemRepresentation":
                var bytes = Array(value.path.utf8)
                bytes.append(0)
                let pointer = try alloc(UInt64(bytes.count))
                try memWrite(pointer, bytes)
                try set(pointer)

                return true
            case "isFileURL":
                try set(boolValue(value.scheme == "file"))

                return true
            case "fragment":
                if let fragment = value.fragment, !fragment.isEmpty {
                    try set(try newObject("NSString", .string(fragment)))
                } else {
                    try set(0)
                }

                return true
            case "host":
                try set(try newObject("NSString", .string(value.host ?? "")))

                return true
            case "scheme":
                try set(try newObject("NSString", .string(value.scheme ?? "")))

                return true
            case "query":
                let rawQuery = URLComponents(url: value, resolvingAgainstBaseURL: false)?.percentEncodedQuery ?? ""
                try set(try newObject("NSString", .string(rawQuery)))

                return true
            default:
                break
            }
        }

        if className == "NSData" || className == "NSMutableData" {
            guard let object else {
                throw StoreRuntimeError.failure("unknown data object")
            }

            switch selector {
            case "bytes":
                var data: [UInt8] = []
                if case let .data(value) = object.value {
                    data = value
                }

                let pointer = try alloc(UInt64(data.count))
                try memWrite(pointer, data)
                try set(pointer)

                return true
            case "appendBytes:length:":
                let size = try arg(3)
                guard size <= 32 << 20 else {
                    throw StoreRuntimeError.failure("data append exceeds budget")
                }

                let other = try engine.memRead(try arg(2), size)
                var data: [UInt8] = []
                if case let .data(value) = object.value {
                    data = value
                }

                object.value = .data(data + other)
                try set(0)

                return true
            case "appendData:":
                guard let source = objects[try arg(2)], case let .data(other) = source.value else {
                    throw StoreRuntimeError.failure("appendData: source is not data")
                }

                var data: [UInt8] = []
                if case let .data(value) = object.value {
                    data = value
                }

                object.value = .data(data + other)
                try set(0)

                return true
            default:
                break
            }
        }

        return false
    }

    func performHTTP(_ task: UInt64) throws {
        guard let taskObject = objects[task] else {
            throw StoreRuntimeError.failure("unknown data task")
        }

        guard let requestObject = objects[taskObject.properties["currentRequest"] ?? 0] else {
            throw StoreRuntimeError.failure("unknown current request")
        }

        let endpoint = try guestString(requestObject.properties["URL"] ?? 0)
        guard let url = URL(string: endpoint),
              storeAllowedURL(url, authenticated: authRequest || !streamResponse) else {
            throw StoreRuntimeError.failure("unsupported transport URL")
        }

        var body: [UInt8] = []
        if let pointer = requestObject.properties["HTTPBody"], pointer != 0 {
            guard let bodyObject = objects[pointer], case let .data(data) = bodyObject.value else {
                throw StoreRuntimeError.failure("request body is not data")
            }

            body = data
        }

        guard let transport else {
            throw StoreRuntimeError.failure("cannot construct transport request")
        }

        var requestHeaders: [String: String] = [:]
        if let pointer = requestObject.properties["allHTTPHeaderFields"], pointer != 0 {
            guard let headersObject = objects[pointer],
                  case let .dictionary(fields) = headersObject.value else {
                throw StoreRuntimeError.failure("request headers are not a dictionary")
            }

            for (key, value) in fields {
                requestHeaders[canonicalHeaderKey(key)] = try guestString(value)
            }
        }

        let request = StoreHTTPRequest(
            url: endpoint,
            method: try guestString(requestObject.properties["HTTPMethod"] ?? 0),
            headers: requestHeaders,
            body: body
        )

        let response: StoreHTTPResponse
        do {
            response = try transport(request)
        } catch {
            transportError = error
            throw StoreRuntimeError.failure("Store HTTP transport failed")
        }

        let redirect = response.status == 301 || response.status == 302
            || response.status == 303 || response.status == 307 || response.status == 308

        var data: [UInt8] = []

        if streamResponse, !redirect {
            lastResponse = response
        } else {
            data = response.body
            guard data.count <= 32 << 20 else {
                throw StoreRuntimeError.failure("Store API response exceeds size limit")
            }

            var copied = response
            copied.body = data
            lastResponse = copied
        }

        var headers: [String: UInt64] = [:]
        for (key, values) in response.headers {
            headers[key] = try newObject("NSString", .string(values.joined(separator: ", ")))
        }

        let headerObject = try newObject("NSDictionary", .dictionary(headers))
        responseHeaders[headerObject] = response.headers

        let contentType = headerValue(response.headers, "Content-Type")
        let mimeType = contentType.components(separatedBy: ";").first ?? ""

        let responseObject = try newObject("NSHTTPURLResponse", .none)
        objects[responseObject]?.properties = [
            "statusCode": UInt64(response.status),
            "allHeaderFields": headerObject,
            "URL": requestObject.properties["URL"] ?? 0,
            "MIMEType": try newObject("NSString", .string(mimeType)),
            "expectedContentLength": UInt64(response.body.count),
        ]

        taskObject.properties["response"] = responseObject

        let session = taskObject.properties["session"] ?? 0
        let delegate = objects[session]?.properties["delegate"] ?? 0

        let completion = try hostBlock { [unowned self] in
            guard try self.arg(1) == 1 else {
                throw StoreRuntimeError.failure("framework rejected response")
            }

            self.pending.append(try self.hostBlock { [unowned self] in
                try self.delegateCall(delegate, "URLSession:dataTask:didReceiveData:", [
                    session,
                    task,
                    try self.newObject("NSData", .data(data)),
                ]) { [unowned self] in
                    self.pending.append(try self.hostBlock { [unowned self] in
                        taskObject.properties["state"] = 3
                        try self.delegateCall(
                            delegate,
                            "URLSession:task:didCompleteWithError:",
                            [session, task, 0]
                        ) { [unowned self] in
                            try self.set(0)
                        }
                    })
                    try self.set(0)
                }
            })
            try self.set(0)
        }

        let deliver: () throws -> Void = { [unowned self] in
            try self.delegateCall(
                delegate,
                "URLSession:dataTask:didReceiveResponse:completionHandler:",
                [session, task, responseObject, completion]
            ) { [unowned self] in
                try self.set(0)
            }
        }

        if redirect, !noRedirects {
            let location = headerValue(response.headers, "Location")
            guard let destination = URL(string: location) else {
                try deliver()

                return
            }

            guard (taskObject.properties["redirectCount"] ?? 0) < 4 else {
                throw StoreRuntimeError.failure("redirect limit exceeded")
            }

            var invalid = !storeAllowedURL(destination, authenticated: authRequest || !streamResponse)

            if !invalid, authRequest {
                let port = destination.port.map(String.init) ?? ""
                var path = destination.path
                while path.hasSuffix("/") {
                    path.removeLast()
                }

                invalid = response.status == 303
                    || (!port.isEmpty && port != "443")
                    || (URLComponents(url: destination, resolvingAgainstBaseURL: false)?.percentEncodedPath ?? "") != destination.path
                    || !(destination.host ?? "").hasSuffix("buy.itunes.apple.com")
                    || path != "/WebObjects/MZFinance.woa/wa/authenticate"
            }

            guard !invalid else {
                throw StoreRuntimeError.failure("invalid Store redirect destination")
            }

            let proposed = try newObject("NSMutableURLRequest", .none)
            guard let newRequest = objects[proposed] else {
                throw StoreRuntimeError.failure("invalid redirect request")
            }

            for (key, value) in requestObject.properties {
                newRequest.properties[key] = value
            }

            newRequest.properties["URL"] = try newObject("NSURL", .string(destination.absoluteString))

            var fields: [String: UInt64] = [:]
            if let pointer = requestObject.properties["allHTTPHeaderFields"], pointer != 0,
               let headerObject = objects[pointer], case let .dictionary(values) = headerObject.value {
                fields = values
            }

            if destination.host?.lowercased() != url.host?.lowercased() {
                for key in ["Authorization", "Cookie", "X-Token", "X-Dsid", "Icloud-Dsid"] {
                    fields.removeValue(forKey: key)
                }
            }

            let method = try guestString(requestObject.properties["HTTPMethod"] ?? 0)
            if response.status == 303
                || ((response.status == 301 || response.status == 302) && method == "POST") {
                newRequest.properties["HTTPMethod"] = try newObject("NSString", .string("GET"))
                newRequest.properties["HTTPBody"] = 0
                fields.removeValue(forKey: "Content-Length")
                fields.removeValue(forKey: "Content-Type")
            }

            newRequest.properties["allHTTPHeaderFields"] = try newObject(
                "NSMutableDictionary", .dictionary(fields)
            )

            let redirectCompletion = try hostBlock { [unowned self] in
                let next = try self.arg(1)
                if next == 0 {
                    try deliver()

                    return
                }

                guard self.objects[next] != nil else {
                    throw StoreRuntimeError.failure("invalid redirected request")
                }

                taskObject.properties["currentRequest"] = next
                taskObject.properties["redirectCount"] = (taskObject.properties["redirectCount"] ?? 0) + 1

                let block = try self.hostBlock { [unowned self] in
                    try self.performHTTP(task)
                }
                self.queuePending(block, 0)
                try self.set(0)
            }

            try delegateCall(
                delegate,
                "URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:",
                [session, task, responseObject, proposed, redirectCompletion]
            ) { [unowned self] in
                try self.set(0)
            }

            return
        }

        try deliver()
    }

    func delegateCall(_ receiver: UInt64, _ selector: String, _ args: [UInt64],
                      _ after: @escaping () throws -> Void) throws {
        guard let object = objects[receiver] else {
            throw StoreRuntimeError.failure("missing transport delegate")
        }

        let entry = lookup(object.cls, selector, false)
        if entry == 0 {
            let forward = lookup(object.cls, "forwardingTargetForSelector:", false)
            guard forward != 0 else {
                throw StoreRuntimeError.failure("missing transport delegate method \(selector)")
            }

            try callbackFunction(forward, [
                receiver,
                try selectorAddress(for: "forwardingTargetForSelector:"),
                try selectorAddress(for: selector),
            ]) { [unowned self] in
                let target = try self.arg(0)
                guard target != 0, target != receiver else {
                    throw StoreRuntimeError.failure("transport delegate cannot forward \(selector)")
                }

                try self.delegateCall(target, selector, args, after)
            }

            return
        }

        try callbackFunction(entry, [receiver, try selectorAddress(for: selector)] + args, after)
    }

    func validJSONObject(_ address: UInt64, _ top: Bool, _ depth: Int) -> Bool {
        if depth > 64 {
            return false
        }

        guard let object = objects[address] else {
            return false
        }

        switch object.value {
        case let .dictionary(fields):
            for (_, child) in fields where !validJSONObject(child, false, depth + 1) {
                return false
            }

            return true
        case let .array(items):
            guard object.cls.contains("Array") else {
                return false
            }

            for child in items where !validJSONObject(child, false, depth + 1) {
                return false
            }

            return true
        case .string, .bool, .int:
            return !top
        case let .double(value):
            return !top && value.isFinite
        default:
            return !top && object.cls == "NSNull"
        }
    }

    func parserError(_ out: UInt64) throws {
        if out == 0 {
            return
        }

        let errorObject = try newObject("NSError", .dictionary([
            "domain": try newObject("NSString", .string("NSCocoaErrorDomain")),
            "code": try newObject("NSNumber", .int(3840)),
            "userInfo": try newObject("NSDictionary", .dictionary([:])),
        ]))
        try write64(out, errorObject)
    }

    // MARK: Cookie 表示

    /// Go 把 *http.Cookie 存在对象值里；GuestValue 没有该分支，因此用属性字典保存。
    private func cookieValue(_ cookie: StoreCookie) throws -> GuestValue {
        var fields: [String: UInt64] = [:]
        fields["Name"] = try newObject("NSString", .string(cookie.name))
        fields["Value"] = try newObject("NSString", .string(cookie.value))
        fields["Domain"] = try newObject("NSString", .string(cookie.domain))
        fields["Path"] = try newObject("NSString", .string(cookie.path))
        fields["Secure"] = try newObject("NSNumber", .bool(cookie.secure))
        fields["HttpOnly"] = try newObject("NSNumber", .bool(cookie.httpOnly))
        if let expires = cookie.expires {
            fields["Expires"] = try newObject("NSDate", .double(expires.timeIntervalSince1970))
        }

        return .dictionary(fields)
    }

    private func newCookieObject(_ cookie: StoreCookie) throws -> UInt64 {
        try newObject("NSHTTPCookie", try cookieValue(cookie))
    }

    private func cookieFromObject(_ object: GuestObject) throws -> StoreCookie {
        guard case let .dictionary(fields) = object.value else {
            throw StoreRuntimeError.failure("cookie value is not a dictionary")
        }

        return try cookieFromFields(fields)
    }

    private func cookieFromFields(_ fields: [String: UInt64]) throws -> StoreCookie {
        func string(_ key: String) throws -> String {
            guard let pointer = fields[key], pointer != 0 else {
                return ""
            }

            return try guestString(pointer)
        }

        func flag(_ key: String) -> Bool {
            guard let pointer = fields[key], pointer != 0, let object = objects[pointer] else {
                return false
            }

            return guestDescription(object.value)
                .compare("TRUE", options: .caseInsensitive) == .orderedSame
        }

        var expires: Date?
        if let pointer = fields["Expires"], pointer != 0,
           let object = objects[pointer], case let .double(seconds) = object.value {
            expires = Date(timeIntervalSince1970: seconds)
        }

        return StoreCookie(
            name: try string("Name"),
            value: try string("Value"),
            domain: try string("Domain"),
            path: try string("Path"),
            secure: flag("Secure"),
            httpOnly: flag("HttpOnly"),
            expires: expires
        )
    }
}
