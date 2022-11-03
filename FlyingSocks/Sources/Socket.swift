//
//  Socket.swift
//  FlyingFox
//
//  Created by Simon Whitty on 13/02/2022.
//  Copyright © 2022 Simon Whitty. All rights reserved.
//
//  Distributed under the permissive MIT license
//  Get the latest version from here:
//
//  https://github.com/swhitty/FlyingFox
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//

#if canImport(WinSDK)
import WinSDK.WinSock2
#endif
import Foundation

public struct Socket: Sendable, Hashable {

    public let file: FileDescriptor

    public struct FileDescriptor: RawRepresentable, Sendable, Hashable {
        public var rawValue: Socket.FileDescriptorType

        public init(rawValue: Socket.FileDescriptorType) {
            self.rawValue = rawValue
        }
    }

    public init(file: FileDescriptor) {
        self.file = file
    }

    public init(domain: Int32) throws {
        try self.init(domain: domain, type: Socket.stream)
    }

    public init(domain: Int32, type: Int32) throws {
        let descriptor = FileDescriptor(rawValue: Socket.socket(domain, type, 0))
        guard descriptor != .invalid else {
            throw SocketError.makeFailed("CreateSocket")
        }
        self.file = descriptor
    }

    public var flags: Flags {
        get throws {
            let flags = Socket.fcntl(file.rawValue, F_GETFL)
            if flags == -1 {
                throw SocketError.makeFailed("GetFlags")
            }
            return Flags(rawValue: flags)
        }
    }

    public func setFlags(_ flags: Flags) throws {
        if Socket.fcntl(file.rawValue, F_SETFL, flags.rawValue) == -1 {
            throw SocketError.makeFailed("SetFlags")
        }
    }

    public func setValue<O: SocketOption>(_ value: O.Value, for option: O) throws {
        // This method exists so that users can still supply `.member` syntax for the `option`
        // parameter for SocketOption members.
        try setValueImpl(value, for: option)
    }

    public func setValue<O: SettableSocketOption>(_ value: O.Value, for option: O) throws {
        try setValueImpl(value, for: option)
    }

    private func setValueImpl<O: SettableSocketOption>(_ value: O.Value, for option: O) throws {
        var value = option.makeSocketValue(from: value)
        let length = socklen_t(MemoryLayout<O.SocketValue>.size)
        guard Socket.setsockopt(file.rawValue, option.getLevel(), option.name, &value, length) >= 0 else {
            throw SocketError.makeFailed("SetOption")
        }
    }

    public func getValue<O: SocketOption>(for option: O) throws -> O.Value {
        // This method exists so that users can still supply `.member` syntax for the `option`
        // parameter for SocketOption members.
        try getValueImpl(for: option)
    }

    public func getValue<O: GettableSocketOption>(for option: O) throws -> O.Value {
        try getValueImpl(for: option)
    }

    public func getValueImpl<O: GettableSocketOption>(for option: O) throws -> O.Value {
        let valuePtr = UnsafeMutablePointer<O.SocketValue>.allocate(capacity: 1)
        var length = socklen_t(MemoryLayout<O.SocketValue>.size)
        guard Socket.getsockopt(file.rawValue, option.getLevel(), option.name, valuePtr, &length) >= 0 else {
            throw SocketError.makeFailed("GetOption")
        }
        return option.makeValue(from: valuePtr.pointee)
    }

    public func bind<A: SocketAddress>(to address: A) throws {
        var addr = address
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Socket.bind(file.rawValue, $0, socklen_t(MemoryLayout<A>.size))
            }
        }
        guard result >= 0 else {
            throw SocketError.makeFailed("Bind")
        }
    }

    public func bind(to storage: sockaddr_storage) throws {
        switch Int32(storage.ss_family) {
        case AF_INET:
            try bind(to: sockaddr_in.make(from: storage))
        case AF_INET6:
            try bind(to: sockaddr_in6.make(from: storage))
        case AF_UNIX:
            try bind(to: sockaddr_un.make(from: storage))
        default:
            throw SocketError.unsupportedAddress
        }
    }

    public func listen(maxPendingConnection: Int32 = SOMAXCONN) throws {
        if Socket.listen(file.rawValue, maxPendingConnection) == -1 {
            let error = SocketError.makeFailed("Listen")
            try close()
            throw error
        }
    }

    public func remotePeer() throws -> Address {
        var addr = sockaddr_storage()
        var len = socklen_t(MemoryLayout<sockaddr_storage>.size)

        let result = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Socket.getpeername(file.rawValue, $0, &len)
            }
        }
        if result != 0 {
            throw SocketError.makeFailed("GetPeerName")
        }
        return try Self.makeAddress(from: addr)
    }

    public func sockname() throws -> Address {
        var addr = sockaddr_storage()
        var len = socklen_t(MemoryLayout<sockaddr_storage>.size)

        let result = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Socket.getsockname(file.rawValue, $0, &len)
            }
        }
        if result != 0 {
            throw SocketError.makeFailed("GetSockName")
        }
        return try Self.makeAddress(from: addr)
    }

    public func accept() throws -> (file: FileDescriptor, addr: sockaddr_storage) {
        var addr = sockaddr_storage()
        var len = socklen_t(MemoryLayout<sockaddr_storage>.size)

        let newFile = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                FileDescriptor(rawValue: Socket.accept(file.rawValue, $0, &len))
            }
        }

        guard newFile != .invalid else {
            if errno == EWOULDBLOCK {
                throw SocketError.blocked
            } else {
                throw SocketError.makeFailed("Accept")
            }
        }

        return (newFile, addr)
    }

    public func connect<A: SocketAddress>(to address: A) throws {
        var addr = address
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Socket.connect(file.rawValue, $0, socklen_t(MemoryLayout<A>.size))
            }
        }
        guard result >= 0 || errno == EISCONN else {
            if errno == EINPROGRESS {
                throw SocketError.blocked
            } else {
                throw SocketError.makeFailed("Connect")
            }
        }
    }

    public func recvFrom(atMost length: Int) throws -> ([UInt8], sockaddr_storage) {
        var sender = sockaddr_storage()
        var sockaddrLength = UInt32(MemoryLayout<sockaddr_storage>.stride)
        let bytes = try [UInt8](unsafeUninitializedCapacity: length) { buffer, count in
            withUnsafeMutablePointer(to: &sender) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { pointer in
                    count = recvfrom(file.rawValue, buffer.baseAddress, length, 0, pointer, &sockaddrLength)
                }
            }

            guard count > 0 else {
                if errno == EWOULDBLOCK {
                    throw SocketError.blocked
                } else if errno == EBADF || count == 0 {
                    throw SocketError.disconnected
                } else {
                    throw SocketError.makeFailed("Read")
                }
            }
        }
        return (bytes, sender)
    }

    public func read() throws -> UInt8 {
        var byte: UInt8 = 0
        _ = try withUnsafeMutablePointer(to: &byte) { buffer in
            try read(into: buffer, length: 1)
        }
        return byte
    }

    public func read(atMost length: Int) throws -> [UInt8] {
        try [UInt8](unsafeUninitializedCapacity: length) { buffer, count in
            count = try read(into: buffer.baseAddress!, length: length)
        }
    }

    private func read(into buffer: UnsafeMutablePointer<UInt8>, length: Int) throws -> Int {
        let count = Socket.read(file.rawValue, buffer, length)
        guard count > 0 else {
            if errno == EWOULDBLOCK {
                throw SocketError.blocked
            } else if errno == EBADF || count == 0 {
                throw SocketError.disconnected
            } else {
                throw SocketError.makeFailed("Read")
            }
        }
        return count
    }

    public func write(_ data: Data, from index: Data.Index = 0) throws -> Data.Index {
        precondition(index >= 0)
        guard index < data.endIndex else { return data.endIndex }
        return try data.withUnsafeBytes { buffer in
            let sent = try write(buffer.baseAddress! + index - data.startIndex, length: data.endIndex - index)
            return index + sent
        }
    }

    private func write(_ pointer: UnsafeRawPointer, length: Int) throws -> Int {
        let sent = Socket.write(file.rawValue, pointer, length)
        guard sent > 0 else {
            if errno == EWOULDBLOCK {
                throw SocketError.blocked
            } else if errno == EBADF {
                throw SocketError.disconnected
            } else {
                throw SocketError.makeFailed("Write")
            }
        }
        return sent
    }

    public func close() throws {
        if Socket.close(file.rawValue) == -1 {
            throw SocketError.makeFailed("Close")
        }
    }
}

public extension Socket {
    struct Flags: OptionSet {
        public var rawValue: Int32

        public init(rawValue: Int32) {
            self.rawValue = rawValue
        }

        public static let nonBlocking = Flags(rawValue: O_NONBLOCK)
    }
}

public extension Socket {

    enum Event {
        case read
        case write
    }

    typealias Events = Set<Event>
}

extension Socket.Event: CustomStringConvertible {
    public var description: String {
        switch self {
        case .read:
            return "read"
        case .write:
            return "write"
        }
    }
}

public extension Socket.Events {
    static let read: Self = [.read]
    static let write: Self = [.write]
    static let connection: Self = [.read, .write]
}

public protocol SettableSocketOption {
    associatedtype Value
    associatedtype SocketValue

    var name: Int32 { get }
    func getLevel() -> Int32
    func makeSocketValue(from value: Value) -> SocketValue
}

public protocol GettableSocketOption {
    associatedtype Value
    associatedtype SocketValue

    var name: Int32 { get }
    func getLevel() -> Int32
    func makeValue(from socketValue: SocketValue) -> Value
}

public protocol SocketOption: SettableSocketOption, GettableSocketOption {
    associatedtype Value
    associatedtype SocketValue

    var name: Int32 { get }
    func getLevel() -> Int32
    func makeValue(from socketValue: SocketValue) -> Value
    func makeSocketValue(from value: Value) -> SocketValue
}

extension SettableSocketOption {
    public func getLevel() -> Int32 {
        SOL_SOCKET
    }
}

extension GettableSocketOption {
    public func getLevel() -> Int32 {
        SOL_SOCKET
    }
}

extension SocketOption {
    public func getLevel() -> Int32 {
        SOL_SOCKET
    }
}

public struct BoolSocketOption: SocketOption {
    public var name: Int32

    public init(name: Int32) {
        self.name = name
    }

    public func makeValue(from socketValue: Int32) -> Bool {
        socketValue > 0
    }

    public func makeSocketValue(from value: Bool) -> Int32 {
        value ? 1 : 0
    }
}

public struct MembershipRequest {
    public var groupAddress: in_addr
    public var localAddress: in_addr

    public init(groupAddress: in_addr, localAddress: in_addr) {
        self.groupAddress = groupAddress
        self.localAddress = localAddress
    }
}

public struct TimeValue {
    public var seconds: Int
    public var microSeconds: Int

    public init(seconds: Int = 0, microSeconds: Int = 0) {
        self.seconds = seconds
        self.microSeconds = microSeconds
    }
}

public typealias Int32SocketOption = SimpleSocketOption<Int32>
public typealias TimeSocketOption = SimpleSocketOption<TimeValue>

public struct MembershipRequestSocketOption: SettableSocketOption {
    public var name: Int32

    public init(name: Int32) {
        self.name = name
    }

    public func getLevel() -> Int32 {
        IPPROTO_IP
    }

    public func makeSocketValue(from value: MembershipRequest) -> MembershipRequest {
        value
    }
}

public struct SimpleSocketOption<T>: SocketOption {
    public var name: Int32

    public init(name: Int32) {
        self.name = name
    }

    public func makeValue(from socketValue: T) -> T {
        socketValue
    }

    public func makeSocketValue(from value: T) -> T {
        value
    }
}

public extension SocketOption where Self == BoolSocketOption {
    static var localAddressReuse: Self {
        BoolSocketOption(name: SO_REUSEADDR)
    }

    #if canImport(Darwin)
    // Prevents SIG_TRAP when app is paused / running in background.
    static var noSIGPIPE: Self {
        BoolSocketOption(name: SO_NOSIGPIPE)
    }
    #endif
}

public extension SettableSocketOption where Self == MembershipRequestSocketOption {
    static var addMembership: Self {
        MembershipRequestSocketOption(name: IP_ADD_MEMBERSHIP)
    }

    static var dropMembership: Self {
        MembershipRequestSocketOption(name: IP_DROP_MEMBERSHIP)
    }
}

public extension SocketOption where Self == Int32SocketOption {
    static var sendBufferSize: Self {
        Int32SocketOption(name: SO_SNDBUF)
    }

    static var receiveBufferSize: Self {
        Int32SocketOption(name: SO_RCVBUF)
    }
}

public extension SocketOption where Self == TimeSocketOption {
    static var receiveTimeout: Self {
        TimeSocketOption(name: SO_RCVTIMEO)
    }

    static var sendTimeout: Self {
        TimeSocketOption(name: SO_SNDTIMEO)
    }
}
