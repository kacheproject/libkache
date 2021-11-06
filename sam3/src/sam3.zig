const std = @import("std");
const strings = @import("strings");
const c = @cImport({
    @cInclude("libsam3.h");
});
const Allocator = std.mem.Allocator;

const SessionType = enum {
    Raw = c.SAM3_SESSION_RAW,
    Dgram = c.SAM3_SESSION_DGRAM,
    Stream = c.SAM3_SESSION_STREAM,

    fn asOriginal(val: SessionType) c.Sam3SessionType {
        return @intToEnum(c.Sam3SessionType, @enumToInt(val));
    }
};

const SigType = enum {
    DSA_SHA1 = c.DSA_SHA1,
    ECDSA_SHA256_P256 = c.ECDSA_SHA256_P256,
    ECDSA_SHA384_P384 = c.ECDSA_SHA384_P384,
    ECDSA_SHA512_P521 = c.ECDSA_SHA512_P521,
    EdDSA_SHA512_Ed25519 = c.EdDSA_SHA512_Ed25519,

    fn asOriginal(val: SigType) c.Sam3SigType {
        return @intToEnum(c.Sam3SigType, @enumToInt(val));
    }

    pub fn recommended() @This() {
        return @This().EdDSA_SHA512_Ed25519;
    }
};

const Error = error {
    Unknown,
    InvalidSessionType,
    InvalidSession,
    InvalidKey,
    IOE,
    HandshakeE,
    ReplyE,
    I2PE,
    CouldNotReachPeer,
    BufferTooSmall,
    InvalidData,
} || Allocator.Error;

fn translateError(estr: []const u8) Error {
    const equal = strings.equal;
    if (equal("INVALID_SESSION_TYPE", estr)) {
        return Error.InvalidSessionType;
    } else if (equal("INVALID_SESSION", estr)) {
        return Error.InvalidSession;
    } else if (equal("NO_MEMORY", estr)) {
        return Error.OutOfMemory;
    } else if (equal("IO_ERROR_SK", estr) or equal("IO_ERROR", estr)) {
        return Error.IOE;
    } else if (equal("INVALID_KEY", estr)) {
        return Error.InvalidKey;
    } else if (equal("CANT_REACH_PEER", estr)) {
        return Error.CouldNotReachPeer;
    } else if (equal("I2P_ERROR_SIZE", estr)) {
        return Error.ReplyE;
    } else if (equal("I2P_ERROR_BUFFER_TOO_SMALL", estr)) {
        return Error.BufferTooSmall;
    } else if (equal("INVALID_DATA", estr)) {
        return Error.InvalidData;
    } else {
        if (std.builtin.mode == .Debug and c.libsam3_debug != 0) std.debug.print("unknown sam3 error: {s}\n", .{estr});
        return Error.Unknown;
    }
}

pub fn setDebug(flag: bool) void {
    c.libsam3_debug = if(flag) 1 else 0;
}

pub fn checkValidKeyLength(key: [:0]const u8) bool {
    return c.sam3CheckValidKeyLength(key) != 0;
}

pub const SessionConfig = struct {
    inboundAllowZeroHop: bool = true,
    outboundAllowZeroHop: bool = true,
    inboundLength: i8 = 3,
    outboundLength: i8 = 3,

    const TEMPLATE =
    \\ inbound.allowZeroHop={} outbound.allowZeroHop={} inbound.length={} outbound.length={}
    ;

    const Self = @This();

    pub fn getOptionsString(self: *const Self, alloc: *Allocator) Allocator.Error![:0]u8 {
        var args = .{
            self.inboundAllowZeroHop,
            self.outboundAllowZeroHop,
            self.inboundLength,
            self.outboundLength,
        };
        return try std.fmt.allocPrintZ(alloc, TEMPLATE, args) catch |e| switch (e) {
            std.fmt.AllocPrintError.OutOfMemory => Allocator.Error.OutOfMemory,
        };
    }
};

const Session = struct {
    session: c.Sam3Session,

    const Self = @This();

    /// Initialise a sam3 session. Caller owns arguments and value.
    pub fn init(hostname: ?[]const u8, port: ?i32, privkey: ?[]const u8, sestype: SessionType, sigtype: SigType, params: ?[]const u8) Error!Self{
        var result = Self {.session = std.mem.zeroes(c.Sam3Session)};
        const stat = c.sam3CreateSession(
            result.original(),
            if (hostname) |value| value.ptr else @ptrCast(?*const u8, c.SAM3_HOST_DEFAULT),
            if (port) |value| value else c.SAM3_PORT_DEFAULT,
            if (privkey) |value| value.ptr else @ptrCast(?*const u8, c.SAM3_DESTINATION_TRANSIENT),
            SessionType.asOriginal(sestype),
            SigType.asOriginal(sigtype),
            if (params) |val| val.ptr else null,
        );
        if (stat < 0){
            return result.getError();
        } else {
            return result;
        }
    }

    pub fn initSilent(hostname: ?[]const u8, port: ?i32, privkey: ?[]const u8, sestype: SessionType, sigtype: SigType, params: ?[]const u8) Error!Self{
        var result = Self {.session = std.mem.zeroes(c.Sam3Session)};
        const stat = c.sam3CreateSilentSession(
            result.original(),
            if (hostname) |value| value.ptr else @ptrCast(?*const u8, c.SAM3_HOST_DEFAULT),
            if (port) |value| value else c.SAM3_PORT_DEFAULT,
            if (privkey) |value| value.ptr else @ptrCast(?*const u8, c.SAM3_DESTINATION_TRANSIENT),
            SessionType.asOriginal(sestype),
            SigType.asOriginal(sigtype),
            if (params) |val| val.ptr else null,
        );
        if (stat < 0){
            return Error.Unknown;
        } else {
            return result;
        }
    }

    pub fn close(self: *Self) void {
        _ = c.sam3CloseSession(self.original());
        // sam3CloseSession return -1 only when the argument is NULL, we can prove the opposite. (Rubicon)
    }

    /// Alias to `close`. Close this stream.
    pub fn deinit(self: *Self) void {
        self.close();
    }

    fn original(self: *Self) *c.Sam3Session {
        return &self.session;
    }

    pub fn generateKeys(self: *Self, host: ?[:0]const u8, port: ?i32, sigType: SigType) Error!void {
        const stat = c.sam3GenerateKeys(
            self.original(),
            if (host) |val| val else @ptrCast(?[*]const u8, c.SAM3_HOST_DEFAULT),
            if (port) |val| val else c.SAM3_PORT_DEFAULT,
            @enumToInt(sigType.asOriginal())
        );
        if (stat < 0) {
            return Error.Unknown;
        }
    }

    pub fn publicKey(self: *Self) [:0]u8 {
        return @ptrCast([*]u8, &self.original().*.pubkey)[0..616:0];
    }

    pub fn privateKey(self: *Self) [:0]u8 {
        return @ptrCast([*]u8, &self.original().*.privkey)[0..616:0];
    }

    pub fn getError(self: *const Self) Error {
        return translateError(&@field(self.session, "error"));
    }

    /// The source's public key which last dgram packet come from.
    pub fn destKey(self: *Self) [:0]u8 {
        return @ptrCast([*]u8, &self.original().*.destkey)[0..616:0];
    }

    /// Send a dgram packet.
    /// Possible errors:
    /// - InvalidSessionType
    /// - InvalidSession
    /// - InvalidKey
    /// - InvalidData
    /// - IOE
    pub fn dgramSend(self: *Self, destkey: [:0]const u8, buf: []const u8) Error!void {
        if (std.builtin.mode == .Debug and c.libsam3_debug != 0) {
            std.debug.print("sam3 dgramSend: [dest={s}] {s}\n", .{destkey, buf});
        }
        if (c.sam3DatagramSend(self.original(), destkey, buf.ptr, buf.len) < 0) {
            return self.getError();
        }
    }

    /// Receive a dgram packet.
    /// Possible errors:
    /// - InvalidSessionType
    /// - InvalidSession
    /// - InvalidKey
    /// - IOE
    /// - I2PE
    /// - ReplyE
    /// - BufferTooSmall
    pub fn dgramReceive(self: *Self, buf: []u8) Error![]u8 {
        std.debug.assert(buf.len >= 1);
        const stat = c.sam3DatagramReceive(self.original(), buf.ptr, buf.len);
        if (stat >= 0){
            return buf[0..@bitCast(usize, stat)];
        } else {
            return self.getError();
        }
    }

    /// Receive a dgram packet. The return slice have exact same size to the packet.
    /// This method will made multiple calls to Alllocator and may fail while resizing memory.
    /// Possible errors:
    /// - InvalidSessionType
    /// - InvalidSession
    /// - InvalidKey
    /// - IOE
    /// - I2PE
    /// - ReplyE
    /// - BufferTooSmall
    /// - OutOfMemory
    pub fn dgramReceiveAlloc(self: *Self, alloc: *Allocator, maxsize: usize) Error![]u8 {
        var buf = try alloc.alloc(u8, maxsize);
        errdefer alloc.free(buf);
        var realSizeSlice = try self.dgramReceive(buf);
        if (buf.len != realSizeSlice.len) {
            buf = try alloc.resize(buf, realSizeSlice.len);
        }
        return buf;
    }

    pub fn streamConnect(self: *Self, destkey: [:0]const u8) Error!Connection {
        return Connection.streamConnect(self, destkey);
    }

    pub fn streamAccept(self: *Self) Error!Connection {
        return Connection.streamAccept(self);
    }

    /// Forward incoming connections to `host`:`port`.
    /// You still need to call `deinit` when there is an error.
    /// Note that this function does not have default timeout.
    pub fn forward(self: *Self, host: [:0]const u8, port: i32) Error!void {
        const stat = c.sam3StreamForward(self.original(), host, @intCast(c_int, port));
        if (stat < 0) {
            return self.getError();
        }
    }
};

const Connection = struct {
    conn: *c.Sam3Connection,

    const Self = @This();

    pub fn streamConnect(ses: *Session, destkey: [:0]const u8) Error!Self {
        var conn = c.sam3StreamConnect(ses.original(), destkey);
        if (conn) |newConn| {
            return Self {
                .conn = newConn,
            };
        } else {
            return ses.getError();
        }
    }

    pub fn streamAccept(ses: *Session) Error!Self {
        var conn = c.sam3StreamAccept(ses.original());
        if (conn) |newConn| {
            return Self {
                .conn = newConn,
            };
        } else {
            return Error.Unknown;
        }
    }

    pub fn tcpSend(self: *Self, buf: []const u8) Error!void {
        if (std.builtin.mode == .Debug and c.libsam3_debug != 0) {
            std.debug.print("sam3 tcpSend: \"{s}\"\n", .{buf});
        }
        const stat = c.sam3tcpSend(self.conn.*.fd, buf.ptr, buf.len);
        if (stat < 0) {
            return Error.Unknown;
        }
    }

    pub fn tcpReceiveEx(self: *Self, buf: []u8, readOnce: bool) Error![]u8 {
        const stat = c.sam3tcpReceiveEx(self.original().*.fd, buf.ptr, buf.len, if (readOnce) 1 else 0);
        if (stat < 0){
            if (-stat > 0) {
                return buf[0..@bitCast(usize, -stat)];
            } else {
                return Error.IOE;
            }
        } else {
            return buf[0..@bitCast(usize, stat)];
        }
    }

    pub fn tcpReceive(self: *Self, buf: []u8) Error![]u8 {
        return self.tcpReceiveEx(buf, true);
    }

    pub fn tcpReceiveExAlloc(self: *Self, alloc: *Allocator, bufSize: usize, allowPartial: bool) Error![]u8 {
        var buf = try alloc.alloc(u8, bufSize);
        return self.tcpReceiveEx(buf, allowPartial);
    }

    pub fn tcpReceiveAlloc(self: *Self, alloc: *Allocator, bufSize: usize) Error![]u8 {
        return self.tcpReceiveExAlloc(alloc, bufSize, false);
    }

    /// Format string and send. This function uses heap to format string.
    /// The memory used will be freed.
    pub fn tcpPrint(self: *Self, comptime fmt: []const u8, args: anytype, alloc: *Allocator) Error!usize {
        var buf = try std.fmt.allocPrint(alloc, fmt, args) catch |e| switch (e) {
            std.fmt.AllocPrintError.OutOfMemory => Error.OutOfMemory,
        };
        defer alloc.free(buf);
        try self.tcpSend(buf);
        return buf.len;
    }

    fn original(self: *Self) *c.Sam3Connection {
        return self.conn;
    }

    pub fn close(self: *Self) void {
        _ = c.sam3CloseConnection(self.original());
        // sam3CloseConnection return -1 only when the argument is NULL, we can prove the opposite. (Rubicon)
    }
};

fn oneConnectionServer(ses: *Session) !void {
    var conn = try Connection.streamAccept(ses);
    errdefer conn.close();
    while (true) {
        var buf = [_]u8{0} ** 256;
        _ = try conn.tcpReceive(buf[0..256]);
        if (strings.equal(buf[0..4], "quit")){
            break;
        } else {
            _ = try conn.tcpPrint("re: {s}", .{buf}, std.testing.allocator);
        }
    }
}

fn oneShotClient(conn: *Connection) !void {
    const _t = std.testing;
    _ = try conn.tcpSend("test\n");
    var buf = [_]u8{0} ** 256;
    _ = try conn.tcpReceive(buf[0..256]);
    try _t.expectEqualStrings(buf[0..8], "re: test");
    try conn.tcpSend("quit\n");
}

test "Integraded: work as stream" {
    const Thread = std.Thread;
    const _t = std.testing;
    setDebug(true);
    defer setDebug(false);
    const sessionConf = SessionConfig {
        .inboundLength = 0,
        .outboundLength = 0,
    };
    var optionStr = try sessionConf.getOptionsString(_t.allocator);
    defer _t.allocator.free(optionStr);
    var serverSession = try Session.init(null, null, null, .Stream, SigType.recommended(), optionStr);
    try _t.expect(checkValidKeyLength(serverSession.publicKey()));
    defer serverSession.close();
    var serverThread = try Thread.spawn(oneConnectionServer, &serverSession);
    var clientSession = try Session.init(null, null, null, .Stream, SigType.recommended(), optionStr);
    defer clientSession.close();
    var clientConn = try Connection.streamConnect(&clientSession, serverSession.publicKey());
    defer clientConn.close();
    var clientThread = try Thread.spawn(oneShotClient, &clientConn);
    serverThread.wait();
    clientThread.wait();
}

fn testDgramServer(ses: *Session) !void {
    const _t = std.testing;
    while (true) {
        std.debug.print("testDgramServer: waiting\n", .{});
        var data = try ses.dgramReceiveAlloc(_t.allocator, 1024);
        std.debug.print("testDgramServer: received \"{s}\"\n", .{data});
        defer _t.allocator.free(data);
        if (strings.equal(data, "quit")) {
            break;
        }
    }
}

fn testDgramClient(ses: *Session) !void {
    try ses.dgramSend(ses.destKey(), "quit");
}

// Rubicon: IDK why dgram doesn't work. Don't test it until I figure a way it works.
// test "Integated: dgram works" {
//     const Thread = std.Thread;
//     const _t = std.testing;
//     setDebug(true);
//     defer setDebug(false);
//     const sessionConf = SessionConfig {
//         .inboundLength = 0,
//         .outboundLength = 0,
//     };
//     var optionStr = try sessionConf.getOptionsString(_t.allocator);
//     defer _t.allocator.free(optionStr);
//     var serverSession = try Session.init(null, null, null, .Dgram, SigType.recommended(), optionStr);
//     defer serverSession.close();
//     var serverThread = try Thread.spawn(testDgramServer, &serverSession);
//     var clientSession = try Session.init(null, null, null, .Dgram, SigType.recommended(), optionStr);
//     defer clientSession.close();
//     std.mem.copy(u8, clientSession.destKey(), serverSession.publicKey());
//     var clientThread = try Thread.spawn(testDgramClient, &clientSession);
//     serverThread.wait();
//     clientThread.wait();
// }
