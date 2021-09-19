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

    pub fn initSlient(hostname: ?[]const u8, port: ?i32, privkey: ?[]const u8, sestype: SessionType, sigtype: SigType, params: ?[]const u8) Error!Self{
        var result = Self {.session = std.mem.zeroes(c.Sam3Session)};
        const stat = c.sam3CreateSlientSession(
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
