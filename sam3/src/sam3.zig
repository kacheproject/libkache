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
} || Allocator.Error;

pub fn setDebug(flag: bool) void {
    c.libsam3_debug = if(flag) 1 else 0;
}

pub fn checkValidKeyLength(key: []const u8) bool {
    return key.len == 616;
}

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
            return Error.Unknown;
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

    pub fn generateKeys(self: *Self, host: []const u8, port: i32, sigType: SigType) Error!void {
        const stat = c.sam3GenerateKeys(self.original(), host, port, sigType.asOriginal());
        if (stat < 0) {
            return Error.Unknown;
        }
    }

    pub fn publicKey(self: *Self) [616:0]u8 {
        return @bitCast([616:0]u8, self.original().*.pubkey);
    }

    pub fn publicKeySlice(self: *Self) []u8 {
        return self.publicKey()[0..617];
    }

    pub fn privateKey(self: *Self) [616:0]u8 {
        return @bitCast([616:0]u8, self.original().*.prikey);
    }

    pub fn privateKeySlice(self: *Self) []u8 {
        return self.privateKey()[0..617];
    }
};

const Connection = struct {
    conn: *c.Sam3Connection,

    const Self = @This();

    pub fn streamConnect(ses: *Session, destkey: []const u8) Error!Self {
        var conn = c.sam3StreamConnect(ses.original(), destkey.ptr);
        if (conn) |newConn| {
            return Self {
                .conn = newConn,
            };
        } else {
            return Error.Unknown;
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
        const stat = c.sam3tcpSend(self.conn.*.fd, buf.ptr, buf.len);
        if (stat < 0) {
            return Error.Unknown;
        }
    }

    pub fn tcpReceiveEx(self: *Self, buf: []u8, allowPartial: bool) Error!usize {
        const stat = c.sam3tcpReceiveEx(self.original().*.fd, buf.ptr, buf.len, if (allowPartial) 1 else 0);
        if (stat < 0){
            return Error.Unknown;
        } else {
            return @intCast(usize, stat);
        }
    }

    pub fn tcpReceive(self: *Self, buf: []u8) Error!usize {
        return self.tcpReceiveEx(buf, false);
    }

    pub fn tcpReceiveExAlloc(self: *Self, alloc: *Allocator, bufSize: usize, allowPartial: bool) Error!usize {
        var buf = try alloc.alloc(u8, bufSize);
        return self.tcpReceiveEx(buf, allowPartial);
    }

    pub fn tcpReceiveAlloc(self: *Self, alloc: *Allocator, bufSize: usize) Error!usize {
        return self.tcpReceiveExAlloc(alloc, bufSize, false);
    }

    pub fn tcpPrint(self: *Self, comptime fmt: []const u8, args: anytype, alloc: *Allocator) Error!usize {
        var buf = try alloc.alloc(u8, std.fmt.count(fmt, args)); // This std.fmt.count() will be evaluted at compile-time
        defer alloc.free(buf);
        _ = std.fmt.bufPrint(buf, fmt, args) catch unreachable; // The buffer size should fit.
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
        if (strings.equal(buf[0..3], "quit")){
            break;
        } else {
            _ = try conn.tcpPrint("re: {s}", .{buf}, std.testing.allocator);
        }
    }
}

fn oneShotClient(conn: *Connection) !void {
    const _t = std.testing;
    _ = try conn.tcpPrint("test\n", .{}, std.testing.allocator);
    var buf = [_]u8{0} ** 256;
    _ = try conn.tcpReceive(buf[0..256]);
    try _t.expectEqualStrings(buf[0..256], "re: test");
    try conn.tcpSend("quit\n");
}

test "Integraded: work as stream" {
    const Thread = std.Thread;
    const _t = std.testing;
    setDebug(true);
    defer setDebug(false);
    var serverSession = try Session.init(null, null, null, .Stream, SigType.recommended(), null);
    defer serverSession.close();
    var serverThread = try Thread.spawn(oneConnectionServer, &serverSession);
    var clientSession = try Session.init(null, null, null, .Stream, SigType.recommended(), null);
    defer clientSession.close();
    var clientConn = try Connection.streamConnect(&clientSession, serverSession.publicKeySlice());
    defer clientConn.close();
    var clientThread = try Thread.spawn(oneShotClient, &clientConn);
    clientThread.wait();
    serverThread.wait();
}
