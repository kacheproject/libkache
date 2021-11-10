const std = @import("std");
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("zmq.h");
});

const _l = std.log.scoped(.ZMQ);

pub const SNDMORE = c.ZMQ_SNDMORE;
pub const DONTWAIT = c.ZMQ_DONTWAIT;

pub const SocketType = enum(c_int) {
    Req = c.ZMQ_REQ,
    Rep = c.ZMQ_REP,
    Router = c.ZMQ_ROUTER,
    Dealer = c.ZMQ_DEALER,
    Pub = c.ZMQ_PUB,
    Sub = c.ZMQ_SUB,
    XPub = c.ZMQ_XPUB,
    XSub = c.ZMQ_XSUB,
    Pair = c.ZMQ_PAIR,
    Pull = c.ZMQ_PULL,
    Push = c.ZMQ_PUSH,
};

pub const Error = error{
    Unknown,
    Invalid,
    Interrupted,
    Terminated,
    InvalidContext,
    InvalidSocket,
    TooManyFiles,
};

pub const IOError = error{
    Again,
    NotSupported,
    NoMultipart,
    FailedStateMachine,
    Terminated,
    InvalidSocket,
    Interrupted,
    HostUnreached,
    FrameTooLarge,
};

pub const FileError = error{
    InvalidEndpoint,
    NotSupportedProtocol,
    IncompatiableProtocol,
    AddressInUse,
    NotALocalAddress,
    NoDevice,
    Terminated,
    InvalidSocket,
    NoIOThread,
};

fn translateFileError(errno: c_int) FileError {
    return switch (errno) {
        c.EINVAL => FileError.InvalidEndpoint,
        c.EPROTONOSUPPORT => FileError.NotSupportedProtocol,
        c.ENOCOMPATPROTO => FileError.IncompatiableProtocol,
        c.EADDRINUSE => FileError.AddressInUse,
        c.EADDRNOTAVAIL => FileError.NotALocalAddress,
        c.ENODEV => FileError.NoDevice,
        c.ETERM => FileError.Terminated,
        c.ENOTSOCK => FileError.InvalidSocket,
        c.EMTHREAD => FileError.NoIOThread,
        else => unreachable,
    };
}

fn getErrNo() c_int {
    var no = c.zmq_errno();
    _l.warn("getErrorNo(): {} {s}", .{no, c.zmq_strerror(no)});
    return no;
}

pub const Context = struct {
    _ctx: *c_void,

    const Self = @This();

    pub const Opt = enum (c_int) {
        Blocky = c.ZMQ_BLOCKY,
        IOThreads = c.ZMQ_IO_THREADS,
    };

    pub fn init() Error!Self {
        var zctx = c.zmq_ctx_new();
        if (zctx) |ctx| {
            return Self{
                ._ctx = ctx,
            };
        } else {
            return Error.Unknown;
        }
    }

    pub fn term(self: *Self) !void {
        const stat = c.zmq_ctx_term(self._ctx);
        switch (stat) {
            c.EFAULT => return Error.InvalidContext,
            c.EINTR => return Error.Interrupted,
            else => {},
        }
    }

    pub fn deinit(self: *Self) void {
        self.term() catch |e| switch (e) {
            Error.InvalidContext => unreachable,
            else => {},
        };
    }

    pub fn socket(self: *Self, comptime typ: SocketType) Error!Socket {
        var sock = c.zmq_socket(self._ctx, @bitCast(c_int, typ));
        if (sock) |realSock| {
            return Socket.init(RawSocket.init(realSock));
        } else {
            return switch (getErrNo()) {
                c.EINVAL => Error.Invalid,
                c.EFAULT => Error.InvalidContext,
                c.EMFILE => Error.TooManyFiles,
                c.ETERM => Error.Terminated,
                else => Error.Unknown,
            };
        }
    }

    /// Create a monitor socket.
    pub fn monitor(self: *Self, sock: *Socket, events: anytype) (Error||FileError)!Socket {
        var monitorSock = try self.socket(.Pair);
        errdefer monitorSock.deinit();
        var addr = genRandomInprocAddress("monitor-", 63);
        try sock.startMonitor(&addr, events);
        try monitorSock.connect(&addr);
        return monitorSock;
    }

    pub fn setOpt(self: *Self, opt: Opt, comptime T: type, value: T) void {
        var val = switch (T) {
            bool => @as(c_int, if (value) 1 else 0),
            else => switch (@typeInfo(T)) {
                .ComptimeInt, .Int => value,
                else => unreachable,
            },
        };
        const stat = c.zmq_ctx_set(self._ctx, @enumToInt(opt), val);
        if (stat < 0) unreachable;
    }

    pub fn getOpt(self: *Self, opt: Opt, comptime T: type) T {
        var val = c.zmq_ctx_get(self._ctx, @enumToInt(opt));
        if (val == -1) unreachable;
        return switch (T) {
            bool => if (val != 0) true else false,
            else => switch (@typeInfo(T)) {
                .ComptimeInt, .Int => val,
                else => unreachable,
            }
        };
    }
};

test "Context: initialise and deinitialise" {
    var ctx = try Context.init();
    ctx.deinit();
}

pub const SockOpt = enum(c_int) {
    Affinity = c.ZMQ_AFFINITY,
    Backlog = c.ZMQ_BACKLOG,
    BindToDevice = c.ZMQ_BINDTODEVICE,
    RoutingId = c.ZMQ_ROUTING_ID,
    ConnectRoutingId = c.ZMQ_CONNECT_ROUTING_ID,
    ConnectTimeout = c.ZMQ_CONNECT_TIMEOUT,
    Linger = c.ZMQ_LINGER,
    ReqCorrelate = c.ZMQ_REQ_CORRELATE,
    SocksProxy = c.ZMQ_SOCKS_PROXY,
    Subscribe = c.ZMQ_SUBSCRIBE,
    Unsubscribe = c.ZMQ_UNSUBSCRIBE,
    RcvMore = c.ZMQ_RCVMORE,
    UseFD = c.ZMQ_USE_FD,
    LastEndpoint = c.ZMQ_LAST_ENDPOINT,
    CurvePublicKey = c.ZMQ_CURVE_PUBLICKEY,
    CurveSecretKey = c.ZMQ_CURVE_SECRETKEY,
    CurveServer = c.ZMQ_CURVE_SERVER,
    CurverServerKey = c.ZMQ_CURVE_SERVERKEY,
    SndHWM = c.ZMQ_SNDHWM,
    RcvHWM = c.ZMQ_RCVHWM,

    const Self = @This();

    pub fn getOriginal(self: *const Self) c_int {
        return @bitCast(c_int, self.*);
    }
};

pub const SocketEvent = enum(u16) {
    Connected = c.ZMQ_EVENT_CONNECTED,
    Delayed = c.ZMQ_EVENT_CONNECT_DELAYED,
    Retring = c.ZMQ_EVENT_CONNECT_RETRIED,
    Listening = c.ZMQ_EVENT_LISTENING,
    BindFailed = c.ZMQ_EVENT_BIND_FAILED,
    Accepted = c.ZMQ_EVENT_ACCEPTED,
    AcceptFailed = c.ZMQ_EVENT_ACCEPT_FAILED,
    Closed = c.ZMQ_EVENT_CLOSED,
    CloseFailed = c.ZMQ_EVENT_CLOSE_FAILED,
    Disconnected = c.ZMQ_EVENT_DISCONNECTED,
    MonitorStopped = c.ZMQ_EVENT_MONITOR_STOPPED,
    HandshakeFailed = c.ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL,
    HandshakeSucceeded = c.ZMQ_EVENT_HANDSHAKE_SUCCEEDED,
    HandshakeBadProtocol = c.ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL,
    HandshakeBadAuth = c.ZMQ_EVENT_HANDSHAKE_FAILED_AUTH,
};

pub const EVENT_ALL = c.ZMQ_EVENT_ALL;

pub const RawSocket = struct {
    _sock: *c_void,

    const Self = @This();

    fn init(sock: *c_void) Self {
        return Self{
            ._sock = sock,
        };
    }

    /// Close this socket. Close a closed socket will trigger undefined behaviour.
    pub fn close(self: *Self) void {
        const stat = c.zmq_close(self._sock);
        if (stat < 0) {
            unreachable;
        }
    }

    /// Close socket and deinitlise structure.
    pub fn deinit(self: *Self) void {
        self.close();
    }

    fn buildFlags(flags: anytype) c_int {
        const T = @TypeOf(flags);
        const infoT = @typeInfo(T);
        if (infoT == .Struct) {
            var iflags = @as(c_int, 0);

            inline for (infoT.Struct.fields) |field| {
                const value = @field(flags, field.name);
                if (comptime std.mem.eql(u8, value, "dontWait")) {
                    iflags = iflags | c.ZMQ_DONTWAIT;
                } else if (comptime std.mem.eql(u8, value, "more")) {
                    iflags = iflags | c.ZMQ_SNDMORE;
                } else {
                    @compileError(std.fmt.comptimePrint("unregonised flag: {s}", .{value}));
                }
            }

            return iflags;
        } else if (infoT == .Int or infoT == .ComptimeInt) {
            return @intCast(c_int, flags);
        } else {
            @compileError(std.fmt.comptimePrint("expect tuple or integer, got {}", .{T}));
        }
    }

    fn getIOError() IOError {
        return switch (getErrNo()) {
            c.EAGAIN => IOError.Again,
            c.ENOTSUP => IOError.NotSupported,
            c.EINVAL => IOError.NoMultipart,
            c.ETERM => IOError.Terminated,
            c.ENOTSOCK => IOError.InvalidSocket,
            c.EINTR => IOError.Interrupted,
            else => unreachable,
        };
    }

    /// Tell socket to connect an endpoint. Caller owns `addr`.
    /// The return does not means the connecting is complete.
    pub fn connect(self: *Self, addr: [:0]const u8) FileError!void {
        const stat = c.zmq_connect(self._sock, addr);
        if (stat < 0) {
            return translateFileError(getErrNo());
        }
    }

    /// Tell socket to bind an endpoint.
    pub fn bind(self: *Self, addr: [:0]const u8) FileError!void {
        const stat = c.zmq_bind(self._sock, addr);
        if (stat < 0) {
            return translateFileError(getErrNo());
        }
    }

    /// Send a frame though socket.
    /// The `buf` should be allocated in C allocator. It will be deallocated after being sent.
    /// The `flags` should be a tuple contains strings. Supported flags: "dontWait", "more".
    pub fn send(self: *Self, buf: []const u8, flags: anytype) IOError!usize {
        const iflags = buildFlags(flags);

        const stat = c.zmq_send(self._sock, buf.ptr, buf.len, iflags);

        if (stat >= 0) {
            return @intCast(usize, stat);
        } else {
            return getIOError();
        }
    }

    /// Send a frame though socket, but do not deallocate the memory after is being sent.
    pub fn sendConst(self: *Self, buf: []const u8, flags: anytype) IOError!usize {
        const iflags = buildFlags(flags);
        const stat = c.zmq_send_const(self._sock, buf.ptr, buf.len, iflags);

        if (stat >= 0) {
            return @intCast(usize, stat);
        } else {
            return getIOError();
        }
    }

    /// Receive a frame as data to `buf`.
    pub fn recv(self: *Self, buf: []u8, flags: anytype) IOError!usize {
        const iflags = buildFlags(flags);
        const stat = c.zmq_recv(self._sock, buf.ptr, buf.len, iflags);

        if (stat >= 0) {
            return @intCast(usize, stat);
        } else {
            return getIOError();
        }
    }

    /// Copy the buf by the C allocator and send as a frame though socket.
    /// Caller owns `buf`.
    pub fn sendCopy(self: *Self, buf: []const u8, flags: anytype) (Allocator.Error || IOError)!usize {
        var copy = try std.heap.c_allocator.dupe(u8, buf);
        return try self.send(copy, flags);
    }

    /// Allocate a block of `maxsize` size, receive data to this block and resize the block to best-fit.
    /// If the frame size is greater than `maxsize`, it will be dropped and IOError.FrameTooLarge will be returned.
    pub fn recvAlloc(self: *Self, alloc: *Allocator, maxsize: usize, flags: anytype) (Allocator.Error || IOError)![]u8 {
        var maxbuf = try alloc.alloc(u8, maxsize);
        errdefer alloc.free(maxbuf);
        var size = try self.recv(maxbuf, flags);
        if (size < maxsize) {
            return try alloc.resize(maxbuf, size);
        } else {
            return IOError.FrameTooLarge;
        }
    }

    fn getError() Error {
        return switch (getErrNo()) {
            c.EINVAL => Error.Invalid,
            c.ETERM => Error.Terminated,
            c.ENOTSOCK => Error.Unknown,
            c.EINTR => Error.Interrupted,
            else => unreachable,
        };
    }

    fn typeAssert(comptime expected: type, comptime real: type) void {
        if (expected != real) {
            @compileError(std.fmt.comptimePrint("expect {}, got {}", .{ expected, real }));
        }
    }

    fn assertSliceOf(comptime childType: type, comptime realType: type) void {
        const realInfo = @typeInfo(realType);
        if (!(realInfo == .Pointer and realInfo.Pointer.size == .Slice and realInfo.Pointer.child == childType)) {
            @compileError(std.fmt.comptimePrint("expect any slice of {}, got {}", .{ childType, realType }));
        }
    }

    /// Set a socket option.
    pub fn setOpt(self: *Self, comptime opt: SockOpt, comptime valueT: type, value: valueT) Error!void {
        const assert = std.debug.assert;
        var result = @as(c_int, -2);
        switch (opt) {
            .Affinity => {
                typeAssert(usize, valueT);
                result = c.zmq_setsockopt(self._sock, opt.getOriginal(), &value, @sizeOf(valueT));
            },

            .BindToDevice, .SocksProxy => {
                assert(valueT == [:0]const u8 or valueT == [:0]u8);
                result = c.zmq_setsockopt(self._sock, opt.getOriginal(), value.ptr, value.len + 1);
            },

            .ConnectRoutingId, .RoutingId => {
                assert(valueT == []const u8 or valueT == []u8);
                assert(value.len >= 1 and value.len <= 255);
                assert(value[0] != 0);
                result = c.zmq_setsockopt(self._sock, opt.getOriginal(), value.ptr, value.len);
            },

            .ConnectTimeout, .Linger, .UseFD, .Backlog, .RcvHWM, .SndHWM => {
                typeAssert(c_int, valueT);
                result = c.zmq_setsockopt(self._sock, opt.getOriginal(), &value, @sizeOf(valueT));
            },

            .ReqCorrelate, .CurveServer => {
                typeAssert(bool, valueT);
                const flag = @as(c_int, if (value) 1 else 0);
                result = c.zmq_setsockopt(self._sock, opt.getOriginal(), &flag, @sizeOf(c_int));
            },

            .Subscribe, .Unsubscribe => {
                assert(valueT == []const u8 or valueT == []u8);
                result = c.zmq_setsockopt(self._sock, opt.getOriginal(), value.ptr, value.len);
            },

            .CurvePublicKey, .CurverServerKey, .CurveSecretKey => {
                assertSliceOf(u8, valueT);
                assert(value.len == 32);
                result = c.zmq_setsockopt(self._sock, opt.getOriginal(), value.ptr, value.len);
            },

            else => @compileError(std.fmt.comptimePrint("unsupported option: {}", .{opt})),
        }
        if (result >= 0) {
            return;
        } else if (result == -1) {
            return getError();
        } else if (result == -2) {
            unreachable; // It's impossible!
        }
    }

    fn translateGetOptErr(errno: c_int) Error {
        return switch (errno) {
            c.EINVAL => Error.Invalid,
            c.ETERM => Error.Terminated,
            c.ENOTSOCK => Error.InvalidSocket,
            c.EINTR => Error.Interrupted,
            else => unreachable,
        };
    }

    /// Get a socket option.
    /// If you are looking for getting strings, see `getOptBuf`, `getOptAlloc`, `getOptAllocAuto`.
    pub fn getOpt(self: *Self, comptime T: type, opt: SockOpt) Error!T {
        std.debug.assert(@typeInfo(T) != .Pointer);
        if (T == bool) {
            const val = try self.getOpt(c_int, opt);
            return val != 0;
        } else {
            var value = std.mem.zeroes(T);
            var size = @as(usize, @sizeOf(T));
            const stat = c.zmq_getsockopt(self._sock, opt.getOriginal(), @ptrCast(*c_void, &value), &size);
            if (stat >= 0) {
                return value;
            } else {
                return translateGetOptErr(getErrNo());
            }
        }
    }

    /// Read the value of a socket option to `buf`.
    /// If the option name is unavailable or the `buf` have not enough size, `Error.Invalid` will be returned. 
    pub fn getOptBuf(self: *Self, opt: SockOpt, buf: []u8) Error![]u8 {
        var size = @as(usize, buf.len);
        const stat = c.zmq_getsockopt(self._sock, opt.getOriginal(), @ptrCast(*c_void, buf.ptr), &size);
        if (stat >= 0) {
            return buf[0..size];
        } else {
            return translateGetOptErr(getErrNo());
        }
    }

    /// Allocate `maxsize` bytes memory, read the value of a socket option into it, and resize it to best-fit.
    pub fn getOptAlloc(self: *Self, opt: SockOpt, alloc: *Allocator, maxsize: usize) (Allocator.Error || Error)![]u8 {
        var buf = try alloc.alloc(u8, maxsize);
        errdefer alloc.free(buf);
        var resultBuf = try self.getOptBuf(opt, buf);
        if (resultBuf.len < maxsize) {
            buf = try alloc.resize(buf, resultBuf.len);
        }
        return buf;
    }

    /// Repeatly retry `getOptBuf` with increasing buffer from `alloc`. 
    /// If `opt` could not be read by libzmq, it would become an infinite loop.
    /// The memory size is initially 512 bytes, then plus 512 bytes each turn.
    pub fn getOptAllocAuto(self: *Self, opt: SockOpt, alloc: *Allocator) (Allocator.Error || Error)![]u8 {
        var currentSize = @as(usize, 512);
        var buf = try alloc.alloc(u8, currentSize);
        while (true) {
            var result = self.getOptBuf(opt, buf) catch |e| switch (e) {
                error.Invalid => null,
                else => return e,
            };
            if (result) |realResult| {
                return realResult;
            } else {
                currentSize += 512;
                buf = try alloc.realloc(buf, currentSize);
            }
        }
    }

    pub fn sendFrame(self: *Self, frame: *Frame, flags: anytype) IOError!usize {
        const iflags = buildFlags(flags);
        const stat = c.zmq_msg_send(&frame.raw, self._sock, iflags);
        if (stat >= 0) {
            frame._beSentFlag = true;
            return @intCast(usize, stat);
        } else {
            return getIOError();
        }
    }

    pub fn recvFrame(self: *Self, frame: *Frame, flags: anytype) IOError!usize {
        const iflags = buildFlags(flags);
        const stat = c.zmq_msg_recv(&frame.raw, self._sock, iflags);
        if (stat >= 0) {
            return @intCast(usize, stat);
        } else {
            return getIOError();
        }
    }

    pub fn sendEmpty(self: *Self, flags: anytype) IOError!void {
        const iflags = buildFlags(flags);
        const stat = c.zmq_send_const(self._sock, null, 0, iflags);
        if (stat < 0) {
            return getIOError();
        }
    }

    fn buildSocketEventFlags(events: anytype) c_int {
        const T = @TypeOf(events);
        const info = @typeInfo(T);
        if (info == .Int or info == .ComptimeInt) {
            return @as(c_int, events);
        } else if (info == .Struct) {
            var iflags = @as(c_int, 0);
            const structInfo = info.Struct;
            inline for (structInfo.fields) |field| {
                const value = @field(events, field.name);
                if (@TypeOf(value) != SocketEvent) @compileError(std.fmt.comptimePrint("expect ScoketEvent, got {}", .{@TypeOf(value)}));
                iflags |= @enumToInt(value);
            }
            return iflags;
        } else @compileError(std.fmt.comptimePrint("expect tuple of ScoketEvent or any integer, got {}", .{T}));
    }

    /// Start a monitor on `events` and bind to `endpoint`. Caller owns `endpoint`.
    /// `endpoint` only accepts inproc transport.
    /// Return `Terminated` when context terminated; `Invalid` when endpoint is invalid.
    pub fn startMonitor(self: *Self, endpoint: [:0]const u8, events: anytype) Error!void {
        const iflags = buildSocketEventFlags(events);
        const stat = c.zmq_socket_monitor(self._sock, endpoint, iflags);
        if (stat >= 0) {
            _l.debug("a monitor is started at {s} for events {}", .{endpoint, events});
        } else {
            return switch (getErrNo()) {
                c.ETERM => Error.Terminated,
                c.EPROTONOSUPPORT => Error.Invalid,
                c.EINVAL => Error.Invalid,
                else => unreachable,
            };
        }
    }

    /// Stop the monitor on this socket.
    pub fn stopMonitor(self: *Self) Error!void {
        const stat = c.zmq_socket_monitor(self._sock, null, 0);
        if (stat >= 0) {
            _l.debug("a monitor is stopped", .{});
        } else {
            return switch (getErrNo()) {
                c.ETERM => Error.Terminated,
                else => unreachable,
            };
        }
    }
};

pub const Socket = struct {
    raw: RawSocket,

    const Self = @This();

    pub fn init(raw: RawSocket) Self {
        return Self{
            .raw = raw,
        };
    }

    /// Close socket.
    pub fn close(self: *Self) void {
        self.raw.close();
    }

    /// Set socket's linger.
    /// If linger is 0, the socket will block when is being closing until all messages sent.
    /// When it's -1, the socket will be close but all queued messages will be kept (context will block when terminating if messages not sent).
    /// For any integer is greater than 0, it will be treated as the milliseconds before all messages timeout and the socket closed.
    pub fn setLinger(self: *Self, linger: c_int) Error!void {
        try self.setOpt(.Linger, c_int, linger);
    }

    /// Close socket and deinitialise structure.
    pub fn deinit(self: *Self) void {
        self.raw.close();
    }

    /// Get the value of a socket option.
    pub fn getOpt(self: *Self, comptime T: type, opt: SockOpt) Error!T {
        return try self.raw.getOpt(T, opt);
    }

    /// Read the value of a socket option to `buf`.
    /// If the option name is unavailable or the `buf` have not enough size, `Error.Invalid` will be returned. 
        /// If the option name is unavailable or the `buf` have not enough size, `Error.Invalid` will be returned. 
    /// If the option name is unavailable or the `buf` have not enough size, `Error.Invalid` will be returned. 
    pub fn getOptBuf(self: *Self, opt: SockOpt, buf: []u8) Error![]u8 {
        return try self.raw.getOptBuf(opt, buf);
    }

    /// Allocate `maxsize` bytes memory, read the value of a socket option into it, and resize it to best-fit.
    pub fn getOptAlloc(self: *Self, opt: SockOpt, alloc: *Allocator, maxsize: usize) (Allocator.Error || Error)![]u8 {
        return try self.raw.getOptAlloc(opt, alloc, maxsize);
    }

    /// Repeatly retry `getOptBuf` with increasing buffer from `alloc`. 
        /// Repeatly retry `getOptBuf` with increasing buffer from `alloc`. 
    /// Repeatly retry `getOptBuf` with increasing buffer from `alloc`. 
    /// If `opt` could not be read by libzmq, it would become an infinite loop.
    /// The memory size is initially 512 bytes, then plus 512 bytes each turn.
    pub fn getOptAllocAuto(self: *Self, opt: SockOpt, alloc: *Allocator) (Allocator.Error || Error)![]u8 {
        return try self.raw.getOptAllocAuto(opt, alloc);
    }

    /// Tell socket to connect an endpoint. Caller owns `addr`.
    /// The return does not means the connecting is complete.
    pub fn connect(self: *Self, addr: [:0]const u8) FileError!void {
        return try self.raw.connect(addr);
    }

    /// Tell socket to bind an endpoint. Caller owns `addr`.
    pub fn bind(self: *Self, addr: [:0]const u8) FileError!void {
        return try self.raw.bind(addr);
    }

    /// Set the value of a socket option.
    pub fn setOpt(self: *Self, comptime opt: SockOpt, comptime valueT: type, value: valueT) Error!void {
        return try self.raw.setOpt(opt, valueT, value);
    }

    /// Send `buf`. The `buf` should be allocated by C allocator and callee owns it.
    /// `flags` receive two kinds of arguments:
    /// - tuple: `.{"dontWait", "more"}`
    /// - integer: `zmq.SNDMORE | zmq.DONTWAIT`
    pub fn send(self: *Self, buf: []const u8, flags: anytype) IOError!usize {
        return try self.raw.send(buf, flags);
    }

    /// Send `buf`, but won't deallocate it when sending complete.
    /// Second advise: returned is not sent.
    /// See `send` for possibilties of `flags`.
    pub fn sendConst(self: *Self, buf: []const u8, flags: anytype) IOError!usize {
        return try self.raw.sendConst(buf, flags);
    }

    /// Copy `buf` into a memory block allocated by C allocator and send.
    /// Caller owns `buf`.
    pub fn sendCopy(self: *Self, buf: []const u8, flags: anytype) (Allocator.Error || IOError)!usize {
        return try self.raw.sendCopy(buf, flags);
    }

    /// Send a `Frame` and deinitialise.
    pub fn sendFrame(self: *Self, frame: *Frame, flags: anytype) (IOError)!usize {
        return try self.raw.sendFrame(frame, flags);
    }

    /// Copy the value to heap and send the copy.
    /// Use `sendConstValue` to avoid coping for constants.
    pub fn sendValue(self: *Self, comptime V: type, value: *const V, flags: anytype) (Allocator.Error || IOError)!usize {
        const size = @sizeOf(V);
        return try self.sendCopy(@ptrCast([*]const u8, value)[0..size], flags);
    }

    /// Send a value and don't destroy it.
    /// The value should be a constant, ZeroMQ does not have promise of when the frame will be sent.
    pub fn sendConstValue(self: *Self, comptime V: type, value: *const V, flags: anytype) IOError!usize {
        const size = @sizeOf(V);
        return try self.sendConst(@ptrCast([*]const u8, value)[0..size], flags);
    }

    /// Read the incoming frame into `buf`.
    pub fn recv(self: *Self, buf: []u8, flags: anytype) IOError!usize {
        return try self.raw.recv(buf, flags);
    }

    /// Allocate `maxsize` byte(s) memory and receive the incoming frame into it.
    pub fn recvAlloc(self: *Self, alloc: *Allocator, maxsize: usize, flags: anytype) (Allocator.Error || IOError)![]u8 {
        return try self.raw.recvAlloc(alloc, maxsize, flags);
    }

    /// Receive a exact value from socket. Return FrameTooLarge if the received data size is not fit. 
    /// Warning: the method just receive data and write them into memory. The data might not be portable.
    pub fn recvValue(self: *Self, comptime V: type, flags: anytype) IOError!V {
        const size = @sizeOf(V);
        var buf: [size]u8 = undefined;
        const recvSize = try self.recv(&buf, flags);
        if (recvSize == size) {
            return @ptrCast(*V, @alignCast(@alignOf(*V), &buf)).*;
        } else {
            return IOError.FrameTooLarge;
        }
    }

    pub fn recvFrame(self: *Self, frame: *Frame, flags: anytype) IOError!usize {
        return try self.raw.recvFrame(frame, flags);
    }

    pub fn recvFrameSize(self: *Self, size: usize, flags: anytype) (Allocator.Error || IOError)!Frame {
        var frame = try Frame.initSize(size);
        errdefer frame.deinit();
        _ = try self.recvFrame(&frame, flags);
        return frame;
    }

    /// Subscribe a topic. Only available on Sub/XPub sockets.
    /// You can use this function on XPub when option XPubManual is set to true (not implemented yet).
    pub fn subscribe(self: *Self, filter: []const u8) Error!void {
        try self.raw.setOpt(.Subscribe, []const u8, filter);
    }

    /// Unsubscribe a topic. Only available on Sub/XPub sockets.
    /// You can use this function on XPub when option XPubManual is set to true (not implemented yet).
    pub fn unsubscribe(self: *Self, filter: []const u8) Error!void {
        try self.raw.setOpt(.Unsubscribe, []const u8, filter);
    }

    /// Set a pre-allocated socket file descriptor.
    /// When set to a positive integer value before zmq_bind is called on the socket, the socket shall use the corresponding file descriptor for connections over TCP or IPC instead of allocating a new file descriptor. 
        /// When set to a positive integer value before zmq_bind is called on the socket, the socket shall use the corresponding file descriptor for connections over TCP or IPC instead of allocating a new file descriptor. 
    /// When set to a positive integer value before zmq_bind is called on the socket, the socket shall use the corresponding file descriptor for connections over TCP or IPC instead of allocating a new file descriptor. 
    /// If set to -1 (default), a new file descriptor will be allocated instead.
    /// NOTE: the file descriptor passed through MUST have been ran through the "bind" and "listen" system calls beforehand.
    /// Also, socket option that would normally be passed through zmq_setsockopt like TCP buffers length, IP_TOS or SO_REUSEADDR MUST be set beforehand by the caller, as they must be set before the socket is bound.
    pub fn setUseFD(self: *Self, fd: c_int) Error!void {
        return try self.setOpt(.UseFD, c_int, fd);
    }

    /// Set the proxy of the socket. Only available for TCP transport.
    /// Does not support authentication.
    pub fn setSocks5Proxy(self: *Self, address: [:0]const u8) Error!void {
        return try self.setOpt(.SocksProxy, [:0]const u8, address);
    }

    /// Retrieve the last endpoint set. Available for TCP or IPC transport.
    pub fn getLastEndpointBuf(self: *Self, buf: []u8) Error![:0]const u8 {
        var result = try self.getOptBuf(.LastEndpoint, buf);
        return result[0 .. result.len - 1 :0];
    }

    /// Allocator version of `getLastEndpointBuf`.
    pub fn getLastEndpointAlloc(self: *Self, alloc: *Allocator, maxsize: usize) (Allocator.Error || Error)![:0]const u8 {
        var result = try self.getOptAlloc(.LastEndpoint, alloc, maxsize);
        return result[0 .. result.len - 1 :0];
    }

    // Auto allocator version of `getLastEndpointBuf`.
    pub fn getLastEndpointAllocAuto(self: *Self, alloc: *Allocator) (Allocator.Error || Error)![:0]const u8 {
        var result = try self.getOptAllocAuto(.LastEndpoint, alloc);
        return result[0 .. result.len - 1 :0];
    }

    pub fn curveSetupClient(self: *Self, secretKey: []const u8) Error!void {
        var pubK = curvePublic(secretKey);
        try self.setOpt(.CurveServer, bool, false);
        try self.setOpt(.CurveSecretKey, []const u8, secretKey);
        try self.setOpt(.CurvePublicKey, []const u8, &pubK);
    }

    pub fn curveClientSetServer(self: *Self, serverPublicKey: []const u8) Error!void {
        try self.setOpt(.CurverServerKey, []const u8, serverPublicKey);
    }

    pub fn curveSetupServer(self: *Self, secretKey: []const u8) Error!void {
        var pubK = curvePublic(secretKey);
        try self.setOpt(.CurveServer, bool, true);
        try self.setOpt(.CurveSecretKey, []const u8, secretKey);
        try self.setOpt(.CurvePublicKey, []const u8, &pubK);
    }

    /// Return true if the message part last received from the socket was a data part with more parts to follow.
    /// If there are no data parts to follow, this option shall return false.
    /// Undefined behaviour will be triggered if being called without any message part received before.
    pub fn getRcvMore(self: *Self) bool {
        return self.getOpt(bool, .RcvMore) catch unreachable;
    }

    /// Ignore next incoming message part.
    pub fn recvIgnore(self: *Self, flags: anytype) IOError!void {
        var buf: [1]u8 = undefined;
        _ = self.recv(&buf, flags) catch |e| switch (e) {
            IOError.FrameTooLarge => {},
            else => return e,
        };
    }
    
    /// Send an empty frame.
    pub fn sendEmpty(self: *Self, flags: anytype) IOError!void {
        return self.raw.sendEmpty(flags);
    }

    /// Start a monitor on `endpoint` to listen `events`.
    /// `events` could be a tuple or integer flags.
    /// `endpoint` only accepts inproc transport, or Error.Invalid will be return.
    /// You should not start two or more monitor on one socket, the behaviour is undefined in document.
    /// `stopMonitor` can be used to stop original monitor.
    pub fn startMonitor(self: *Self, endpoint: [:0]const u8, events: anytype) Error!void {
        return try self.raw.startMonitor(endpoint, events);
    }
    
    /// Stop the monitor.
    pub fn stopMonitor(self: *Self) Error!void {
        return try self.raw.stopMonitor();
    }
};

fn fillBufReadableChars(buf: []u8) void {
    const RANDTABLE = "0123456789abcdefghijklmnopqrstuvwxyz";
    for (buf) |*ch| {
        ch.* = RANDTABLE[std.crypto.random.intRangeLessThan(usize, 0, RANDTABLE.len)];
    }
}

pub fn genRandomInprocAddress(prefix: []const u8, comptime size: usize) [size:0]u8 {
    std.debug.assert(prefix.len+9 <= size);
    const ADDR_PREFIX = "inproc://";
    var addrBuf: [size:0]u8 = undefined;
    fillBufReadableChars(addrBuf[ADDR_PREFIX.len+prefix.len..addrBuf.len]);
    std.mem.copy(u8, addrBuf[0..ADDR_PREFIX.len], ADDR_PREFIX);
    std.mem.copy(u8, addrBuf[ADDR_PREFIX.len..ADDR_PREFIX.len+prefix.len], prefix);
    return addrBuf;
}

pub fn curvePublic(secretKey: []const u8) [32]u8 {
    std.debug.assert(secretKey.len == 32);
    var z85Buf: [41]u8 = undefined;
    var z85PubBuf: [41]u8 = undefined;
    if (c.zmq_z85_encode(&z85Buf, secretKey.ptr, 32)) |_| {
        if (c.zmq_curve_public(&z85PubBuf, &z85Buf) != c.ENOTSUP) {
            var pubKBuf: [32]u8 = undefined;
            if (c.zmq_z85_decode(&pubKBuf, &z85PubBuf)) |_| {
                return pubKBuf;
            } else unreachable;
        } else unreachable; // libzmq not built with crypto support
    } else unreachable;
}

pub fn curveGenerateSecretKey() [32]u8 {
    var secK: [41]u8 = undefined;
    var pubK: [41]u8 = undefined;

    if (c.zmq_curve_keypair(&pubK, &secK) != c.ENOTSUP) {
        var pubKBin: [32]u8 = undefined;
        if (c.zmq_z85_decode(&pubKBin, &pubK)) |_| {
            return pubKBin;
        } else unreachable;
    } else unreachable;
}

fn comptimeHexToBytes(comptime s: []const u8, comptime binLength: usize) *const [binLength]u8 {
    comptime {
        var buf: [binLength]u8 = undefined;
        var slice = std.fmt.hexToBytes(&buf, s) catch unreachable;
        if (slice.len != binLength) @compileError("internal error");
        return &buf;
    }
}

pub const TEST_CLIENT_PUBKEY = comptimeHexToBytes("BB88471D65E2659B30C55A5321CEBB5AAB2B70A398645C26DCA2B2FCB43FC518", 32);
pub const TEST_CLIENT_SECKEY = comptimeHexToBytes("7BB864B489AFA3671FBE69101F94B38972F24816DFB01B51656B3FEC8DFD0888", 32);
pub const TEST_SERVER_PUBKEY = comptimeHexToBytes("54FCBA24E93249969316FB617C872BB0C1D1FF14800427C594CBFACF1BC2D652", 32);
pub const TEST_SERVER_SECKEY = comptimeHexToBytes("8E0BDD697628B91D8F245587EE95C5B04D48963F79259877B49CD9063AEAD3B7", 32);

test "curvePublic and TEST_*_*KEY" {
    const _t = std.testing;
    {
        var pubKey = curvePublic(TEST_CLIENT_SECKEY);
        try _t.expectEqualSlices(u8, TEST_CLIENT_PUBKEY, &pubKey);
    }
    {
        var pubKey = curvePublic(TEST_SERVER_SECKEY);
        try _t.expectEqualSlices(u8, TEST_SERVER_PUBKEY, &pubKey);
    }
}

test "curveGenerateSecretKey" {
    {
        var key0 = curveGenerateSecretKey();
        _ = curvePublic(&key0);
    }
}

test "Socket: initialise and deinitialise" {
    var ctx = try Context.init();
    defer ctx.deinit();
    var sock = try ctx.socket(.Pair);
    defer sock.deinit();
}

test "Socket: send and recv" {
    const _t = std.testing;
    const DATA = "Hello Zig from ZeroMQ";
    var ctx = try Context.init();
    defer ctx.deinit();
    var sock0 = try ctx.socket(.Pair);
    defer sock0.deinit();
    var sock1 = try ctx.socket(.Pair);
    defer sock1.deinit();
    try sock0.bind("inproc://test");
    try sock1.connect("inproc://test");
    _ = try sock0.sendConst(DATA, .{});
    var receivedData = try sock1.recvAlloc(_t.allocator, 256, .{});
    defer _t.allocator.free(receivedData);
    try _t.expectEqualStrings(DATA, receivedData);
}

test "Socket: recvIgnore" {
    const _t = std.testing;
    const DATA = "Hello Zig from ZeroMQ";
    var ctx = try Context.init();
    defer ctx.deinit();
    var sock0 = try ctx.socket(.Pair);
    defer sock0.deinit();
    var sock1 = try ctx.socket(.Pair);
    defer sock1.deinit();
    try sock0.bind("inproc://test");
    try sock1.connect("inproc://test");
    _ = try sock0.sendConst("HELLO", .{});
    _ = try sock0.sendConst(DATA, .{});
    try sock1.recvIgnore(.{});
    var receivedData = try sock1.recvAlloc(_t.allocator, 256, .{});
    defer _t.allocator.free(receivedData);
    try _t.expectEqualStrings(DATA, receivedData);
}

test "Socket: subscribe and unsubscribe" {
    const _t = std.testing;
    const DATA = "Hello Zig from ZeroMQ";
    var ctx = try Context.init();
    defer ctx.deinit();
    var sockPub = try ctx.socket(.Pub);
    defer sockPub.deinit();
    try sockPub.bind("inproc://test");
    var sock0 = try ctx.socket(.Sub);
    defer sock0.deinit();
    var sock1 = try ctx.socket(.Sub);
    defer sock1.deinit();
    try sock0.connect("inproc://test");
    try sock0.subscribe("simple_flag");
    try sock1.connect("inproc://test");
    try sock1.subscribe("simple_flag");
    try sock1.unsubscribe("simple_flag");
    _ = try sockPub.sendConst("simple_flag", .{"more"});
    _ = try sockPub.sendConst(DATA, .{});

    // sock0 receive the message
    var firstFrame = try sock0.recvAlloc(_t.allocator, 256, .{});
    defer _t.allocator.free(firstFrame);
    try _t.expectEqualStrings("simple_flag", firstFrame);
    var receivedData = try sock0.recvAlloc(_t.allocator, 256, .{});
    defer _t.allocator.free(receivedData);
    try _t.expectEqualStrings(DATA, receivedData);

    // sock1 does not receive the message
    var frame: ?[]u8 = sock1.recvAlloc(_t.allocator, 256, DONTWAIT) catch |e| switch (e) {
        error.Again => null,
        else => return e,
    };
    try _t.expect(frame == null);
}

test "Socket: setOpt and getOpt" {
    const _t = std.testing;
    var ctx = try Context.init();
    defer ctx.deinit();
    var sock = try ctx.socket(.Pair);
    defer sock.deinit();
    try sock.setLinger(-1);
    try _t.expectEqual(@as(c_int, -1), try sock.getOpt(c_int, .Linger));
}

test "Socket: getOptBuf and getOptAlloc" {
    const _t = std.testing;
    const ROUTINGID = [_]u8{ 2, 3, 5, 7, 8 };
    var ctx = try Context.init();
    defer ctx.deinit();
    var sock = try ctx.socket(.Pair);
    defer sock.deinit();
    try sock.setOpt(.RoutingId, []const u8, &ROUTINGID);

    var id = try sock.getOptAlloc(.RoutingId, _t.allocator, 256);
    defer _t.allocator.free(id);
    try _t.expectEqualStrings(&ROUTINGID, id);
}

test "Socket: CurveZMQ" {
    const _t = std.testing;
    var ctx = try Context.init();
    defer ctx.deinit();
    var sock0 = try ctx.socket(.Rep);
    defer sock0.deinit();
    var sock1 = try ctx.socket(.Req);
    defer sock1.deinit();
    // Setup CurveZMQ (only affect connection after set up)
    try sock0.curveSetupServer(TEST_SERVER_SECKEY);
    try sock1.curveSetupClient(TEST_CLIENT_SECKEY);
    // Setup end
    try sock0.bind("tcp://127.0.0.1:*");
    const sock0Address = try sock0.getLastEndpointAlloc(_t.allocator, 256);
    defer _t.allocator.free(sock0Address);
    try sock1.curveClientSetServer(TEST_SERVER_PUBKEY);
    try sock1.connect(sock0Address);

    _ = try sock1.sendConst("PING", .{});
    var result = try sock0.recvAlloc(_t.allocator, 64, .{});
    defer _t.allocator.free(result);
    try _t.expectEqualStrings("PING", result);
    _ = try sock0.sendConst("PONG", .{});

    var result1 = try sock1.recvAlloc(_t.allocator, 64, .{});
    defer _t.allocator.free(result1);
    try _t.expectEqualStrings("PONG", result1);
}

test "Socket: getRcvMore" {
    const _t = std.testing;
    var ctx = try Context.init();
    defer ctx.deinit();
    var sock0 = try ctx.socket(.Pair);
    defer sock0.deinit();
    var sock1 = try ctx.socket(.Pair);
    defer sock1.deinit();
    try sock0.bind("inproc://test");
    try sock1.connect("inproc://test");
    _ = try sock0.sendConst("Hello", .{"more"});
    _ = try sock0.sendConst("", .{});
    var buf: [256]u8 = undefined;
    _ = try sock1.recv(&buf, .{});
    try _t.expect(sock1.getRcvMore());
}

test "Socket: sendEmpty" {
    const _t = std.testing;
    var ctx = try Context.init();
    defer ctx.deinit();
    var sock0 = try ctx.socket(.Pair);
    defer sock0.deinit();
    var sock1 = try ctx.socket(.Pair);
    defer sock1.deinit();
    try sock0.bind("inproc://test");
    try sock1.connect("inproc://test");

    try sock0.sendEmpty(.{});
    var frame = try sock1.recvFrameSize(1, .{});
    defer frame.deinit();
    try _t.expectEqual(@as(usize, 0), frame.size());
}

pub const SocketEventLogger = struct {
    monitor: Socket,
    monitoredSocket: *Socket,
    thread: *std.Thread,
    alloc: *Allocator,

    const Self = @This();

    fn loggerThreadBody(self: *Self) void {
        const l = std.log.scoped(.ZMQSocketEventLogger);
        l.info("a socket event logger is started", .{});
        while (true) {
            var msg: ?SocketEventMessage = SocketEventMessage.recv(&self.monitor, self.alloc) catch |e| switch (e) {
                error.OutOfMemory => oom: {
                    l.crit("could not receive socket event: allocator report OOM", .{});
                    break :oom null;
                },
                else => blk: {
                    l.err("could not receive socket event: io error {}", .{e});
                    break :blk null;
                },
            };
            if (msg) |*nnmsg| {
                defer nnmsg.deinit();
                l.info("socket event: {} {} \"{s}\"", .{nnmsg.event, nnmsg.value, nnmsg.endpoint.?});
                if (nnmsg.event == .MonitorStopped) {
                    break;
                }
            }
        }
        l.info("a socket event logger is stopped", .{});
    }

    pub fn init(monitor: Socket, monitoredSocket: *Socket, alloc: *Allocator) (std.Thread.SpawnError||Allocator.Error)!*Self {
        var result = try alloc.create(Self);
        errdefer alloc.destroy(result);
        result.* = Self {
            .monitor = monitor,
            .monitoredSocket = monitoredSocket,
            .thread = undefined,
            .alloc = alloc,
        };
        result.thread = try std.Thread.spawn(loggerThreadBody, result);
        return result;
    }

    pub fn deinit(self: *Self) void {
        self.monitoredSocket.stopMonitor() catch {}; // ignore terminated error.
        self.thread.wait();
        self.monitor.deinit();
        self.alloc.destroy(self);
    }
};

test "Socket: monitor" {
    const _t = std.testing;
    var ctx = try Context.init();
    defer ctx.deinit();
    var sock0 = try ctx.socket(.Rep);
    defer sock0.deinit();
    var sock1 = try ctx.socket(.Req);
    defer sock1.deinit();
    var monitor0 = try ctx.monitor(&sock0, .{SocketEvent.Listening});
    defer monitor0.deinit();
    try sock0.bind("tcp://127.0.0.1:*");
    var lastEndpoint = try sock0.getLastEndpointAlloc(_t.allocator, 256);
    defer _t.allocator.free(lastEndpoint);
    try sock1.connect(lastEndpoint);

    _ = try sock1.sendConst("Hello", .{});
    _ = try sock0.recvIgnore(.{});
    _ = try sock0.sendConst("World!", .{});
    _ = try sock1.recvIgnore(.{});

    var connectedMsg = try SocketEventMessage.recvEvent(&monitor0);
    try monitor0.recvIgnore(.{});
    defer connectedMsg.deinit();
    try _t.expectEqual(SocketEvent.Listening, connectedMsg.event);
}

pub const FrameOpt = enum(c_int) {
    More = c.ZMQ_MORE,
    SrcFD = c.ZMQ_SRCFD,
    Shared = c.ZMQ_SHARED,
};

pub const Frame = struct {
    raw: c.zmq_msg_t,
    _beSentFlag: bool = false,
    _closed: bool = false,
    _zeroCopyMeta: ?*ZeroCopyMeta = null,

    const Self = @This();

    const ZeroCopyMeta = struct {
        slice: []u8,
        alloc: *Allocator,
    };

    /// Initialise frame.
    pub fn init() Self {
        var raw = std.mem.zeroes(c.zmq_msg_t);
        _ = c.zmq_msg_init(&raw);
        return Self{
            .raw = raw,
        };
    }

    /// Deinitialise this structure.
    /// You can always call this function when your work is done.
    /// It will try to ensure the data will not be free'd before they are sent.
    /// Caution: use sendFrame and recvFrame instead of other functions for frames!
    pub fn deinit(self: *Self) void {
        if (!(self._closed or self._beSentFlag)) {
            _ = c.zmq_msg_close(&self.raw);
        }
        self._closed = true;
    }

    /// Initialise frame with specific size.
    /// Note the memory is allocated by libzmq.
    pub fn initSize(blksize: usize) Allocator.Error!Self {
        var raw = std.mem.zeroes(c.zmq_msg_t);
        const stat = c.zmq_msg_init_size(&raw, blksize);
        if (stat >= 0) {
            return Self{
                .raw = raw,
            };
        } else {
            return switch (getErrNo()) {
                c.ENOMEM => Allocator.Error.OutOfMemory,
                else => unreachable,
            };
        }
    }

    /// Initialise frame with specific size and copy `buf` into it.
    /// Note the memory is allocated by libzmq.
    pub fn initCopy(buf: []const u8) Allocator.Error!Self {
        var frame = try Self.initSize(buf.len);
        std.mem.copy(u8, frame.data(), buf);
        return frame;
    }

    /// Initialise frame with `val`. `val` will be copied to heap by allocator or libzmq if `alloc` is non-null or not.
    pub fn initValue(comptime T: type, val: *T, alloc: ?*Allocator) Allocator.Error!Self {
        var frame = if (alloc) |nalloc| try Self.initData(try nalloc.alloc(u8, @sizeOf(T)), nalloc) else try Self.initSize(@sizeOf(T));
        errdefer frame.deinit();
        std.mem.copy(u8, frame.data(), @ptrCast([*]u8, val)[0..@sizeOf(T)]);
        return frame;
    }

    fn zmqAutoFreeFn(_: ?*c_void, hint: ?*c_void) callconv(.C) void {
        var meta = @ptrCast(*align(1) Self.ZeroCopyMeta, hint.?);
        meta.alloc.free(meta.slice);
        meta.alloc.destroy(meta);
    }

    /// Initialise frame in zero copy favour.
    /// This funtion will allocate memory for some meta infomation in `alloc`.
    /// That's because the callback of zmq_msg_init_data() does not provide the size of `buf`, which is key to deallocate the memory.
    /// So we need to save the size in this structure and make sure it could be accessed when the callback is being called.
    /// You must call .deinit() to deinitialise the structure (or memory will leak). The data will not be deinitialise if it have been queued, and will be free'd after it have been send.
    pub fn initData(buf: []u8, alloc: *Allocator) Allocator.Error!Self {
        var raw = std.mem.zeroes(c.zmq_msg_t);
        var meta = try alloc.create(ZeroCopyMeta);
        errdefer alloc.destroy(meta);
        meta.* = ZeroCopyMeta {
            .slice = buf,
            .alloc = alloc,
        };
        const stat = c.zmq_msg_init_data(&raw, buf.ptr, buf.len, zmqAutoFreeFn, meta);
        if (stat >= 0) {
            return Self {
                .raw = raw,
                ._zeroCopyMeta = meta,
            };
        } else {
            return switch (getErrNo()) {
                c.ENOMEM => Allocator.Error.OutOfMemory,
                else => unreachable,
            };
        }
    }

    pub fn size(self: *Self) usize {
        return c.zmq_msg_size(&self.raw);
    }

    pub fn data(self: *Self) []u8 {
        var ptr = c.zmq_msg_data(&self.raw);
        return @ptrCast([*]u8, ptr.?)[0..self.size()];
    }

    /// Return a copy of the data as specific type.
    /// It will trigger undefined behaviour if the received length is differ from expected.
    /// It's not recommended to read normal structure in zig, because of zig's auto optimised structure layouts.
    /// You should use packed structure.
    pub fn readValue(self: *Self, comptime T: type) T {
        std.debug.assert(@sizeOf(T) == self.size());
        return @ptrCast(*T, @alignCast(@alignOf(*T), self.data().ptr)).*;
    }

    pub fn getSocketType(self: *Self) [:0]const u8 {
        if (@hasDecl(c, "ZMQ_MSG_PROPERTY_SOCKET_TYPE")) {
            return self.getProperty(c.ZMQ_MSG_PROPERTY_SOCKET_TYPE) orelse unreachable;
        } else {
            return self.getProperty("Socket-Type") orelse unreachable;
        }
    }

    /// Return routing ID for frame, if any.
    /// The routing ID is set on all messages received from a ZMQ_SERVER socket.
    /// To send a message to a ZMQ_SERVER socket you must set the routing ID of a connected ZMQ_CLIENT peer.
    /// Routing IDs are transient.
    pub fn getRoutingId(self: *Self) ?u32 {
        const id = c.zmq_msg_routing_id(&self.raw);
        if (id > 0) {
            return id;
        } else {
            return null;
        }
    }

    /// Set routing ID property on message.
    /// The `id` must be greater than zero.
    /// To get a valid routing ID, you must receive a message from a ZMQ_SERVER socket, and use the `getRoutingId` method. 
    pub fn setRoutingId(self: *Self, id: u32) void {
        std.debug.assert(id != 0);
        _ = c.zmq_msg_set_routing_id(&self.raw, id);
    }

    pub fn getPeerAddress(self: *Self) ?[:0]const u8 {
        if (@hasDecl(c, "ZMQ_MSG_PROPERTY_PEER_ADDRESS")) {
            return self.getProperty(c.ZMQ_MSG_PROPERTY_PEER_ADDRESS);
        } else {
            return self.getProperty("Peer-Address");
        }
    }

    pub fn getProperty(self: *Self, key: [:0]const u8) ?[:0]const u8 {
        var ptr = c.zmq_msg_gets(&self.raw, key);
        if (ptr) |nnptr| {
            return nnptr[0..std.mem.len(nnptr) :0];
        } else {
            return null;
        }
    }

    pub fn getOpt(self: *Self, comptime T: type, comptime opt: FrameOpt) Error!T {
        switch (opt) {
            .More => {
                if (T == bool) {
                    const val = c.zmq_msg_get(&self.raw, @bitCast(c_int, opt));
                    if (val != -1) {
                        return val != 0;
                    } else {
                        return Error.Invalid;
                    }
                } else {
                    @compileError(".More accepts bool as type");
                }
            },

            .SrcFD => {
                if (T == c_int) {
                    const val = c.zmq_msg_get(&self.raw, @bitCast(c_int, opt));
                    if (val != -1) {
                        return val;
                    } else {
                        return Error.Invalid;
                    }
                } else {
                    @compileError(".SrcFD accepts c_int as type");
                }
            },

            .Shared => {
                if (T == bool) {
                    const val = c.zmq_msg_get(&self.raw, @bitCast(c_int, opt));
                    if (val != -1) {
                        return val != 0;
                    } else {
                        return Error.Invalid;
                    }
                } else {
                    @compileError(".Shared accepts bool as type");
                }
            },
        }
    }

    pub fn setOpt(self: *Self, comptime T: type, opt: FrameOpt, val: T) Error!void {
        _ = self; _ = T; _ = opt; _ = val;
        @compileError("Currently setOpt does not support any property names");
    }

    /// Share data with `aframe` from this structure.
    /// Don't modify data after it have been shared with other frames.
    pub fn share(self: *Self, aframe: *Frame) void {
        _ = c.zmq_msg_copy(&aframe.raw, &self.raw); // zmq_msg_copy only return error when msg_t is invalid
    }

    /// Copy data to `frame`. You must ensure `frame` have exact same size to this frame.
    pub fn copy(self: *Self, frame: *Frame) void {
        var targetBuf = frame.data();
        for (self.data()) |ch, i| {
            targetBuf[i] = ch;
        }
    }

    /// Create a duplication. If `alloc` is null, use libzmq's built-in memory management.
    pub fn dupe(self: *Self, alloc: ?*Allocator) Allocator.Error!Self {
        var frame: Frame = undefined;
        if (alloc) |a| {
            var buf = try a.alloc(u8, self.size());
            errdefer a.free(buf);
            frame = try Self.initData(buf, a);
        } else {
            frame = try Self.initSize(self.size());
        }
        self.copy(&frame);
        return frame;
    }

    /// Move contents to `aframe` without copying.
    pub fn move(self: *Self, aframe: *Frame) void {
        _ = c.zmq_msg_move(&aframe.raw, &self.raw);
        aframe._zeroCopyMeta = self._zeroCopyMeta;
        aframe._closed = self._closed;
        aframe._beSentFlag = self._beSentFlag;
    }
};

test "Frame: initialise and deinitialise" {
    const _t = std.testing;
    {
        var frame = Frame.init();
        defer frame.deinit();
    }

    {
        const DATA = "Hello World!";
        var frame = try Frame.initSize(12);
        defer frame.deinit();
        var data = frame.data();
        for (DATA) |ch, i| data[i] = ch;
        try _t.expectEqualStrings(DATA, frame.data());
    }

    {
        const DATA = "Hello World!";
        var buf = try _t.allocator.dupe(u8, DATA);
        var frame = try Frame.initData(buf, _t.allocator);
        defer frame.deinit();
        try _t.expectEqualStrings(DATA, frame.data());
    }

    {
        var DATA = @as(isize, -1);
        var frame = try Frame.initValue(isize, &DATA, _t.allocator);
        defer frame.deinit();
        try _t.expectEqual(DATA, frame.readValue(isize));
    }
}

test "Frame: size" {
    const _t = std.testing;
    {
        var frame = Frame.init();
        defer frame.deinit();
        try _t.expectEqual(@as(usize, 0), frame.size());
    }
    {
        const DATA = "Hello Jack Cooper";
        var frame = try Frame.initCopy(DATA);
        defer frame.deinit();
        try _t.expectEqual(@as(usize, 17), frame.size());
    }
}

test "Frame: share, copy, dupe and move" {
    const _t = std.testing;
    const DATA = "Hello World";
    {
        var frame = try Frame.initCopy(DATA);
        defer frame.deinit();
        var frame1 = Frame.init();
        defer frame1.deinit();
        frame.share(&frame1);
        try _t.expectEqualStrings(DATA, frame1.data());
    }
    {
        var frame = try Frame.initCopy(DATA);
        defer frame.deinit();
        var frame1 = try frame.dupe(_t.allocator);
        defer frame1.deinit();
        try _t.expectEqualStrings(DATA, frame1.data());
    }
    {
        var frame = try Frame.initCopy(DATA);
        defer frame.deinit();
        var frame1 = try frame.dupe(null);
        defer frame1.deinit();
        try _t.expectEqualStrings(DATA, frame1.data());
    }
    {
        var frame = try Frame.initCopy(DATA);
        defer frame.deinit();
        var frame1 = Frame.init();
        defer frame1.deinit();
        frame.move(&frame1);
        try _t.expectEqual(@as(usize, 0), frame.size());
        try _t.expectEqualStrings(DATA, frame1.data());
    }
}

test "Frame: recv and send" {
    const _t = std.testing;
    {
        const DATA = "BT-7274";
        var ctx = try Context.init();
        defer ctx.deinit();
        var sock0 = try ctx.socket(.Pair);
        defer sock0.deinit();
        var sock1 = try ctx.socket(.Pair);
        defer sock1.deinit();
        try sock0.bind("inproc://hello");
        try sock1.connect("inproc://hello");

        {
            var frame = try Frame.initCopy(DATA);
            defer frame.deinit();
            _ = try sock0.sendFrame(&frame, .{});
        }
        {
            var frame = try sock1.recvFrameSize(256, .{});
            defer frame.deinit();
            try _t.expectEqual(@as(usize, 7), frame.data().len);
            try _t.expectEqual(@as(usize, 7), frame.size());
            try _t.expectEqualStrings(DATA, frame.data());
        }
    }
    {
        const DATA = "BT-7274";
        var ctx = try Context.init();
        defer ctx.deinit();
        var sock0 = try ctx.socket(.Pair);
        defer sock0.deinit();
        var sock1 = try ctx.socket(.Pair);
        defer sock1.deinit();
        try sock0.bind("inproc://hello");
        try sock1.connect("inproc://hello");

        {
            var buf = try _t.allocator.dupe(u8, DATA);
            var frame = try Frame.initData(buf, _t.allocator);
            defer frame.deinit();
            _ = try sock0.sendFrame(&frame, .{});
        }
        {
            var frame = try sock1.recvFrameSize(256, .{});
            defer frame.deinit();
            try _t.expectEqual(@as(usize, 7), frame.data().len);
            try _t.expectEqual(@as(usize, 7), frame.size());
            try _t.expectEqualStrings(DATA, frame.data());
        }
    }
}

test "Frame: getOpt" {
    const _t = std.testing;
    {
        const DATA = "BT-7274";
        var ctx = try Context.init();
        defer ctx.deinit();
        var sock0 = try ctx.socket(.Pair);
        defer sock0.deinit();
        var sock1 = try ctx.socket(.Pair);
        defer sock1.deinit();
        try sock0.bind("inproc://hello");
        try sock1.connect("inproc://hello");

        {
            var frame = try Frame.initCopy(DATA);
            defer frame.deinit();
            _ = try sock0.sendFrame(&frame, .{"more"});
        }
        {
            var frame = try Frame.initCopy(DATA);
            defer frame.deinit();
            _ = try sock0.sendFrame(&frame, .{});
        }
        {
            var frame = try sock1.recvFrameSize(256, .{});
            defer frame.deinit();
            try _t.expectEqual(true, try frame.getOpt(bool, .More));
            (try sock1.recvFrameSize(256, .{})).deinit();
        }
    }
}

fn buildEventFlags(val: anytype) c_short {
    const T = @TypeOf(val);
    const info = @typeInfo(T);
    if (info == .Int or info == .ComptimeInt) {
        return @intCast(c_short, val);
    } else if (info == .Struct) {
        var iflags = @intCast(c_short, 0);
        inline for (info.Struct.fields) |field| {
            const value = @field(val, field.name);
            if (comptime std.mem.eql(u8, value, "in")) {
                iflags |= @intCast(c_short, c.ZMQ_POLLIN);
            } else if (comptime std.mem.eql(u8, value, "out")) {
                iflags |= @intCast(c_short, c.ZMQ_POLLOUT);
            } else {
                @compileError(std.fmt.comptimePrint("unregonised flag: {s}", .{value}));
            }
        }
        return iflags;
    } else {
        @compileError(std.fmt.comptimePrint("expect tuple or integer, got {}", .{T}));
    }
}

pub const PollEvent = struct {
    socket: *Socket,
    in: bool,
    out: bool,

    const Self = @This();
};

pub const Poller = struct {
    mapping: std.AutoArrayHashMap(*c_void, *Socket),
    pollItems: std.ArrayList(c.zmq_pollitem_t),
    alloc: *Allocator,
    nextStartFind: usize = 0,

    const Self = @This();

    pub const IN = c.ZMQ_POLLIN;
    pub const OUT = c.ZMQ_POLLOUT;

    pub fn init(alloc: *Allocator) Self {
        return Self{
            .mapping = std.AutoArrayHashMap(*c_void, *Socket).init(alloc),
            .pollItems = std.ArrayList(c.zmq_pollitem_t).init(alloc),
            .alloc = alloc,
        };
    }

    pub fn deinit(self: *Self) void {
        self.mapping.deinit();
        self.pollItems.deinit();
    }

    pub fn add(self: *Self, socket: *Socket, events: anytype) Allocator.Error!void {
        if (self.pollItems.items.len >= std.math.maxInt(c_int)) {
            return Allocator.Error.OutOfMemory;
        }
        try self.mapping.put(socket.raw._sock, socket);
        try self.pollItems.append(.{
            .socket = socket.raw._sock,
            .fd = 0,
            .events = buildEventFlags(events),
            .revents = 0,
        });
    }

    pub fn rm(self: *Self, socket: *Socket) void {
        var i: usize = undefined;
        for (self.pollItems.items) |item, index| {
            if (item.socket == socket.raw._sock) {
                i = index;
                break;
            }
        } else unreachable;
        _ = self.pollItems.orderedRemove(i);
        _ = self.mapping.orderedRemove(socket.raw._sock);
    }

    pub fn findNextEvent(self: *Self) ?PollEvent {
        for (self.pollItems.items) |*item| {
            if (item.revents > 0) {
                var result = PollEvent{
                    .socket = self.mapping.get(item.socket.?).?,
                    .in = item.revents & IN > 0,
                    .out = item.revents & OUT > 0,
                };
                item.revents = @as(c_short, 0);
                return result;
            }
        }
        return null;
    }

    pub fn wait(self: *Self, timeout: c_int) Error!?PollEvent {
        const n = c.zmq_poll(self.pollItems.items.ptr, @intCast(c_int, self.pollItems.items.len), timeout);
        if (n > 0) {
            return self.findNextEvent();
        } else if (n == 0) {
            return null;
        } else {
            return switch (getErrNo()) {
                c.ETERM => Error.Terminated,
                c.EFAULT => unreachable,
                c.EINTR => Error.Interrupted,
                else => unreachable,
            };
        }
    }
};

test "Poller" {
    const _t = std.testing;
    var ctx = try Context.init();
    defer ctx.deinit();
    var sock0 = try ctx.socket(.Pair);
    defer sock0.deinit();
    var sock1 = try ctx.socket(.Pair);
    defer sock1.deinit();
    try sock0.bind("inproc://test");
    try sock1.connect("inproc://test");

    var poller = Poller.init(_t.allocator);
    defer poller.deinit();
    try poller.add(&sock0, .{"in"});
    try poller.add(&sock1, Poller.IN);

    _ = try sock0.sendConst("PING", .{});
    var i = @as(i32, 3);
    while (i>0) {
        var pollev = try poller.wait(-1);
        if (pollev) |event| {
            var socket = event.socket;
            var buf = try socket.recvAlloc(_t.allocator, 256, .{});
            defer _t.allocator.free(buf);
            if (std.mem.eql(u8, "PING", buf)) {
                _ = try socket.sendConst("PONG", .{});
            } else if (std.mem.eql(u8, "PONG", buf)) {
                i -= 1;
                _ = try socket.sendConst("PING", .{});
            } else unreachable;
        }
    }
}

pub const SocketEventMessage = struct {
    event: SocketEvent,
    value: u32,
    endpoint: ?[]const u8,
    alloc: ?*Allocator,

    const Self = @This();

    pub fn init(event: SocketEvent, value: u32, endpoint: []const u8, alloc: ?*Allocator) Self {
        return Self {
            .event = event,
            .value = value,
            .endpoint = endpoint,
            .alloc = alloc,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.alloc) |alloc| {
            if (self.endpoint) |endpoint| {
                alloc.free(endpoint);
            }
        }
    }

    /// Receive the first frame of the socket event message.
    /// If you don't want to receive the endpoint frame, don't forget to use `Socket.recvIgnore` to ignore the second frame.
    /// Caution: Bad message will trigger undefined behaviour.
    pub fn recvEvent(sock: *Socket) IOError!Self {
        var buf: [6]u8 = undefined;
        var realSize = try sock.recv(&buf, .{});
        std.debug.assert(realSize == 6);
        var packedSlice = std.PackedIntSlice(u8).init(&buf, 6);
        var evId = packedSlice.slice(0, 2).sliceCast(u16).get(0);
        var evVal = packedSlice.slice(2, 6).sliceCast(u32).get(0);
        var event = @intToEnum(SocketEvent, evId);
        return Self {
            .event = event,
            .value = evVal,
            .endpoint = null,
            .alloc = null,
        };
    }

    /// Receive the whole socket event message, including endpoint (the second frame).
    /// The endpoint should not be larger thant 2048 bytes, or IOError.FrameTooLarge will be return.
    /// Tips: this function might allocate 2048 bytes at first, them shrink it to best-fit size.
    /// You might manually set `alloc` and `endpoint` fields if you don't have much memory.
    pub fn recv(sock: *Socket, alloc: *Allocator) (IOError||Allocator.Error)!Self {
        var result = try Self.recvEvent(sock);
        std.debug.assert(sock.getRcvMore());
        var endpoint = try sock.recvAlloc(alloc, 2048, .{});
        result.endpoint = endpoint;
        result.alloc = alloc;
        return result;
    }
};

/// Toolkit structure to deal with multi-part messages.
pub const Msg = struct {
    frame: Frame,
    next: ?*Self,
    selfAllocator: ?*Allocator = null,

    const Self = @This();

    pub fn init(frame: Frame) Self {
        return Self {
            .frame = frame,
            .next = null,
        };
    }

    pub fn initPtr(frame: Frame, alloc: *Allocator) Allocator.Error!*Self {
        var obj = try alloc.create(Self);
        obj.* = Self.init(frame);
        obj.selfAllocator = alloc;
        return obj;
    }

    pub fn deinit(self: *Self) void {
        self.frame.deinit();
        if (self.selfAllocator) |alloc| {
            alloc.destroy(self);
        }
    }

    pub fn deinitAll(self: *Self) void {
        var next = self.next;
        self.deinit();
        if (next) |nnext| {
            nnext.deinitAll();
        }
    }

    /// Get the next nth message.
    /// `0` means this message.
    pub fn getNext(self: *Self, n: usize) ?*Self {
        if (n == 0) {
            return self;
        } else {
            if (self.next) |nextf| {
                return nextf.getNext(n-1);
            } else {
                return null;
            }
        }
    }

    pub fn countFrames(self: *Self) usize {
        var count = 0;
        var curr = self;
        while (curr) |f| {
            count += 1;
            curr = f.next;
        }
        return count;
    }

    pub fn getEnd(self: *Self) *Self {
        var curr = self;
        while (curr.next) |nextf| {
            curr = nextf;
        }
        return curr;
    }

    /// Append a frame with `data` and `alloc` to the end of this message.
    /// Callee owns `data`.
    pub fn appendData(self: *Self, data: []const u8, alloc: *Allocator) Allocator.Error!*Self {
        var frame = try Frame.initData(data, alloc);
        errdefer frame.deinit();
        return try self.appendFrame(frame, alloc);
    }

    pub fn appendFrame(self: *Self, frame: Frame, alloc: *Allocator) Allocator.Error!*Self {
        var msg = try Msg.initPtr(frame, alloc);
        errdefer msg.deinit();
        self.attach(msg);
        return msg;
    }

    pub fn appendEmpty(self: *Self, alloc: *Allocator) Allocator.Error!void {
        var emptyf = Frame.init();
        return try self.appendFrame(emptyf, alloc);
    }

    pub fn appendValue(self: *Self, comptime T: type, val: T, alloc: *Allocator) Allocator.Error!*Self {
        var frame = try Frame.initValue(T, val, alloc);
        errdefer frame.deinit();
        return self.appendFrame(frame, alloc);
    }

    pub fn attach(self: *Self, msg: *Msg) void {
        while (true) {
            var eof = self.getEnd();
            if (@cmpxchgWeak(?*Msg, &eof.next, null, msg, .SeqCst, .SeqCst) == null) break;
        }
    }

    pub fn sendBy(self: *Self, socket: *Socket, flags: anytype) IOError!void {
        const realFlags = RawSocket.buildFlags(flags) | (if (self.next) |_| SNDMORE else 0);
        _ = try socket.sendFrame(&self.frame, realFlags);
        if (self.next) |nextMsg| {
            return nextMsg.sendBy(socket, flags);
        }
    }

    /// Receive frames.
    /// Note that the `alloc` is only used to allocate memory for the structure itself.
    /// The memory used by data will be allocated by libzmq.
    pub fn recvFrom(socket: *Socket, flags: anytype, alloc: *Allocator) (IOError||Allocator.Error)!*Msg {
        var frame = Frame.init();
        errdefer frame.deinit();
        _ = try socket.recvFrame(&frame, flags);
        var msg = try Self.initPtr(frame, alloc);
        errdefer msg.deinit();
        if (socket.getRcvMore()) {
            msg.next = try Self.recvFrom(socket, flags, alloc);
        }
        return msg;
    }

    pub fn chain(items: []Self) void {
        for (items) |*item, i| {
            if (i > 0) {
                items[i-1].next = item;
            }
        }
    }

    pub fn chainPtrs(items: []*Self) void {
        for (items) |item, i| {
            if (i > 0) {
                items[i-1].next = item;
            }
        }
    }
};
