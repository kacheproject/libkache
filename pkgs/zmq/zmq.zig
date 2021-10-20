const std = @import("std");
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("zmq.h");
});

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
    return c.zmq_errno();
}

pub const Context = struct {
    _ctx: *c_void,

    const Self = @This();

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
};

test "Context: initialise and deinitialise" {
    const _t = std.testing;
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

    const Self = @This();

    pub fn getOriginal(self: *const Self) c_int {
        return @bitCast(c_int, self.*);
    }
};

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
    pub fn sendCopy(self: *Self, buf: []const u8, flags: anytype) (Allocator.IOError | IOError)!usize {
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

            .ConnectTimeout, .Linger, .UseFD, .Backlog => {
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
                return result;
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
    pub fn sendCopy(self: *Self, buf: []const u8, flags: anytype) (Allocator.Error | IOError)!usize {
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

    /// Receive a exact value from socket.
    /// Warning: the method just receive data and write them into memory. The data might not be portable.
    pub fn recvValue(self: *Self, comptime V: type, flags: anytype) IOError!?V {
        std.debug.assert(@typeInfo(V) != .Pointer);
        const size = @sizeOf(V);
        var buf = [_]u8{0} * size;
        const recvSize = try self.recv(buf, flags);
        if (recvSize == size) {
            return @ptrCast(*V, buf.ptr).*;
        } else {
            return null;
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
};

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
    const _t = std.testing;
    {
        var key0 = curveGenerateSecretKey();
        var pk0 = curvePublic(&key0);
    }
}

test "Socket: initialise and deinitialise" {
    const _t = std.testing;
    var ctx = try Context.init();
    defer ctx.deinit();
    var sock = try ctx.socket(.Pair);
    sock.deinit();
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

const FrameOpt = enum(c_int) {
    More = c.ZMQ_MORE,
    SrcFD = c.ZMQ_SRCFD,
    Shared = c.ZMQ_SHARED,
};

const Frame = struct {
    raw: c.zmq_msg_t,
    _beSentFlag: bool = false,
    _closed: bool = false,

    const Self = @This();

    pub fn init() Self {
        var raw = std.mem.zeroes(c.zmq_msg_t);
        const stat = c.zmq_msg_init(&raw);
        return Self{
            .raw = raw,
        };
    }

    pub fn deinit(self: *Self) void {
        if (!self._closed and !self._beSentFlag) {
            _ = c.zmq_msg_close(&self.raw);
        }
        self._closed = true;
    }

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

    pub fn initCopy(buf: []const u8) Allocator.Error!Self {
        var frame = try Self.initSize(buf.len);
        if (frame.data()) |d| {
            std.mem.copy(u8, d, buf);
        } else unreachable; // If initSize return without error, data should have value.
        return frame;
    }

    // Rubicon: It's hard to implement zmq_init_data with zig's slices and allocators, so leave it alone.

    pub fn size(self: *Self) usize {
        return c.zmq_msg_size(&self.raw);
    }

    pub fn data(self: *Self) ?[]u8 {
        var ptr = c.zmq_msg_data(&self.raw);
        if (ptr) |nnptr| {
            return @ptrCast([*]u8, nnptr)[0..self.size()];
        } else {
            return null;
        }
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
        var data = frame.data().?;
        for (DATA) |ch, i| data[i] = ch;
        try _t.expectEqualStrings(DATA, frame.data().?);
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
            try _t.expectEqual(@as(usize, 7), frame.data().?.len);
            try _t.expectEqual(@as(usize, 7), frame.size());
            try _t.expectEqualStrings(DATA, frame.data().?);
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

const Poller = struct {
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
        const i = for (self.pollItems.items) |item, i| blk: {
            if (item.socket == socket.raw._sock) {
                break :blk i;
            }
        };
        self.pollItems.orderedRemove(i);
        self.mapping.orderedRemove(socket.raw._sock);
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
